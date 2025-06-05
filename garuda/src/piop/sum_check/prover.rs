// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Prover subroutines for a SumCheck protocol.

use super::SumCheckProver;
use crate::arithmetic::{fix_variables, VirtualPolynomial};
use crate::piop::structs::{IOPProverStateInner, MaskProverState};
use crate::piop::{
    errors::PolyIOPErrors,
    structs::{IOPProverMessage, IOPProverState},
};
use ark_ff::{batch_inversion, PrimeField};
use ark_poly::multivariate::Term;
use ark_poly::multivariate::{SparsePolynomial, SparseTerm};
use ark_poly::{DenseMVPolynomial, DenseMultilinearExtension};
use ark_std::rand::RngCore;
use ark_std::{cfg_into_iter, cfg_iter_mut, end_timer, start_timer, vec::Vec};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator};
use std::sync::Arc;

impl<F: PrimeField> SumCheckProver<F> for IOPProverState<F> {
    type VirtualPolynomial = VirtualPolynomial<F>;
    type ProverMessage = IOPProverMessage<F>;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    fn init(
        polynomial: &Self::VirtualPolynomial,
        mask: Option<(SparsePolynomial<F, SparseTerm>, F)>,
    ) -> Result<Self, PolyIOPErrors> {
        let start = start_timer!(|| "sum check prover init");
        if polynomial.aux_info.num_variables == 0 {
            return Err(PolyIOPErrors::InvalidParameters(
                "Attempt to prove a constant.".to_string(),
            ));
        }
        end_timer!(start);
        let mask_state = match mask {
            Some((mask_poly, challenge)) => Some(Self::mask_init(
                &mask_poly,
                polynomial.aux_info.num_variables,
                polynomial.aux_info.max_degree,
                challenge,
            )),
            None => None,
        };

        Ok(Self {
            inner: IOPProverStateInner {
                challenges: Vec::with_capacity(polynomial.aux_info.num_variables),
                round: 0,
                poly: polynomial.clone(),
                extrapolation_aux: (1..polynomial.aux_info.max_degree)
                    .map(|degree| {
                        let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                        let weights = barycentric_weights(&points);
                        (points, weights)
                    })
                    .collect(),
            },
            //TODO: Check if this is correct
            mask_state,
        })
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    fn prove_round_and_update_state(
        &mut self,
        zk: bool,
        challenge: &Option<F>,
    ) -> Result<Self::ProverMessage, PolyIOPErrors> {
        let prover_message = self.prove_round_and_update_state_inner(challenge)?;
        if zk {
            let mask = self.mask_round(challenge);
            Ok(IOPProverMessage {
                evaluations: prover_message
                    .evaluations
                    .iter()
                    .zip(mask.evaluations.iter())
                    .map(|(msg, sum)| *msg + sum)
                    .collect(),
            })
        } else {
            Ok(IOPProverMessage {
                evaluations: prover_message.evaluations,
            })
        }
    }
}

impl<F: PrimeField> IOPProverState<F> {
    pub fn mask_init(
        mask_polynomial: &impl DenseMVPolynomial<F>,
        num_vars: usize,
        max_multiplicands: usize,
        challenge: F,
    ) -> MaskProverState<F> {
        let degree = mask_polynomial.degree();
        let num_variables = num_vars;
        let mut univariate_mask_polynomials = vec![vec![F::zero(); degree + 1]; num_variables];
        for (coef, term) in mask_polynomial.terms() {
            if term.len() > 1 {
                panic!("Invalid mask polynomial")
            } else if term.len() == 1 {
                univariate_mask_polynomials[term[0].0][term[0].1] = *coef;
            } else {
                univariate_mask_polynomials[0][0] = *coef;
            }
        }
        let mut partial_sum: Vec<F> = Vec::new();
        let mut sum = F::zero();
        for (count, mask_poly) in univariate_mask_polynomials.iter().rev().enumerate() {
            sum += mask_poly[0] + mask_poly[0];
            for i in 1..degree + 1 {
                sum += mask_poly[i];
            }
            partial_sum.push(sum * F::from(1u128 << count));
        }
        partial_sum.reverse();
        partial_sum.push(F::zero());
        MaskProverState {
            mask_polynomials: univariate_mask_polynomials,
            challenge,
            front_partial_sum: F::zero(),
            tail_partial_sum: partial_sum,
            round: 0,
            num_vars: num_variables,
            max_multiplicands,
        }
    }

    pub fn mask_round(
        &mut self,
        verifier_chall: &Option<F>,
    ) -> <IOPProverState<F> as SumCheckProver<F>>::ProverMessage {
        // Get a mutable reference to the MaskState struct inside the Option.
        // This replaces multiple .unwrap() calls and prevents move errors.
        let mask_state = self
            .mask_state
            .as_mut()
            .expect("mask_state should be Some in mask_round"); // Or .unwrap() if you prefer no custom message

        mask_state.round += 1;
        let i = mask_state.round;
        let nv = mask_state.num_vars;
        let deg = mask_state.max_multiplicands;
        let challenge = mask_state.challenge; // Original logic for challenge
        let mut sum = vec![F::zero(); deg + 1];

        if let Some(chall) = verifier_chall {
            // Accessing fields through the 'mask_state' mutable reference
            mask_state.front_partial_sum +=
                Self::get_mask_evaluation(&mask_state.mask_polynomials[i - 2], *chall);
        }

        for j in 0..deg + 1 {
            // Accessing fields through the 'mask_state' mutable reference
            sum[j] =
                Self::get_mask_evaluation(&mask_state.mask_polynomials[i - 1], F::from(j as u64))
                    + mask_state.front_partial_sum;
            sum[j] *= F::from(1u128 << (nv - i));
            sum[j] += mask_state.tail_partial_sum[i];
            sum[j] *= challenge;
        }

        IOPProverMessage { evaluations: sum }
    }
    /// get evaluation of univariate polynomial on specific point
    pub fn get_mask_evaluation(mask_polynomial: &Vec<F>, point: F) -> F {
        let mut evaluation = F::zero();
        for coef in mask_polynomial.iter().rev() {
            evaluation *= point;
            evaluation += coef;
        }
        evaluation
    }
    fn prove_round_and_update_state_inner(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<<IOPProverState<F> as SumCheckProver<F>>::ProverMessage, PolyIOPErrors> {
        // let start =
        //     start_timer!(|| format!("sum check prove {}-th round and update state",
        // self.round));

        if self.inner.round >= self.inner.poly.aux_info.num_variables {
            return Err(PolyIOPErrors::InvalidProver(
                "Prover is not active".to_string(),
            ));
        }

        // let fix_argument = start_timer!(|| "fix argument");

        // Step 1:
        // fix argument and evaluate f(x) over x_m = r; where r is the challenge
        // for the current round, and m is the round number, indexed from 1
        //
        // i.e.:
        // at round m <= n, for each mle g(x_1, ... x_n) within the flattened_mle
        // which has already been evaluated to
        //
        //    g(r_1, ..., r_{m-1}, x_m ... x_n)
        //
        // eval g over r_m, and mutate g to g(r_1, ... r_m,, x_{m+1}... x_n)
        let mut flattened_ml_extensions: Vec<DenseMultilinearExtension<F>> = self
            .inner
            .poly
            .flattened_ml_extensions
            .par_iter()
            .map(|x| x.as_ref().clone())
            .collect();

        if let Some(chal) = challenge {
            if self.inner.round == 0 {
                return Err(PolyIOPErrors::InvalidProver(
                    "first round should be prover first.".to_string(),
                ));
            }
            self.inner.challenges.push(*chal);

            let r = self.inner.challenges[self.inner.round - 1];
            cfg_iter_mut!(flattened_ml_extensions).for_each(|mle| *mle = fix_variables(mle, &[r]));
        } else if self.inner.round > 0 {
            return Err(PolyIOPErrors::InvalidProver(
                "verifier message is empty".to_string(),
            ));
        }
        // end_timer!(fix_argument);

        self.inner.round += 1;

        let products_list = self.inner.poly.products.clone();
        let mut products_sum = vec![F::zero(); self.inner.poly.aux_info.max_degree + 1];

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        products_list.iter().for_each(|(coefficient, products)| {
            let mut sum =
                cfg_into_iter!(0..1 << (self.inner.poly.aux_info.num_variables - self.inner.round))
                    .fold(
                        || {
                            (
                                vec![(F::zero(), F::zero()); products.len()],
                                vec![F::zero(); products.len() + 1],
                            )
                        },
                        |(mut buf, mut acc), b| {
                            buf.iter_mut().zip(products).for_each(|((eval, step), f)| {
                                let table = &flattened_ml_extensions[*f];
                                *eval = table[b << 1];
                                *step = table[(b << 1) + 1] - table[b << 1];
                            });
                            acc[0] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            acc[1..].iter_mut().for_each(|acc| {
                                buf.iter_mut().for_each(|(eval, step)| *eval += step as &_);
                                *acc += buf.iter().map(|(eval, _)| eval).product::<F>();
                            });
                            (buf, acc)
                        },
                    )
                    .map(|(_, partial)| partial)
                    .reduce(
                        || vec![F::zero(); products.len() + 1],
                        |mut sum, partial| {
                            sum.iter_mut()
                                .zip(partial)
                                .for_each(|(sum, partial)| *sum += partial);
                            sum
                        },
                    );
            sum.iter_mut().for_each(|sum| *sum *= coefficient);
            let extrapolation =
                cfg_into_iter!(0..self.inner.poly.aux_info.max_degree - products.len())
                    .map(|i| {
                        let (points, weights) = &self.inner.extrapolation_aux[products.len() - 1];
                        let at = F::from((products.len() + 1 + i) as u64);
                        extrapolate(points, weights, &sum, &at)
                    })
                    .collect::<Vec<_>>();
            products_sum
                .iter_mut()
                .zip(sum.into_iter().chain(extrapolation))
                .for_each(|(products_sum, sum)| *products_sum += sum);
        });

        // update prover's state to the partial evaluated polynomial
        self.inner.poly.flattened_ml_extensions = flattened_ml_extensions
            .par_iter()
            .map(|x| Arc::new(x.clone()))
            .collect();

        Ok(IOPProverMessage {
            evaluations: products_sum,
        })
    }
}

fn barycentric_weights<F: PrimeField>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter_map(|(i, point_i)| (i != j).then(|| *point_j - point_i))
                .reduce(|acc, value| acc * value)
                .unwrap_or_else(F::one)
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut weights);
    weights
}

fn extrapolate<F: PrimeField>(points: &[F], weights: &[F], evals: &[F], at: &F) -> F {
    let (coeffs, sum_inv) = {
        let mut coeffs = points.iter().map(|point| *at - point).collect::<Vec<_>>();
        batch_inversion(&mut coeffs);
        coeffs.iter_mut().zip(weights).for_each(|(coeff, weight)| {
            *coeff *= weight;
        });
        let sum_inv = coeffs.iter().sum::<F>().inverse().unwrap_or_default();
        (coeffs, sum_inv)
    };
    coeffs
        .iter()
        .zip(evals)
        .map(|(coeff, eval)| *coeff * eval)
        .sum::<F>()
        * sum_inv
}
