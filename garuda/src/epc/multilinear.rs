use super::{
    data_structures::{
        MLBatchedCommitment, MLCommitment, MLCommitmentKey, MLPublicParameters, MLTrapdoor,
        MLVerifyingKey,
    },
    EPC,
};
use crate::to_bytes;
use ark_crypto_primitives::crh::{sha256::Sha256, CRHScheme};
use ark_ec::scalar_mul::BatchMulPreprocessing;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_poly::multivariate::Term;
use ark_poly::DenseMVPolynomial;
use ark_poly::{
    multivariate::{SparsePolynomial, SparseTerm},
    DenseMultilinearExtension as DenseMLE, MultilinearExtension, Polynomial,
    SparseMultilinearExtension,
};
use ark_std::{cfg_chunks, cfg_into_iter, cfg_iter, marker::PhantomData, rand::Rng, UniformRand};
use ark_std::{collections::LinkedList, end_timer, start_timer};
use ark_std::{rand::RngCore, One, Zero};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use shared_utils::msm_bigint_wnaf;

use std::{ops::Mul, os::macos::raw::stat};
pub struct MultilinearEPC<E: Pairing> {
    _p1: PhantomData<E>,
}

impl<E: Pairing> EPC<E::ScalarField> for MultilinearEPC<E> {
    type PublicParameters = MLPublicParameters<E>;
    type OpeningProof = (Vec<E::G1Affine>, Option<E::ScalarField>);
    type BatchedOpeningProof = Self::OpeningProof;
    type CommitmentKey = MLCommitmentKey<E>;
    type VerifyingKey = MLVerifyingKey<E>;
    type EvaluationPoint = Vec<E::ScalarField>;
    type Trapdoor = MLTrapdoor<E>;
    type ProverState = Option<SparsePolynomial<E::ScalarField, SparseTerm>>;
    type ProverBatchedState = Vec<Self::ProverState>;
    type Commitment = MLCommitment<E>;
    type BatchedCommitment = MLBatchedCommitment<E>;
    type Polynomial = DenseMLE<E::ScalarField>;
    type BasisPoly = SparseMultilinearExtension<E::ScalarField>;
    type PolynomialBasis = Vec<Self::BasisPoly>;
    type EquifficientConstraint = Vec<Self::PolynomialBasis>;

    fn setup(
        mut rng: impl RngCore,
        pp: &Self::PublicParameters,
        hiding_bound: Option<usize>,
        equifficient_constraints: &Self::EquifficientConstraint,
    ) -> (Self::CommitmentKey, Self::VerifyingKey, Self::Trapdoor) {
        // beta_is, the random evaluation points
        let beta: Vec<E::ScalarField> = (0..pp.num_var)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();
        // alpha_is, the random consistency challenges
        let consistency_challanges: Vec<E::ScalarField> = (0..pp.num_constraints)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        let mut powers_of_g = Vec::new();
        let mut eq: LinkedList<DenseMLE<E::ScalarField>> =
            LinkedList::from_iter(Self::eq_extension(&beta));
        let mut eq_arr = LinkedList::new();
        let mut base = eq.pop_back().unwrap().evaluations;

        for i in (0..pp.num_var).rev() {
            eq_arr.push_front(Self::remove_dummy_variable(&base, i));
            if i != 0 {
                let mul = eq.pop_back().unwrap().evaluations;
                base = base
                    .into_iter()
                    .zip(mul.into_iter())
                    .map(|(a, b)| a * b)
                    .collect();
            }
        }

        let mut pp_powers = Vec::new();
        for i in 0..pp.num_var {
            let eq = eq_arr.pop_front().unwrap();
            let pp_k_powers = (0..(1 << (pp.num_var - i))).map(|x| eq[x]);
            pp_powers.extend(pp_k_powers);
        }

        let g_table = BatchMulPreprocessing::new(pp.generators.g, 1 << pp.num_var);
        let h_table = BatchMulPreprocessing::new(pp.generators.h, pp.num_var);
        let pp_g = g_table.batch_mul(&pp_powers);
        let mut start = 0;
        for i in 0..pp.num_var {
            let size = 1 << (pp.num_var - i);
            let pp_k_g = pp_g[start..][..size].to_vec();
            powers_of_g.push(pp_k_g);
            start += size;
        }
        let last = powers_of_g.last().unwrap();
        powers_of_g.push(vec![last.iter().sum::<E::G1>().into_affine()]);
        let h_mask = h_table.batch_mul(&beta);

        // Preparing the zk srs, if hiding_bound is set
        let (gamma_g, powers_of_gamma_g) = match hiding_bound {
            Some(hiding_bound) => {
                let gamma_g = E::G1::rand(&mut rng);
                let mut powers_of_gamma_g = vec![Vec::new(); pp.num_var];
                let gamma_g_table = BatchMulPreprocessing::new(gamma_g, hiding_bound + 1);

                ark_std::cfg_iter_mut!(powers_of_gamma_g)
                    .enumerate()
                    .for_each(|(i, v)| {
                        let mut powers_of_beta_i = Vec::with_capacity(hiding_bound + 1);
                        let mut cur = E::ScalarField::one();
                        for _ in 0..=hiding_bound {
                            cur *= &beta[i];
                            powers_of_beta_i.push(cur);
                        }
                        *v = gamma_g_table.batch_mul(&powers_of_beta_i);
                    });

                let gamma_g = gamma_g.into_affine();
                (Some(gamma_g), Some(powers_of_gamma_g))
            }
            None => (None, None),
        };

        // Preparing the consistency srs

        let dim = equifficient_constraints[0].len();
        let mut randomized_basis_set = Vec::new();
        for i in 0..dim {
            let value = equifficient_constraints
                .iter()
                .zip(consistency_challanges.iter())
                .fold(
                    E::ScalarField::zero(),
                    |acc, (basis_set, consistency_chall)| {
                        acc + (basis_set[i].evaluate(&beta) * consistency_chall)
                    },
                );
            randomized_basis_set.push(value);
        }
        let g1_table: BatchMulPreprocessing<E::G1> =
            BatchMulPreprocessing::new(pp.generators.g, dim);
        let consistency_pk = g1_table.batch_mul(&randomized_basis_set);
        let consistency_vk: Vec<E::G2> = consistency_challanges
            .iter()
            .map(|alpha| pp.generators.h * (*alpha))
            .collect();
        let consistency_vk = E::G2::normalize_batch(&consistency_vk);

        let consistency_vk_prep: Vec<E::G2Prepared> = consistency_vk
            .iter()
            .map(|x| E::G2Prepared::from(*x))
            .collect();
        let powers_of_h_prep: Vec<E::G2Prepared> =
            h_mask.iter().map(|x| E::G2Prepared::from(*x)).collect();

        // Assembling the keys
        (
            MLCommitmentKey {
                nv: pp.num_var,
                powers_of_g,
                g: pp.generators.g.into(),
                h: pp.generators.h.into(),
                gamma_g,
                powers_of_gamma_g,
                consistency_pk,
            },
            MLVerifyingKey {
                nv: pp.num_var,
                g: pp.generators.g.into(),
                h: pp.generators.h.into(),
                h_prep: pp.generators.h.into().into(),
                powers_of_h: h_mask,
                powers_of_h_prep,
                gamma_g,
                consistency_vk,
                consistency_vk_prep,
            },
            MLTrapdoor {
                beta,
                consistency_challanges,
            },
        )
    }

    fn commit(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        rng: &mut impl Rng,
        hiding_bound: Option<usize>,
        rest_zero: Option<usize>,
    ) -> (Self::Commitment, Self::ProverState) {
        let (hiding_commitment, prover_state) = match hiding_bound {
            Some(hiding_bound) => {
                let p_hat: SparsePolynomial<E::ScalarField, SparseTerm> =
                    Self::generate_mask_polynomial(rng, poly.num_vars(), hiding_bound, false);
                // Get the powers of `\gamma G` corresponding to the terms of `rand`
                let powers_of_gamma_g = p_hat
                    .terms()
                    .iter()
                    .map(|(_, term)| {
                        // Implicit Assumption: Each monomial in `rand` is univariate
                        let vars = term.vars();
                        match term.is_constant() {
                            true => ck.gamma_g.unwrap(),
                            false => {
                                ck.powers_of_gamma_g.clone().unwrap()[vars[0]][term.degree() - 1]
                            }
                        }
                    })
                    .collect::<Vec<_>>();

                let msm_time = start_timer!(|| "MSM to compute commitment to random poly");
                let scalars: Vec<E::ScalarField> = cfg_into_iter!(p_hat.terms())
                    .map(|(coeff, _)| coeff.clone())
                    .collect();
                let random_commitment =
                    <E::G1 as VariableBaseMSM>::msm_unchecked(&powers_of_gamma_g, &scalars)
                        .into_affine();
                end_timer!(msm_time);
                (random_commitment, Some(p_hat))
            }
            None => (E::G1Affine::zero(), None),
        };

        // Base commitment
        let rest_zero = rest_zero.unwrap_or(1 << poly.num_vars());
        let scalars: Vec<_> = cfg_iter!(poly.evaluations[..rest_zero])
            .map(|x| x.into_bigint())
            .collect();
        let base_commitmet = E::G1::msm_bigint(&ck.powers_of_g[0], scalars.as_slice());
        // Outputting the final commitment
        (
            Self::Commitment {
                nv: ck.nv,
                g_product: (base_commitmet + hiding_commitment).into_affine(),
            },
            prover_state,
        )
    }

    fn batch_commit(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        rest_zeros: &[Option<usize>],
        hiding_bounds: &[Option<usize>],
        equifficients: Option<&[E::ScalarField]>,
    ) -> (Self::BatchedCommitment, Self::ProverBatchedState) {
        let timer_indiv_comm = start_timer!(|| "Individual commits");
        #[cfg(feature = "parallel")]
        use rayon::iter::once;
        #[cfg(not(feature = "parallel"))]
        use std::iter::once;
        let (mut individual_comms, mut prover_states): (
            Vec<Self::Commitment>,
            Vec<Self::ProverState>,
        ) = cfg_iter!(polys)
            .zip(rest_zeros)
            .zip(hiding_bounds)
            .map(|((poly, rest_zero), hiding_bound)| {
                let mut local_rng = ark_std::rand::thread_rng();
                Self::commit(ck, poly, &mut local_rng, *hiding_bound, *rest_zero)
            })
            .chain(once({
                let g = match equifficients {
                    Some(e) => E::G1::msm(&ck.consistency_pk, e).unwrap(),
                    None => E::G1::zero(),
                };
                (
                    MLCommitment {
                        nv: 0,
                        g_product: g.into_affine(),
                    },
                    None,
                )
            }))
            .unzip();
        end_timer!(timer_indiv_comm);
        let consistency_comm = individual_comms.pop().unwrap().g_product;
        let _ = prover_states.pop().unwrap();
        (
            Self::BatchedCommitment {
                individual_comms,
                consistency_comm: equifficients.map(|_| consistency_comm),
            },
            prover_states,
        )
    }

    fn open(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        point: &Self::EvaluationPoint,
        _comm: &Self::Commitment,
        state: &Self::ProverState,
    ) -> Self::OpeningProof {
        let nv = poly.num_vars();
        let mut current_r = poly.to_evaluations();
        let mut last_r = vec![E::ScalarField::zero(); 1 << (nv - 1)];
        let zero = <E::ScalarField as PrimeField>::BigInt::from(0u8);
        let mut current_q = vec![zero; 1 << (nv - 1)];

        let mut w_scalars = Vec::with_capacity(nv);
        let compute_scalars_time = start_timer!(|| "Compute scalars");
        for (i, &point_at_k) in point.iter().enumerate() {
            let k = nv - i;
            current_q.truncate(1 << (k - 1));
            last_r.truncate(1 << (k - 1));
            cfg_chunks!(current_r, 2)
                .zip(&mut current_q)
                .zip(&mut last_r)
                .for_each(|((current_r_s, q), r)| {
                    let [r_2b, r_2b_plus_1] = <[_; 2]>::try_from(current_r_s).unwrap();
                    let t = r_2b_plus_1 - r_2b;
                    *r = r_2b + t * point_at_k;
                    *q = t.into_bigint();
                });
            std::mem::swap(&mut current_r, &mut last_r);
            w_scalars.push(current_q.clone());
        }
        end_timer!(compute_scalars_time);
        let proof_g1 = match state {
            Some(sparse_random_poly) => {
                let mut w = cfg_iter!(w_scalars)
                    .zip(cfg_iter!(ck.powers_of_g[1..]))
                    .map(|(scalars, powers)| E::G1::msm_bigint(powers, scalars))
                    .collect::<Vec<_>>();
                let hiding_witnesses = Self::divide_at_point(sparse_random_poly, point);
                ark_std::cfg_iter_mut!(w)
                    .enumerate()
                    .for_each(|(i, witness)| {
                        let hiding_witness = &hiding_witnesses[i];
                        // Get the powers of `\gamma G` corresponding to the terms of `hiding_witness`
                        let powers_of_gamma_g = hiding_witness
                            .terms()
                            .iter()
                            .map(|(_, term)| {
                                // Implicit Assumption: Each monomial in `hiding_witness` is univariate
                                let vars = term.vars();
                                match term.is_constant() {
                                    true => ck.gamma_g.unwrap(),
                                    false => {
                                        ck.powers_of_gamma_g.as_ref().unwrap()[vars[0]][term.degree() - 1]
                                    }
                                }
                            })
                            .collect::<Vec<_>>();
                        // Convert coefficients to BigInt
                        // let hiding_witness_ints = Self::convert_to_bigints(hiding_witness);
                        let hiding_witness_coeffs = hiding_witness
                            .terms()
                            .into_iter().map(|(coeff, _)| coeff.clone())
                            .collect::<Vec<_>>();
                        // Compute MSM and add result to witness
                        *witness += &<E::G1 as VariableBaseMSM>::msm_unchecked(
                            &powers_of_gamma_g,
                            &hiding_witness_coeffs,
                        );
                    });
                w.into_iter().map(|w| w.into_affine()).collect()
            }
            None => cfg_iter!(w_scalars)
                .zip(cfg_iter!(ck.powers_of_g[1..]))
                .map(|(scalars, powers)| E::G1::msm_bigint(powers, scalars).into_affine())
                .collect::<Vec<_>>(),
        };

        (proof_g1, state.as_ref().map(|s| s.evaluate(point)))
    }

    fn batch_open(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        point: &Self::EvaluationPoint,
        comms: &Self::BatchedCommitment,
        batch_state: &Self::ProverBatchedState,
    ) -> Self::BatchedOpeningProof {
        let timer_batch_polys = start_timer!(|| "Batching Polys");
        let (batched_poly, p_hat) = Self::produce_batched_poly_state(polys, comms, batch_state);
        end_timer!(timer_batch_polys);
        let timer_open_batched_polys = start_timer!(|| "Open batched polys");
        let result = Self::open(
            ck,
            &batched_poly,
            point,
            &comms.individual_comms[0],
            &Some(p_hat),
        );
        end_timer!(timer_open_batched_polys);
        result
    }

    fn verify(
        vk: &Self::VerifyingKey,
        comm: &Self::Commitment,
        point: &Self::EvaluationPoint,
        eval: E::ScalarField,
        proof: &Self::OpeningProof,
    ) -> bool {
        let verify_time = start_timer!(|| "EPC Verify");
        let lhs = {
            let mut left_input = comm.g_product.into_group() - &vk.g.mul(eval);
            // This is for ZK
            if let Some(v_bar) = &proof.1 {
                // scalars.push((-*v_bar).into_bigint());
            }

            let point_bigint = point.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
            left_input += msm_bigint_wnaf::<E::G1>(&proof.0, point_bigint.as_slice());

            let right_input = vk.h_prep.clone();
            (left_input.into().into(), right_input)
        };
        let mut rhs = {
            let left_inputs = proof
                .0
                .iter()
                .map(|x| E::G1Prepared::from(-*x))
                .collect::<Vec<_>>();
            let right_inputs = vk.powers_of_h_prep.clone();
            (left_inputs, right_inputs)
        };
        rhs.0.push(lhs.0);
        rhs.1.push(lhs.1);
        let result = E::multi_pairing(rhs.0, rhs.1).is_zero();
        end_timer!(verify_time);
        result
    }

    fn batch_verify(
        vk: &Self::VerifyingKey,
        comm: &Self::BatchedCommitment,
        point: &Self::EvaluationPoint,
        evals: &[E::ScalarField],
        proof: &Self::BatchedOpeningProof,
        constrained_num: usize,
    ) -> bool {
        let verify_time = start_timer!(|| "EPC Batch Verify");
        // perform the consistency check on the constrained polyanomials, i.e. check the equifficiency property
        let mut consistency_result = true;
        if let Some(consistency_comm) = &comm.consistency_comm {
            consistency_result &= Self::verify_consistency(
                vk,
                *consistency_comm,
                &comm.individual_comms[..constrained_num],
            );
        }
        let individual_comms = &comm.individual_comms;
        let mut g_products: Vec<_> = individual_comms.iter().map(|x| x.g_product).collect();
        assert_eq!(
            evals.len(),
            individual_comms.len(),
            "Invalid size of values"
        );
        let comm_batch_time = start_timer!(|| "Batching comms");
        let challs_field = Self::produce_opening_batch_challs(individual_comms);
        let challs_bigint = challs_field.iter().map(|x| x.into_bigint());
        let batched_eval = challs_field
            .iter()
            .zip(evals.iter())
            .fold(E::ScalarField::zero(), |acc, (x, y)| acc + (*x * y));
        end_timer!(comm_batch_time);

        let point_bigint = point.iter().map(|x| x.into_bigint());

        let result = {
            let eval = &batched_eval;
            let verify_time = start_timer!(|| "EPC Verify");
            // We rewrite the logn many pairings via the standard KZG pairing rewrite
            // to maximize the pairings which use the same G2 element.
            let lhs = {
                // One big MSM for
                // 1. Combining the individual commitments via a linear combination
                // 2. Computing `proof[i] * point[i]` for each i
                // 3. Computing `-eval * vk.g`
                //
                // Part 1 above generates the batched commitment
                g_products.extend(proof.0.clone());
                g_products.push(vk.g);
                // This is for ZK
                if let Some(gamma_g) = vk.gamma_g {
                    g_products.push(gamma_g);
                }
                let mut scalars = challs_bigint
                    .chain(point_bigint)
                    .chain(std::iter::once((-*eval).into_bigint()))
                    .collect::<Vec<_>>();
                // This is for ZK
                if let Some(v_bar) = &proof.1 {
                    scalars.push((-*v_bar).into_bigint());
                }
                let left_input = msm_bigint_wnaf::<E::G1>(&g_products, scalars.as_slice());

                let right_input = vk.h_prep.clone();
                (left_input.into().into(), right_input)
            };
            let mut rhs = {
                let left_inputs = proof
                    .0
                    .iter()
                    .map(|x| E::G1Prepared::from(-*x))
                    .collect::<Vec<_>>();
                let right_inputs = vk.powers_of_h_prep.clone();
                (left_inputs, right_inputs)
            };
            rhs.0.push(lhs.0);
            rhs.1.push(lhs.1);
            let result = E::multi_pairing(rhs.0, rhs.1).is_zero();
            end_timer!(verify_time);
            result
        };
        end_timer!(verify_time);
        consistency_result & result
    }
}

impl<E: Pairing> MultilinearEPC<E> {
    fn divide_at_point<P>(p: &P, point: &P::Point) -> Vec<P>
    where
        P: DenseMVPolynomial<E::ScalarField> + Sync,
        P::Point: std::ops::Index<usize, Output = E::ScalarField>,
    {
        let num_vars = p.num_vars();
        if p.is_zero() {
            return vec![P::zero(); num_vars];
        }
        let mut quotients = Vec::with_capacity(num_vars);
        // `cur` represents the current dividend
        let mut cur = p.clone();
        // Divide `cur` by `X_i - z_i`
        for i in 0..num_vars {
            let mut quotient_terms = Vec::new();
            let mut remainder_terms = Vec::new();
            for (mut coeff, term) in cur.terms() {
                // Since the final remainder is guaranteed to be 0, all the constant terms
                // cancel out so we don't need to keep track of them
                if term.is_constant() {
                    continue;
                }
                // If the current term contains `X_i` then divide appropiately,
                // otherwise add it to the remainder
                let mut term_vec = (&*term).to_vec();
                match term_vec.binary_search_by(|(var, _)| var.cmp(&i)) {
                    Ok(idx) => {
                        // Repeatedly divide the term by `X_i - z_i` until the remainder
                        // doesn't contain any `X_i`s
                        while term_vec[idx].1 > 1 {
                            // First divide by `X_i` and add the term to the quotient
                            term_vec[idx] = (i, term_vec[idx].1 - 1);
                            quotient_terms.push((coeff, P::Term::new(term_vec.clone())));
                            // Then compute the remainder term in-place
                            coeff *= &point[i];
                        }
                        // Since `X_i` is power 1, we can remove it entirely
                        term_vec.remove(idx);
                        quotient_terms.push((coeff, P::Term::new(term_vec.clone())));
                        remainder_terms.push((point[i] * &coeff, P::Term::new(term_vec)));
                    }
                    Err(_) => remainder_terms.push((coeff, term.clone())),
                }
            }
            quotients.push(P::from_coefficients_vec(num_vars, quotient_terms));
            // Set the current dividend to be the remainder of this division
            cur = P::from_coefficients_vec(num_vars, remainder_terms);
        }
        quotients
    }

    pub(crate) fn generate_mask_polynomial<F: Field>(
        mask_rng: &mut impl RngCore,
        num_variables: usize,
        deg: usize,
        sum_to_zero: bool,
    ) -> SparsePolynomial<F, SparseTerm> {
        let mut mask_polynomials: Vec<Vec<F>> = Vec::new();
        let mut sum_g = F::zero();
        for _ in 0..num_variables {
            let mut mask_poly = Vec::<F>::with_capacity(deg + 1);
            mask_poly.push(F::rand(mask_rng));
            sum_g += mask_poly[0] + mask_poly[0];
            for i in 1..deg + 1 {
                mask_poly.push(F::rand(mask_rng));
                sum_g += mask_poly[i];
            }
            mask_polynomials.push(mask_poly);
        }
        if sum_to_zero {
            mask_polynomials[0][0] -= sum_g / F::from(2u8);
        }
        let mut terms: Vec<(F, SparseTerm)> = Vec::new();
        for (var, variables_coef) in mask_polynomials.iter().enumerate() {
            variables_coef
                .iter()
                .enumerate()
                .for_each(|(degree, coef)| {
                    terms.push((coef.clone(), SparseTerm::new(vec![(var, degree)])))
                });
        }

        SparsePolynomial::from_coefficients_vec(num_variables, terms)
    }

    fn verify_consistency(
        vk: &MLVerifyingKey<E>,
        consistency_comm: E::G1Affine,
        individual_comms: &[MLCommitment<E>],
    ) -> bool {
        let start = start_timer!(|| "EPC Consistency Check");
        assert_eq!(vk.consistency_vk.len(), individual_comms.len());
        let mut pairing_lefts: Vec<_> = individual_comms
            .iter()
            .map(|comm| comm.g_product.into())
            .collect::<Vec<E::G1Prepared>>();
        pairing_lefts.push((-consistency_comm).into());
        let mut pairing_rights = vk.consistency_vk_prep.clone();
        pairing_rights.push(vk.h_prep.clone());
        let result = E::multi_pairing(pairing_lefts, pairing_rights).is_zero();
        end_timer!(start);
        result
    }

    /// generate eq(t,x), a product of multilinear polynomials with fixed t.
    /// eq(a,b) is takes extensions of a,b in {0,1}^num_vars such that if a and b in {0,1}^num_vars are equal
    /// then this polynomial evaluates to 1.
    fn eq_extension(t: &[E::ScalarField]) -> Vec<DenseMLE<E::ScalarField>> {
        let dim = t.len();
        let mut result = Vec::new();
        for i in 0..dim {
            let mut poly = Vec::with_capacity(1 << dim);
            for x in 0..(1 << dim) {
                let xi = if x >> i & 1 == 1 {
                    E::ScalarField::one()
                } else {
                    E::ScalarField::zero()
                };
                let ti = t[i];
                let ti_xi = ti * xi;
                poly.push(ti_xi + ti_xi - xi - ti + E::ScalarField::one());
            }
            result.push(DenseMLE::from_evaluations_vec(dim, poly));
        }

        result
    }

    /// fix first `pad` variables of `poly` represented in evaluation form to zero
    fn remove_dummy_variable(poly: &[E::ScalarField], pad: usize) -> Vec<E::ScalarField> {
        if pad == 0 {
            return poly.to_vec();
        }
        if !poly.len().is_power_of_two() {
            panic!("Size of polynomial should be power of two. ")
        }
        let nv = ark_std::log2(poly.len()) as usize - pad;
        let table: Vec<_> = (0..(1 << nv)).map(|x| poly[x << pad]).collect();
        table
    }

    pub fn produce_batched_poly_state(
        polys: &[DenseMLE<E::ScalarField>],
        comms: &MLBatchedCommitment<E>,
        state: &Vec<Option<SparsePolynomial<E::ScalarField, SparseTerm>>>,
    ) -> (
        DenseMLE<E::ScalarField>,
        SparsePolynomial<E::ScalarField, SparseTerm>,
    ) {
        let comms = &comms.individual_comms;
        let num_vars = polys[0].num_vars();
        for poly in polys {
            assert_eq!(poly.num_vars(), num_vars, "Invalid size of polynomial");
        }
        let challenges = Self::produce_opening_batch_challs(comms);
        let mut batched_poly =
            DenseMLE::from_evaluations_vec(num_vars, vec![E::ScalarField::zero(); 1 << num_vars]);
        for (poly, challenge) in polys.iter().zip(&challenges) {
            cfg_iter!(poly.evaluations)
                .zip(&mut batched_poly.evaluations)
                .for_each(|(eval, batched_eval)| {
                    *batched_eval += *challenge * eval;
                });
        }
        let mut batched_state = SparsePolynomial::zero();
        for (poly, chall) in state.iter().zip(challenges.iter()) {
            let mut p = poly.as_ref().unwrap().clone();
            p.terms.iter_mut().for_each(|(coeff, _)| {
                *coeff *= chall;
            });
            batched_state += &p;
        }

        (batched_poly, batched_state)
    }
    /// Convert polynomial coefficients to `BigInt`
    fn convert_to_bigints(
        p: &SparsePolynomial<E::ScalarField, SparseTerm>,
    ) -> Vec<<E::ScalarField as PrimeField>::BigInt> {
        let plain_coeffs = ark_std::cfg_into_iter!(p.terms())
            .map(|(coeff, _)| coeff.into_bigint())
            .collect();
        plain_coeffs
    }

    pub fn produce_opening_batch_challs(comms: &[MLCommitment<E>]) -> Vec<E::ScalarField> {
        let commitments = comms.iter().map(|x| x.g_product).collect::<Vec<_>>();
        let mut seed: Vec<u8> = Vec::new();
        let num = commitments.len();
        for commitment in commitments {
            seed.extend_from_slice(&to_bytes!(&commitment).unwrap());
        }
        let mut challanges: Vec<E::ScalarField> = Vec::new();
        for i in 0..num {
            seed.push(i as u8);
            challanges.push(E::ScalarField::from_be_bytes_mod_order(
                &Sha256::evaluate(&(), seed.clone()).unwrap(),
            ));
        }
        challanges
    }
}
