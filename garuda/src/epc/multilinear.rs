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
use ark_ff::PrimeField;
use ark_poly::{
    DenseMultilinearExtension as DenseMLE, MultilinearExtension, Polynomial,
    SparseMultilinearExtension,
};
use ark_std::{cfg_chunks, cfg_iter, marker::PhantomData, UniformRand};
use ark_std::{collections::LinkedList, end_timer, start_timer};
use ark_std::{rand::RngCore, One, Zero};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use shared_utils::msm_bigint_wnaf;

use std::ops::Mul;
pub struct MultilinearEPC<E: Pairing> {
    _p1: PhantomData<E>,
}

impl<E: Pairing> EPC for MultilinearEPC<E> {
    type PublicParameters = MLPublicParameters<E>;
    type OpeningProof = Vec<E::G1Affine>;
    type BatchedOpeningProof = Vec<E::G1Affine>;
    type CommitmentKey = MLCommitmentKey<E>;
    type VerifyingKey = MLVerifyingKey<E>;
    type Evaluation = E::ScalarField;
    type EvaluationPoint = Vec<E::ScalarField>;
    type Trapdoor = MLTrapdoor<E>;
    type Commitment = MLCommitment<E>;
    type BatchedCommitment = MLBatchedCommitment<E>;
    type Polynomial = DenseMLE<E::ScalarField>;
    type Equifficient = E::ScalarField;
    type BasisPoly = SparseMultilinearExtension<E::ScalarField>;
    type PolynomialBasis = Vec<Self::BasisPoly>;
    type EquifficientConstraint = Vec<Self::PolynomialBasis>;

    fn setup(
        mut rng: impl RngCore,
        pp: &Self::PublicParameters,
        equifficient_constraints: &Self::EquifficientConstraint,
    ) -> (Self::CommitmentKey, Self::VerifyingKey, Self::Trapdoor) {
        let dim = equifficient_constraints[0].len();
        let tau: Vec<E::ScalarField> = (0..pp.num_var)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        let consistency_challanges: Vec<E::ScalarField> = (0..pp.num_constraints)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        let mut powers_of_g = Vec::new();
        let mut eq: LinkedList<DenseMLE<E::ScalarField>> =
            LinkedList::from_iter(Self::eq_extension(&tau).into_iter());
        let mut eq_arr = LinkedList::new();
        let mut base = eq.pop_back().unwrap().evaluations;

        for i in (0..pp.num_var).rev() {
            eq_arr.push_front(Self::remove_dummy_variable(&base, i));
            if i != 0 {
                let mul = eq.pop_back().unwrap().evaluations;
                base = base
                    .into_iter()
                    .zip(mul.into_iter())
                    .map(|(a, b)| a * &b)
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
        let h_mask = h_table.batch_mul(&tau);

        // Consistency stuff

        let mut randomized_basis_set = Vec::new();
        for i in 0..dim {
            let value = equifficient_constraints
                .iter()
                .zip(consistency_challanges.iter())
                .fold(
                    E::ScalarField::zero(),
                    |acc, (basis_set, consistency_chall)| {
                        acc + (basis_set[i].evaluate(&tau) * consistency_chall)
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
        let h_mask_random_prep: Vec<E::G2Prepared> =
            h_mask.iter().map(|x| E::G2Prepared::from(*x)).collect();

        (
            MLCommitmentKey {
                nv: pp.num_var,
                powers_of_g,
                g: pp.generators.g.into(),
                h: pp.generators.h.into(),
                consistency_pk,
            },
            MLVerifyingKey {
                nv: pp.num_var,
                g: pp.generators.g.into(),
                h: pp.generators.h.into(),
                h_prep: pp.generators.h.into().into(),
                h_mask_random: h_mask,
                h_mask_random_prep,
                consistency_vk,
                consistency_vk_prep,
            },
            MLTrapdoor {
                tau,
                consistency_challanges,
            },
        )
    }

    fn commit(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        rest_zero: Option<usize>,
    ) -> Self::Commitment {
        let rest_zero = rest_zero.unwrap_or(1 << poly.num_vars());
        let scalars: Vec<_> = cfg_iter!(poly.evaluations[..rest_zero])
            .map(|x| x.into_bigint())
            .collect();
        Self::Commitment {
            nv: ck.nv,
            g_product: E::G1::msm_bigint(&ck.powers_of_g[0], scalars.as_slice()).into_affine(),
        }
    }

    fn batch_commit(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        rest_zeros: &[Option<usize>],
        equifficients: Option<&[Self::Equifficient]>,
    ) -> Self::BatchedCommitment {
        let timer_indiv_comm = start_timer!(|| "Individual commits");
        #[cfg(feature = "parallel")]
        use rayon::iter::once;
        #[cfg(not(feature = "parallel"))]
        use std::iter::once;
        let mut individual_comms = cfg_iter!(polys)
            .zip(rest_zeros)
            .map(|(poly, rest_zero)| Self::commit(ck, poly, *rest_zero))
            .chain(once({
                let g = match equifficients {
                    Some(e) => E::G1::msm(&ck.consistency_pk, e).unwrap(),
                    None => E::G1::zero(),
                };
                MLCommitment {
                    nv: 0,
                    g_product: g.into_affine(),
                }
            }))
            .collect::<Vec<_>>();
        end_timer!(timer_indiv_comm);
        let consistency_comm = individual_comms.pop().unwrap().g_product;
        Self::BatchedCommitment {
            individual_comms,
            consistency_comm: equifficients.map(|_| consistency_comm),
        }
    }

    fn open(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        point: &Self::EvaluationPoint,
        _comm: &Self::Commitment,
    ) -> Self::OpeningProof {
        let nv = poly.num_vars();
        let mut current_r = poly.to_evaluations();
        let mut last_r = vec![E::ScalarField::zero(); 1 << (nv - 1)];
        let zero = <E::ScalarField as PrimeField>::BigInt::from(0u8);
        let mut current_q = vec![zero; 1 << (nv - 1)];

        let mut all_scalars = Vec::with_capacity(nv);
        let compute_scalars_time = start_timer!(|| "Compute scalars");
        for i in 0..nv {
            let k = nv - i;
            let point_at_k = point[i];
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
            all_scalars.push(current_q.clone());
        }
        end_timer!(compute_scalars_time);

        let msm_time = start_timer!(|| "MSM");
        let proofs = cfg_iter!(all_scalars)
            .zip(&ck.powers_of_g[1..])
            .map(|(scalars, powers)| E::G1::msm_bigint(&powers, &scalars).into_affine())
            .collect::<Vec<_>>();
        end_timer!(msm_time);
        proofs
    }

    fn batch_open(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        point: &Self::EvaluationPoint,
        comms: &Self::BatchedCommitment,
    ) -> Self::BatchedOpeningProof {
        let timer_batch_polys = start_timer!(|| "Batching Polys");
        let batched_poly = Self::produce_batched_poly(polys, comms);
        end_timer!(timer_batch_polys);
        let timer_open_batched_polys = start_timer!(|| "Open batched polys");
        let result = Self::open(ck, &batched_poly, point, &comms.individual_comms[0]);
        end_timer!(timer_open_batched_polys);
        result
    }

    fn verify(
        vk: &Self::VerifyingKey,
        comm: &Self::Commitment,
        point: &Self::EvaluationPoint,
        eval: &Self::Evaluation,
        proof: &Self::OpeningProof,
    ) -> bool {
        let verify_time = start_timer!(|| "EPC Verify");
        let lhs = {
            let mut left_input = comm.g_product.into_group() - &vk.g.mul(*eval);
            let point_bigint = point.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
            left_input += msm_bigint_wnaf::<E::G1>(proof, point_bigint.as_slice());

            let right_input = vk.h_prep.clone();
            (left_input.into().into(), right_input)
        };
        let mut rhs = {
            let left_inputs = proof
                .iter()
                .map(|x| E::G1Prepared::from(-*x))
                .collect::<Vec<_>>();
            let right_inputs = vk.h_mask_random_prep.clone();
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
        evals: &[Self::Evaluation],
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
                g_products.extend(proof.clone());
                g_products.push(vk.g);
                let scalars = challs_bigint
                    .chain(point_bigint)
                    .chain(std::iter::once((-*eval).into_bigint()))
                    .collect::<Vec<_>>();
                let left_input = msm_bigint_wnaf::<E::G1>(&g_products, scalars.as_slice());

                let right_input = vk.h_prep.clone();
                (left_input.into().into(), right_input)
            };
            let mut rhs = {
                let left_inputs = proof
                    .iter()
                    .map(|x| E::G1Prepared::from(-*x))
                    .collect::<Vec<_>>();
                let right_inputs = vk.h_mask_random_prep.clone();
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

    pub fn produce_batched_poly(
        polys: &[DenseMLE<E::ScalarField>],
        comms: &MLBatchedCommitment<E>,
    ) -> DenseMLE<E::ScalarField> {
        let comms = &comms.individual_comms;
        let num_vars = polys[0].num_vars();
        for poly in polys {
            assert_eq!(poly.num_vars(), num_vars, "Invalid size of polynomial");
        }
        let challenges = Self::produce_opening_batch_challs(comms);
        let mut batched_poly =
            DenseMLE::from_evaluations_vec(num_vars, vec![E::ScalarField::zero(); 1 << num_vars]);
        for (poly, challenge) in polys.iter().zip(challenges) {
            cfg_iter!(poly.evaluations)
                .zip(&mut batched_poly.evaluations)
                .for_each(|(eval, batched_eval)| {
                    *batched_eval += challenge * eval;
                });
        }

        batched_poly
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
