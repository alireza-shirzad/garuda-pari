use std::marker::PhantomData;

use super::{
    data_structures::{
        MLBatchedCommitment, MLCommitment, MLCommitmentKey, MLPublicParameters, MLTrapdoor,
        MLVerifyingKey,
    },
    EPC,
};
use crate::to_bytes;
use ark_crypto_primitives::crh::{sha256::Sha256, CRHScheme};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ec::{scalar_mul::BatchMulPreprocessing, ScalarMul};
use ark_ff::PrimeField;
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
use ark_std::UniformRand;
use ark_std::{collections::LinkedList, end_timer, start_timer};
use ark_std::{rand::RngCore, One, Zero};

use std::ops::Mul;
pub struct MultilinearEPC<E: Pairing, R: RngCore> {
    _p1: PhantomData<E>,
    _p2: PhantomData<R>,
}

impl<E: Pairing, R: RngCore> EPC<R> for MultilinearEPC<E, R> {
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
    type Polynomial = DenseMultilinearExtension<E::ScalarField>;
    type Equifficient = E::ScalarField;
    type BasisPoly = SparseMultilinearExtension<E::ScalarField>;
    type PolynomialBasis = Vec<Self::BasisPoly>;
    type EquifficientConstraint = Vec<Self::PolynomialBasis>;

    fn setup(
        rng: &mut R,
        pp: &Self::PublicParameters,
        equifficient_constraints: &Self::EquifficientConstraint,
    ) -> (Self::CommitmentKey, Self::VerifyingKey, Self::Trapdoor) {
        let dim = equifficient_constraints[0].len();
        let tau: Vec<E::ScalarField> = (0..pp.num_var).map(|_| E::ScalarField::rand(rng)).collect();

        let consistency_challanges: Vec<E::ScalarField> = (0..pp.num_constraints)
            .map(|_| E::ScalarField::rand(rng))
            .collect();

        let mut powers_of_g = Vec::new();
        let mut eq: LinkedList<DenseMultilinearExtension<E::ScalarField>> =
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

        let g_table = BatchMulPreprocessing::new(pp.generators.g, pp.num_var);
        let h_table = BatchMulPreprocessing::new(pp.generators.h, pp.num_var);
        let pp_g = g_table.batch_mul(&pp_powers);
        let mut start = 0;
        for i in 0..pp.num_var {
            let size = 1 << (pp.num_var - i);
            let pp_k_g = (&pp_g[start..(start + size)]).to_vec();
            powers_of_g.push(pp_k_g);
            start += size;
        }
        let h_mask = h_table.batch_mul(&tau);

        // Consistency stuff

        let mut randomized_basis_set: Vec<E::ScalarField> = Vec::new();
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
                h_mask_random: h_mask,
                consistency_vk,
            },
            MLTrapdoor {
                tau,
                consistency_challanges,
            },
        )
    }

    fn commit(ck: &Self::CommitmentKey, poly: &Self::Polynomial) -> Self::Commitment {
        let scalars: Vec<_> = poly
            .to_evaluations()
            .into_iter()
            .map(|x| x.into_bigint())
            .collect();
        Self::Commitment {
            nv: ck.nv,
            g_product: <E::G1 as VariableBaseMSM>::msm_bigint(
                &ck.powers_of_g[0],
                scalars.as_slice(),
            )
            .into_affine(),
        }
    }

    fn batch_commit(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        equifficients: Option<&[Self::Equifficient]>,
    ) -> Self::BatchedCommitment {
        let timer_indiv_comm = start_timer!(|| "Individual commits");
        let mut individual_comms = Vec::new();
        for poly in polys {
            individual_comms.push(Self::commit(ck, poly));
        }
        end_timer!(timer_indiv_comm);
        match equifficients {
            Some(equifficients) => {
                let timer_consistency_comm = start_timer!(|| "Consistency commitment");
                let consistency_comm: <E as Pairing>::G1 =
                    E::G1::msm(&ck.consistency_pk, equifficients).unwrap();
                end_timer!(timer_consistency_comm);
                Self::BatchedCommitment {
                    individual_comms,
                    consistency_comm: Some(consistency_comm),
                }
            }
            None => Self::BatchedCommitment {
                individual_comms,
                consistency_comm: None,
            },
        }
    }

    fn open(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        point: &Self::EvaluationPoint,
        _comm: &Self::Commitment,
    ) -> Self::OpeningProof {
        let nv = poly.num_vars();
        let mut r: Vec<Vec<E::ScalarField>> = (0..nv + 1).map(|_| Vec::new()).collect();
        let mut q: Vec<Vec<E::ScalarField>> = (0..nv + 1).map(|_| Vec::new()).collect();

        r[nv] = poly.to_evaluations();

        let mut proofs = Vec::new();
        for i in 0..nv {
            let k = nv - i;
            let point_at_k = point[i];
            q[k] = (0..(1 << (k - 1)))
                .map(|_| E::ScalarField::zero())
                .collect();
            r[k - 1] = (0..(1 << (k - 1)))
                .map(|_| E::ScalarField::zero())
                .collect();
            for b in 0..(1 << (k - 1)) {
                q[k][b] = r[k][(b << 1) + 1] - &r[k][b << 1];
                r[k - 1][b] = r[k][b << 1] * &(E::ScalarField::one() - &point_at_k)
                    + &(r[k][(b << 1) + 1] * &point_at_k);
            }
            let scalars: Vec<_> = (0..(1 << k))
                .map(|x| q[k][x >> 1].into_bigint()) // fine
                .collect();

            let pi_h =
                <E::G1 as VariableBaseMSM>::msm_bigint(&ck.powers_of_g[i], scalars.as_slice())
                    .into_affine(); // no need to move outside and partition
            proofs.push(pi_h);
        }
        proofs
    }

    fn BatchOpen(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        point: &Self::EvaluationPoint,
        comms: &Self::BatchedCommitment,
    ) -> Self::BatchedOpeningProof {
        let timer_batch_polys = start_timer!(|| "Batching Polys");
        let batched_poly: DenseMultilinearExtension<E::ScalarField> =
            Self::produce_batched_poly(polys, comms);
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
        let left = E::pairing(comm.g_product.into_group() - &vk.g.mul(eval), vk.h);

        let h_mul = vk.h.into_group().batch_mul(point);

        let pairing_rights: Vec<_> = (0..comm.nv)
            .map(|i| vk.h_mask_random[i].into_group() - &h_mul[i])
            .collect();
        let pairing_rights: Vec<E::G2Affine> = E::G2::normalize_batch(&pairing_rights);
        let pairing_rights: Vec<E::G2Prepared> = pairing_rights
            .into_iter()
            .map(|x| E::G2Prepared::from(x))
            .collect();

        let pairing_lefts: Vec<E::G1Prepared> =
            proof.iter().map(|x| E::G1Prepared::from(*x)).collect();

        let right = E::multi_pairing(pairing_lefts, pairing_rights);
        left == right
    }

    fn BatchVerify(
        vk: &Self::VerifyingKey,
        comm: &Self::BatchedCommitment,
        point: &Self::EvaluationPoint,
        evals: &[Self::Evaluation],
        proof: &Self::BatchedOpeningProof,
        constrained_num: usize,
    ) -> bool {
        // perform the consistency check on the constrained polyanomials, i.e. check the equifficiency property
        match &comm.consistency_comm {
            Some(consistency_comm) => {
                Self::verify_consistency(
                    vk,
                    *consistency_comm,
                    &comm.individual_comms[..constrained_num],
                );
            }
            None => {}
        }
        let individual_comms = &comm.individual_comms;
        let g_products: Vec<_> = individual_comms.iter().map(|x| x.g_product).collect();
        assert_eq!(
            evals.len(),
            individual_comms.len(),
            "Invalid size of values"
        );
        let challs_field: Vec<_> = Self::produce_opening_batch_challs(individual_comms);
        let challs_bigint: Vec<_> = challs_field.iter().map(|x| x.into_bigint()).collect();
        let batched_eval = challs_field
            .iter()
            .zip(evals.iter())
            .fold(E::ScalarField::zero(), |acc, (x, y)| acc + (*x * y));
        let batched_comm =
            <E::G1 as VariableBaseMSM>::msm_bigint(&g_products, challs_bigint.as_slice())
                .into_affine();
        let result = Self::verify(
            vk,
            &MLCommitment {
                nv: individual_comms[0].nv,
                g_product: batched_comm,
            },
            point,
            &batched_eval,
            proof,
        );
        result
    }
}
impl<E: Pairing, R: RngCore> MultilinearEPC<E, R> {
    fn verify_consistency(
        vk: &MLVerifyingKey<E>,
        consistency_comm: E::G1,
        individual_comms: &[MLCommitment<E>],
    ) {
        assert_eq!(vk.consistency_vk.len(), individual_comms.len());
        let left: PairingOutput<E> = E::pairing(consistency_comm, vk.h);
        let pairing_lefts: Vec<E::G1Prepared> = individual_comms
            .iter()
            .map(|comm| E::G1Prepared::from(comm.g_product))
            .collect();
        let pairing_rights: Vec<E::G2Prepared> =
            vk.consistency_vk.iter().map(E::G2Prepared::from).collect();
        let right: PairingOutput<E> = E::multi_pairing(pairing_lefts, pairing_rights);
        if left != right {
            panic!("consistency check failed");
        }
    }

    /// generate eq(t,x), a product of multilinear polynomials with fixed t.
    /// eq(a,b) is takes extensions of a,b in {0,1}^num_vars such that if a and b in {0,1}^num_vars are equal
    /// then this polynomial evaluates to 1.
    fn eq_extension(t: &[E::ScalarField]) -> Vec<DenseMultilinearExtension<E::ScalarField>> {
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
            result.push(DenseMultilinearExtension::from_evaluations_vec(dim, poly));
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
        polys: &[DenseMultilinearExtension<E::ScalarField>],
        comms: &MLBatchedCommitment<E>,
    ) -> DenseMultilinearExtension<E::ScalarField> {
        let comms = &comms.individual_comms;
        let num_vars = polys[0].num_vars();
        for poly in polys {
            assert_eq!(poly.num_vars(), num_vars, "Invalid size of polynomial");
        }
        let num_polynomials = comms.len();
        let challs = Self::produce_opening_batch_challs(comms);
        let mut batched_poly: DenseMultilinearExtension<E::ScalarField> =
            DenseMultilinearExtension::zero();
        for i in 0..num_polynomials {
            let new_evaluations: Vec<<E as Pairing>::ScalarField> = polys[i]
                .to_evaluations()
                .iter()
                .map(|eval| *eval * challs[i])
                .collect();
            batched_poly +=
                DenseMultilinearExtension::from_evaluations_vec(num_vars, new_evaluations);
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
