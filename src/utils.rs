use crate::data_structures::GroupParams;
use ark_crypto_primitives::crh::{sha256::Sha256, CRHScheme};
use ark_ec::ScalarMul;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
use ark_std::One;
use ark_std::Zero;
use std::ops::Mul;
/// Takes as input a struct, and converts them to a series of bytes. All traits
/// that implement `CanonicalSerialize` can be automatically converted to bytes
/// in this manner.
#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = ark_std::vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed($x, &mut buf).map(|_| buf)
    }};
}

pub fn epc_unconstrained_commit<E: Pairing>(
    group_params: &GroupParams<E>,
    polynomial: &impl MultilinearExtension<E::ScalarField>,
) -> E::G1Affine {
    let scalars: Vec<_> = polynomial
        .to_evaluations()
        .into_iter()
        .map(|x| x.into_bigint())
        .collect();

    <E::G1 as VariableBaseMSM>::msm_bigint(&group_params.powers_of_g[0], scalars.as_slice())
        .into_affine()
}

pub fn generate_opening_proof<E: Pairing>(
    group_params: &GroupParams<E>,
    polys: &[DenseMultilinearExtension<E::ScalarField>],
    comms: &[E::G1Affine],
    point: &[E::ScalarField],
) -> Vec<E::G1Affine> {
    let batched_poly: DenseMultilinearExtension<E::ScalarField> =
        produce_batched_poly::<E>(polys, comms);
    let nv = batched_poly.num_vars();
    let mut r: Vec<Vec<E::ScalarField>> = (0..nv + 1).map(|_| Vec::new()).collect();
    let mut q: Vec<Vec<E::ScalarField>> = (0..nv + 1).map(|_| Vec::new()).collect();

    r[nv] = batched_poly.to_evaluations();

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

        let pi_h = <E::G1 as VariableBaseMSM>::msm_bigint(
            &group_params.powers_of_g[i],
            scalars.as_slice(),
        )
        .into_affine(); // no need to move outside and partition
        proofs.push(pi_h);
    }
    proofs
}

pub fn produce_batched_poly<E: Pairing>(
    polys: &[DenseMultilinearExtension<E::ScalarField>],
    comms: &[E::G1Affine],
) -> DenseMultilinearExtension<E::ScalarField> {
    let num_vars = polys[0].num_vars();
    for poly in polys {
        assert_eq!(poly.num_vars(), num_vars, "Invalid size of polynomial");
    }
    let num_polynomials = comms.len();
    let challs = produce_opening_batch_challs::<E>(comms);
    let mut batched_poly: DenseMultilinearExtension<E::ScalarField> =
        DenseMultilinearExtension::zero();
    for i in 0..num_polynomials {
        let new_evaluations: Vec<<E as Pairing>::ScalarField> = polys[i]
            .to_evaluations()
            .iter()
            .map(|eval| *eval * challs[i])
            .collect();
        batched_poly += DenseMultilinearExtension::from_evaluations_vec(num_vars, new_evaluations);
    }

    batched_poly
}

pub fn produce_opening_batch_challs<E: Pairing>(
    commitments: &[E::G1Affine],
) -> Vec<E::ScalarField> {
    let mut seed: Vec<u8> = Vec::new();
    let num = commitments.len();
    for commitment in commitments {
        seed.extend_from_slice(&to_bytes!(commitment).unwrap());
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
pub fn epc_constrained_commit<E: Pairing>(
    group_params: &GroupParams<E>,
    consistency_pk: &[E::G1Affine],
    polynomials: &[impl MultilinearExtension<E::ScalarField>],
    equiffients: &[E::ScalarField],
) -> (Vec<E::G1Affine>, E::G1) {
    let mut commitments: Vec<E::G1Affine> = Vec::new();
    for poly in polynomials {
        let commitment: E::G1Affine = epc_unconstrained_commit(group_params, poly);
        commitments.push(commitment);
    }
    let consistency_commitment: <E as Pairing>::G1 =
        E::G1::msm(consistency_pk, equiffients).unwrap();
    (commitments, consistency_commitment)
}

pub fn epc_batch_check<E: Pairing>(
    g_h: (&E::G1Affine, &E::G2Affine),
    h_mask_random: &[E::G2Affine], 
    comms: &[E::G1Affine],
    point: &[E::ScalarField],
    evals: &[E::ScalarField],
    proof: &[E::G1Affine],
    nv: usize,
) -> bool {
    // assert_eq!(evals.len(), comms.len(), "Invalid size of values");
    // let challs_field: Vec<_> = produce_opening_batch_challs::<E>(comms);
    // let challs_bigint: Vec<_> = challs_field.iter().map(|x| x.into_bigint()).collect();
    // let batched_eval = challs_field
    //     .iter()
    //     .zip(evals.iter())
    //     .fold(E::ScalarField::zero(), |acc, (x, y)| acc + (*x * y));
    // let batched_comm =
    //     <E::G1 as VariableBaseMSM>::msm_bigint(comms, challs_bigint.as_slice()).into_affine();
    assert_eq!(evals.len(), comms.len(), "Invalid size of values");
    let mut final_g_product = Vec::new();
    for commitment in comms {
        final_g_product.push(*commitment);
    }
    let challanges: Vec<E::ScalarField> = produce_opening_batch_challs::<E>(comms);
    let random_value = challanges.iter().zip(evals.iter()).fold(E::ScalarField::zero(), |acc, (x, y)| acc + &(*x * y));


    let scalars:Vec<_> = challanges.iter().map(|x| x.into_bigint()).collect();
    let commitment = <E::G1 as VariableBaseMSM>::msm_bigint(&final_g_product, scalars.as_slice()).into_affine();
    epc_check::<E>(g_h, commitment, point, random_value, proof, h_mask_random, nv)
}

/// Verifies that `value` is the evaluation at `x` of the polynomial
/// committed inside `comm`.
fn epc_check<E: Pairing>(
    g_h: (&E::G1Affine, &E::G2Affine),
    comm: E::G1Affine,
    point: &[E::ScalarField],
    eval: E::ScalarField,
    proof: &[E::G1Affine],
    h_mask_random: &[E::G2Affine],
    nv: usize,
) -> bool {
    let g = g_h.0;
    let h = g_h.1;
    let left = E::pairing(comm.into_group() - &g.mul(eval), h);

    let h_mul = h.into_group().batch_mul(point);

    let pairing_rights: Vec<_> = (0..nv)
        .map(|i| h_mask_random[i].into_group() - &h_mul[i])
        .collect();
    let pairing_rights: Vec<E::G2Affine> = E::G2::normalize_batch(&pairing_rights);
    let pairing_rights: Vec<E::G2Prepared> = pairing_rights
        .into_iter()
        .map(|x| E::G2Prepared::from(x))
        .collect();

    let pairing_lefts: Vec<E::G1Prepared> = proof
        .iter()
        .map(|x| E::G1Prepared::from(*x))
        .collect();

    let right = E::multi_pairing(pairing_lefts, pairing_rights);
    left == right
}
