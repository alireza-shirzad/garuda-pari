use crate::data_structures::VerifyingKey;
use ark_ec::pairing::Pairing;

#[cfg(not(feature = "sol"))]
pub fn compute_chall<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    a: &E::G1Affine,
    c: &E::G1Affine,
    sec_chall: Option<(E::ScalarField, E::ScalarField)>,
) -> E::ScalarField {
    use shared_utils::transcript::IOPTranscript;
    let mut transcript = IOPTranscript::<E::ScalarField>::new(crate::Polymath::<E>::SNARK_NAME);
    let _ = transcript.append_serializable_element(b"vk", vk);
    let _ = transcript.append_serializable_element(b"input", &public_input.to_vec());
    let _ = transcript.append_serializable_element(b"comm", a);
    match sec_chall {
        Some((x, y)) => {
            let _ = transcript.append_serializable_element(b"sec_chall_x", &x);
            let _ = transcript.append_serializable_element(b"sec_chall_y", &y);
        }
        None => {}
    }
    let challenge = transcript.get_and_append_challenge("r".as_bytes()).unwrap();
    challenge
}
#[cfg(feature = "sol")]
use ark_ec::AffineRepr;
#[cfg(feature = "sol")]
use ark_ff::PrimeField;
use ark_ff::{FftField, batch_inversion_and_mul};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

#[cfg(feature = "sol")]
pub fn compute_chall<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    a: &E::G1Affine,
    c: &E::G1Affine,
    sec_chall: Option<(E::ScalarField, E::ScalarField)>,
) -> E::ScalarField
where
    E::BaseField: PrimeField,
    <E::G1Affine as AffineRepr>::BaseField: PrimeField,
{
    todo!()
}

#[cfg(feature = "sol")]
fn encode_packed<F: PrimeField>(field_element: F) -> Vec<u8> {
    use num_bigint::BigUint;

    let a: BigUint = field_element.into();
    let mut b = a.to_bytes_be();

    if b.len() < 32 {
        let mut padded = vec![0u8; 32 - b.len()];
        padded.extend_from_slice(&b);
        b = padded;
    }

    b
}

pub fn eval_last_lagrange_coeffs<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    tau: F,
    start_ind: usize,
    count: usize,
) -> (Vec<F>, F) {
    let z_h_at_tau: F = domain.evaluate_vanishing_polynomial(tau);
    let group_gen: F = domain.group_gen();

    assert!(!z_h_at_tau.is_zero());

    let group_gen_inv = domain.group_gen_inv();
    let v_0_inv = domain.size_as_field_element();

    let start_gen = group_gen.pow([start_ind as u64]);
    let z_h_at_tau_inv = z_h_at_tau.inverse().unwrap();
    let mut l_i = z_h_at_tau_inv * v_0_inv;
    let mut negative_cur_elem = -start_gen;
    let mut lagrange_coefficients_inverse = vec![F::zero(); count];
    for coeff in &mut lagrange_coefficients_inverse.iter_mut() {
        *coeff = l_i * (tau + negative_cur_elem);
        l_i *= &group_gen_inv;
        negative_cur_elem *= &group_gen;
    }
    batch_inversion_and_mul(lagrange_coefficients_inverse.as_mut_slice(), &start_gen);
    (lagrange_coefficients_inverse, z_h_at_tau_inv)
}
