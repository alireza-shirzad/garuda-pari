use crate::data_structures::VerifyingKey;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use shared_utils::transcript::IOPTranscript;
#[cfg(not(feature = "sol"))]
pub fn compute_chall<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    t_g: &E::G1Affine,
) -> E::ScalarField {
    let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
        IOPTranscript::<E::ScalarField>::new("".as_bytes());
    let _ = transcript.append_serializable_element("vk".as_bytes(), vk);
    let _ = transcript.append_serializable_element("input".as_bytes(), &public_input.to_vec());
    let _ = transcript.append_serializable_element("batched_commitments".as_bytes(), t_g);
    let challenge = transcript.get_and_append_challenge("r".as_bytes()).unwrap();
    challenge
}

#[cfg(feature = "sol")]
use ark_ec::AffineRepr;
#[cfg(feature = "sol")]
use ark_serialize::CanonicalSerialize;
#[cfg(feature = "sol")]
use shared_utils::to_bytes;

use ark_ff::Field;
#[cfg(feature = "sol")]
use tiny_keccak::{Hasher, Keccak};
#[cfg(feature = "sol")]
pub fn compute_chall<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    t_g: &E::G1Affine,
) -> E::ScalarField
where
    E::BaseField: PrimeField,
    <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField,
{
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    let binding = vk.h.into().x().unwrap();
    let mut vk_h_x = binding.to_base_prime_field_elements();
    let binding = vk.h.into().y().unwrap();
    let mut vk_h_y = binding.to_base_prime_field_elements();

    let binding = vk.delta_two_h.into().x().unwrap();
    let mut vk_delta_h_x = binding.to_base_prime_field_elements();
    let binding = vk.delta_two_h.into().y().unwrap();
    let mut vk_delta_h_y = binding.to_base_prime_field_elements();

    let binding = vk.tau_h.into().x().unwrap();
    let mut vk_tau_h_x = binding.to_base_prime_field_elements();
    let binding = vk.tau_h.into().y().unwrap();
    let mut vk_tau_h_y = binding.to_base_prime_field_elements();

    hasher.update(&encode_packed(t_g.x().unwrap()));
    hasher.update(&encode_packed(t_g.y().unwrap()));
    hasher.update(&encode_packed(E::ScalarField::from(1)));
    for elem in public_input.iter() {
        hasher.update(&encode_packed(*elem));
    }

    hasher.update(&encode_packed(vk.g.into().x().unwrap()));
    hasher.update(&encode_packed(vk.g.into().y().unwrap()));
    hasher.update(&encode_packed(vk.alpha_g.into().x().unwrap()));
    hasher.update(&encode_packed(vk.alpha_g.into().y().unwrap()));
    hasher.update(&encode_packed(vk.beta_g.into().x().unwrap()));
    hasher.update(&encode_packed(vk.beta_g.into().y().unwrap()));
    hasher.update(&encode_packed(vk_h_x.next().unwrap()));
    hasher.update(&encode_packed(vk_h_x.next().unwrap()));
    hasher.update(&encode_packed(vk_h_y.next().unwrap()));
    hasher.update(&encode_packed(vk_h_y.next().unwrap()));
    hasher.update(&encode_packed(vk_delta_h_x.next().unwrap()));
    hasher.update(&encode_packed(vk_delta_h_x.next().unwrap()));
    hasher.update(&encode_packed(vk_delta_h_y.next().unwrap()));
    hasher.update(&encode_packed(vk_delta_h_y.next().unwrap()));
    hasher.update(&encode_packed(vk_tau_h_x.next().unwrap()));
    hasher.update(&encode_packed(vk_tau_h_x.next().unwrap()));
    hasher.update(&encode_packed(vk_tau_h_y.next().unwrap()));
    hasher.update(&encode_packed(vk_tau_h_y.next().unwrap()));
    hasher.finalize(&mut output);
    E::ScalarField::from_be_bytes_mod_order(&output)
}

use num_bigint::BigUint;
fn encode_packed<F: PrimeField>(field_element: F) -> Vec<u8> {
    let a: BigUint = field_element.into();
    let mut b = a.to_bytes_be();

    if b.len() < 32 {
        let mut padded = vec![0u8; 32 - b.len()];
        padded.extend_from_slice(&b);
        b = padded;
    }

    b
}
