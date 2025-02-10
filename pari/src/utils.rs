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
#[cfg(feature = "sol")]
use tiny_keccak::{Hasher, Keccak};

#[cfg(feature = "sol")]
pub fn compute_chall<E: Pairing>(
    vk: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    t_g: &E::G1Affine,
) -> E::ScalarField {
    // Collect all inputs as byte arrays

    use ark_ec::CurveGroup;
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    // hasher.update(&to_bytes!(&t_g.x().unwrap()).unwrap());
    hasher.update(&[0u8; 1]);
    hasher.finalize(&mut output);
    // Convert first 31 bytes of the hash into a field element (ensuring it fits in the field)
    let challenge = E::ScalarField::from_be_bytes_mod_order(&output);
    E::ScalarField::from(5)
}
