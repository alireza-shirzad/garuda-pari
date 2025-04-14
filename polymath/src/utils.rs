use crate::data_structures::VerifyingKey;
use ark_ec::pairing::Pairing;
use shared_utils::transcript::{self, IOPTranscript};

pub fn sample_x1<E: Pairing>(
    transcript: &mut IOPTranscript<E::ScalarField>,
    vk: &VerifyingKey<E>,
    public_input: &[E::ScalarField],
    a: &E::G1Affine,
    c: &E::G1Affine,
) -> E::ScalarField {
    let _ = transcript.append_serializable_element(b"vk", vk);
    let _ = transcript.append_serializable_element(b"input", &public_input.to_vec());
    let _ = transcript.append_serializable_element(b"a", a);
    let _ = transcript.append_serializable_element(b"c", c);
    transcript.get_and_append_challenge("r".as_bytes()).unwrap()
}

pub fn sample_x2<E: Pairing>(
    transcript: &mut IOPTranscript<E::ScalarField>,
    x1: E::ScalarField,
    ax1: E::ScalarField,
) -> E::ScalarField {
    let _ = transcript.append_serializable_element(b"x1", &x1);
    let _ = transcript.append_serializable_element(b"ax1", &ax1);
    transcript.get_and_append_challenge("r".as_bytes()).unwrap()
}
