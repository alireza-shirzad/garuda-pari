use crate::data_structures::VerifyingKey;
use ark_ec::pairing::Pairing;

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
