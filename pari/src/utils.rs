use crate::data_structures::Index;
use ark_ff::Field;
use ark_relations::gr1cs::{Matrix, R1CS_PREDICATE_LABEL};

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

fn evaluate_lagrange_poly<D: EvaluationDomain<F>>(index: usize, tau: F, domain: &D) -> F {
    let v_tau = domain.evaluate_vanishing_polynomial(tau);
    let i_th_element = domain.element(index);
    i_th_element * &v_tau * domain.size_inv() * (tau - i_th_element).inverse().unwrap()
}