use std::ops::Neg;

use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_std::rand::RngCore;

use crate::Polymath;

impl<E: Pairing> Polymath<E> {
    pub fn compute_c_at_x1(
        y1_to_gamma: E::ScalarField,
        y1_alpha: E::ScalarField,
        a_at_x1: E::ScalarField,
        pi_at_x1: E::ScalarField,
        m0: E::ScalarField,
        n: E::ScalarField,
        h_domain: GeneralEvaluationDomain<E::ScalarField>,
        k_domain: GeneralEvaluationDomain<E::ScalarField>,
        x1: E::ScalarField,
    ) -> E::ScalarField {
        ((a_at_x1 + y1_to_gamma) * a_at_x1
            - pi_at_x1 * m0 * Self::compute_z_of_h_over_k_of_x1(h_domain, k_domain, x1) / n)
            / y1_alpha
    }

    fn compute_z_of_h_over_k_of_x1(
        h_domain: GeneralEvaluationDomain<E::ScalarField>,
        k_domain: GeneralEvaluationDomain<E::ScalarField>,
        x1: E::ScalarField,
    ) -> E::ScalarField {
        h_domain.evaluate_vanishing_polynomial(x1) / k_domain.evaluate_vanishing_polynomial(x1)
    }
}
