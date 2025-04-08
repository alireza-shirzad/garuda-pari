use std::ops::Neg;

use crate::{Polymath, data_structures::VerifyingKey};
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_std::Zero;
use ark_std::rand::RngCore;

impl<E: Pairing> Polymath<E> {
    pub(crate) fn compute_c_at_x1(
        y1_gamma: E::ScalarField,
        y1_alpha: E::ScalarField,
        a_at_x1: E::ScalarField,
        full_public_input: &[E::ScalarField],
        x1: E::ScalarField,
        vk: &VerifyingKey<E>,
    ) -> E::ScalarField {
        let pi_poly =
            Evaluations::from_vec_and_domain(full_public_input.to_vec(), vk.k_domain).interpolate();
        let pi_at_x1 = pi_poly.evaluate(&x1);
        let n_field = E::ScalarField::from(vk.n as u64);
        let m0_field = E::ScalarField::from(vk.m0 as u64);
        let z_h_over_k = vk.h_domain.evaluate_vanishing_polynomial(x1)
            / vk.k_domain.evaluate_vanishing_polynomial(x1);
        ((a_at_x1 + y1_gamma) * a_at_x1 - pi_at_x1 * z_h_over_k * m0_field / n_field) / y1_alpha
    }

    fn z_tilde_i(public_inputs: &[E::ScalarField], i: usize) -> E::ScalarField {
        let m0 = public_inputs.len();
        let one = E::ScalarField::ONE;

        match i {
            0 => one + one,

            i if i < m0 => {
                let j = i;
                one + public_inputs[j]
            }

            i if i == m0 => E::ScalarField::zero(),

            i => {
                // i > m0
                let j = i - m0;
                one - public_inputs[j]
            }
        }
    }
}
