use std::ops::Neg;

use crate::{Polymath, data_structures::VerifyingKey};
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_std::Zero;
use ark_std::rand::RngCore;

impl<E: Pairing> Polymath<E> {
    pub(crate) fn compute_c_at_x1(
        y1_gamma: E::ScalarField,
        y1_alpha: E::ScalarField,
        a_at_x1: E::ScalarField,
        pi_at_x1: E::ScalarField,
    ) -> E::ScalarField {
        ((a_at_x1 + y1_gamma) * a_at_x1 - pi_at_x1) / y1_alpha
    }

    fn compute_z_of_h_over_k_of_x1(
        h_domain: GeneralEvaluationDomain<E::ScalarField>,
        k_domain: GeneralEvaluationDomain<E::ScalarField>,
        x1: E::ScalarField,
    ) -> E::ScalarField {
        h_domain.evaluate_vanishing_polynomial(x1) / k_domain.evaluate_vanishing_polynomial(x1)
    }

    pub(crate) fn compute_pi_at_x1(
        vk: &VerifyingKey<E>,
        public_inputs: &[E::ScalarField],
        x1: E::ScalarField,
        y1_gamma: E::ScalarField,
    ) -> E::ScalarField {
        let mut sum = E::ScalarField::zero();

        let mut lagrange_i_at_x1_numerator =
            (x1.pow([vk.n as u64]) - E::ScalarField::ONE) / &E::ScalarField::from(vk.n as u64);
        let mut omega_exp_i = E::ScalarField::ONE;

        let m0 = public_inputs.len();

        for i in 0..m0 * 2 {
            let lagrange_i_at_x1 = lagrange_i_at_x1_numerator / (x1 - omega_exp_i);
            let to_add = Self::z_tilde_i(public_inputs, i) * lagrange_i_at_x1;
            lagrange_i_at_x1_numerator *= vk.omega;
            omega_exp_i *= vk.omega;
            sum += to_add;
        }

        sum * y1_gamma
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
