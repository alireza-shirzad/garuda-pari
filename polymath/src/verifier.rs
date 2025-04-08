use crate::utils::compute_chall;
use crate::{GAMMA, MINUS_ALPHA, MINUS_GAMMA};
use crate::{
    Polymath,
    data_structures::{Proof, VerifyingKey},
};
use ark_ec::AffineRepr;
use ark_ec::{VariableBaseMSM, pairing::Pairing};
use ark_ff::PrimeField;
use ark_ff::{BigInteger, FftField, Field, Zero};
use ark_poly::{EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use ark_std::{end_timer, ops::Neg, start_timer};

impl<E: Pairing> Polymath<E> {
    pub fn verify(proof: &Proof<E>, vk: &VerifyingKey<E>, public_input: &[E::ScalarField]) -> bool
    where
        <E::G1Affine as AffineRepr>::BaseField: PrimeField,
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let timer_verify = start_timer!(|| "Verifying");
        debug_assert_eq!(public_input.len(), vk.succinct_index.num_instance - 1);
        let Proof { a_x_1, a, c, d } = proof;

        /////////////////////// Challenge Computation ///////////////////////
        let timer_transcript_init = start_timer!(|| "Computing Challenge");
        let x1 = compute_chall::<E>(&vk, public_input, &a, &c, None);
        end_timer!(timer_transcript_init);
        let x2 = compute_chall::<E>(&vk, public_input, &a, &c, Some((x1, *a_x_1)));
        end_timer!(timer_transcript_init);

        /////////////////////// Some variables ///////////////////////

        let n = vk.h_domain.size();
        let n_field = E::ScalarField::from(n as u64);
        let m0 = vk.succinct_index.num_instance;
        let m0_field = E::ScalarField::from(m0 as u64);
        let sigma = n + 3;
        let y_1 = x1.pow([sigma as u64]);
        let y1_to_gamma = y_1.pow([MINUS_GAMMA as u64]).inverse().unwrap();
        let y1_to_alpha = y_1.pow([MINUS_ALPHA as u64]).inverse().unwrap();

        /////////////////////// Computing polynomials x_A ///////////////////////

        let timer_x_poly = start_timer!(|| "Compute x_a polynomial");
        let mut px_evaluations = Vec::with_capacity(vk.succinct_index.num_instance);

        px_evaluations.push(E::ScalarField::ONE);
        px_evaluations.extend_from_slice(&public_input[..(vk.succinct_index.num_instance - 1)]);
        let pi_poly = Evaluations::from_vec_and_domain(px_evaluations, vk.k_domain).interpolate();
        let pi_of_x1 = pi_poly.evaluate(&x1);
        end_timer!(timer_x_poly);

        /////////////////////////////// C_x1 ///////////////////////

        let c_x_1 = Self::compute_c_at_x1(
            y1_to_gamma,
            y1_to_alpha,
            *a_x_1,
            pi_of_x1,
            m0_field,
            n_field,
            vk.h_domain,
            vk.k_domain,
            x1,
        );

        /////////////////////// Final Pairing///////////////////////

        let first_left = (*a) + (*c) * x2 - vk.g * ((*a_x_1) + x2 * c_x_1);
        let second_right = vk.x_h - vk.h * x1;

        let timer_pairing = start_timer!(|| "Final Pairing");
        let right = E::multi_pairing(
            [first_left, (*d).into_group()],
            [vk.z_h, second_right.into()],
        );
        assert!(right.is_zero());
        end_timer!(timer_pairing);
        end_timer!(timer_verify);
        true
    }
}
