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
use ark_std::{One, end_timer, ops::Neg, start_timer};

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

        let public_inputs = &[&[E::ScalarField::ONE], public_input].concat();

        let y_1 = x1.pow([vk.sigma as u64]);
        let y1_gamma = y_1.pow([MINUS_GAMMA as u64]).inverse().unwrap();
        let pi_at_x1 = Self::compute_pi_at_x1(vk, public_inputs, x1, y1_gamma);
        let y1_alpha = y_1.pow([MINUS_ALPHA as u64]).inverse().unwrap();

        // compute c_at_x1
        let c_at_x1 = Self::compute_c_at_x1(y1_gamma, y1_alpha, proof.a_x_1, pi_at_x1);
        let commitments_minus_evals_in_g1 = E::G1::msm_unchecked(
            &[proof.a, proof.c, vk.g],
            &[E::ScalarField::ONE, x2, -(proof.a_x_1 + x2 * c_at_x1)],
        );
        let x_minus_x1_in_g2 = E::G2::msm_unchecked(&[vk.x_h, vk.h], &[E::ScalarField::ONE, -x1]);

        let pairing_output = E::multi_pairing(
            [
                <E::G1 as Into<E::G1Prepared>>::into(commitments_minus_evals_in_g1),
                <E::G1 as Into<E::G1Prepared>>::into(proof.d * (-E::ScalarField::ONE)),
            ],
            [
                <E::G2 as Into<E::G2Prepared>>::into(vk.z_h.into()),
                <E::G2 as Into<E::G2Prepared>>::into(x_minus_x1_in_g2),
            ],
        );
        dbg!(pairing_output);
        assert!(pairing_output.0.is_one());
        end_timer!(timer_verify);
        true
    }
}
