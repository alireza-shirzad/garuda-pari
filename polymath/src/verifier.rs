use crate::utils::compute_chall;
use crate::{MINUS_ALPHA, MINUS_GAMMA};
use crate::{
    Polymath,
    data_structures::{Proof, VerifyingKey},
};
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_ff::{Field, Zero};
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, ops::Neg, start_timer};
use shared_utils::{batch_inversion_and_mul, msm_bigint_wnaf};

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
        // TODO: avoid re-appending to transcript.
        let x2 = compute_chall::<E>(&vk, public_input, &a, &c, Some((x1, *a_x_1)));
        end_timer!(timer_transcript_init);

        let full_public_input = [&[E::ScalarField::ONE], public_input].concat();

        let y_1 = x1.pow([vk.sigma as u64]);
        
        let v_h_at_x1 = vk.h_domain.evaluate_vanishing_polynomial(x1);
        let v_k_at_x1 = vk.k_domain.evaluate_vanishing_polynomial(x1);
        let mut result = [v_k_at_x1, y_1];
        batch_inversion_and_mul(&mut result, &E::ScalarField::ONE);
        let filter_at_x1 = {
            if v_k_at_x1.is_zero() {
                E::ScalarField::ONE
            } else {
                v_h_at_x1 * result[0] * vk.k_domain_size_by_h_domain_size
            }
        };

        let y_1_inverse = result[1];
        
        let y1_gamma = y_1_inverse.pow([MINUS_GAMMA as u64]).inverse().unwrap();
        let y1_inverse_alpha = y_1.pow([MINUS_ALPHA as u64]).inverse().unwrap();

        //////////////////////// Computing c_x1 ///////////////////////
        let pi_at_x1 = {
            // TODO: combine inversion in here with inversion above.
            let lagrange_coeffs = vk.k_domain.evaluate_all_lagrange_coefficients(x1);
            lagrange_coeffs
                .into_iter()
                .zip(full_public_input)
                .map(|(l_i, pi_i)| l_i * pi_i)
                .sum::<E::ScalarField>()
                * y1_gamma
        };
        
        let c_at_x1 = ((*a_x_1 + y1_gamma) * a_x_1 - pi_at_x1 * filter_at_x1) * y1_inverse_alpha;
        let commitments_minus_evals_in_g1 = proof.a + msm_bigint_wnaf::<E::G1>(
            &[proof.c, vk.g],
            &[x2.into(), (-(*a_x_1 + x2 * c_at_x1)).into()],
        );

        let pairing_output = E::multi_pairing(
            [
                commitments_minus_evals_in_g1,
                *d * x1,
                E::G1::from(-*d),
            ],
            [
                vk.z_h_prep.clone(),
                vk.h_prep.clone(),
                vk.x_h_prep.clone(),
            ],
        );
        assert!(pairing_output.is_zero());
        end_timer!(timer_verify);
        true
    }
}
