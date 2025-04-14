use crate::utils::{sample_x1, sample_x2};
use crate::{
    data_structures::{Proof, VerifyingKey},
    Polymath,
};
use crate::{MINUS_ALPHA, MINUS_GAMMA};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{batch_inversion, PrimeField};
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::One;
use ark_std::{end_timer, ops::Neg, start_timer};
use shared_utils::transcript::IOPTranscript;
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
        let mut transcript = IOPTranscript::<E::ScalarField>::new(crate::Polymath::<E>::SNARK_NAME);
        let x1 = sample_x1::<E>(&mut transcript, vk, public_input, a, c);
        end_timer!(timer_transcript_init);
        let x2 = sample_x2::<E>(&mut transcript, x1, *a_x_1);
        end_timer!(timer_transcript_init);

        let full_public_input = [&[E::ScalarField::ONE], public_input].concat();

        let y_1 = x1.pow([vk.sigma as u64]);

        let v_h_at_x1 = vk.h_domain.evaluate_vanishing_polynomial(x1);
        let v_k_at_x1 = vk.k_domain.evaluate_vanishing_polynomial(x1);
        let mut result = [v_k_at_x1, y_1];

        let mut lagrange_coeffs =
            Self::evaluate_all_lagrange_coefficients_inverse(&vk.k_domain, x1);
        Self::merge_and_invert(&mut result, &mut lagrange_coeffs);
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
            lagrange_coeffs
                .into_iter()
                .zip(full_public_input)
                .map(|(l_i, pi_i)| l_i * pi_i)
                .sum::<E::ScalarField>()
                * y1_gamma
        };

        let c_at_x1 = ((*a_x_1 + y1_gamma) * a_x_1 - pi_at_x1 * filter_at_x1) * y1_inverse_alpha;
        let commitments_minus_evals_in_g1 = proof.a
            + msm_bigint_wnaf::<E::G1>(
                &[proof.c, vk.g],
                &[x2.into(), (-(*a_x_1 + x2 * c_at_x1)).into()],
            );

        let pairing_output = E::multi_pairing(
            [commitments_minus_evals_in_g1, *d * x1, E::G1::from(-*d)],
            [vk.z_h_prep.clone(), vk.h_prep.clone(), vk.x_h_prep.clone()],
        );
        // assert!(pairing_output.is_zero());
        end_timer!(timer_verify);
        true
    }

    fn evaluate_all_lagrange_coefficients_inverse(
        d: &GeneralEvaluationDomain<E::ScalarField>,
        tau: E::ScalarField,
    ) -> Vec<E::ScalarField> {
        let size = d.size();
        let z_h_at_tau = d.evaluate_vanishing_polynomial(tau);
        let offset = d.coset_offset();
        let group_gen = d.group_gen();
        if z_h_at_tau.is_zero() {
            let mut u = vec![E::ScalarField::zero(); size];
            let mut omega_i = offset;
            for u_i in u.iter_mut().take(size) {
                if omega_i == tau {
                    *u_i = E::ScalarField::one();
                    break;
                }
                omega_i *= &group_gen;
            }
            u
        } else {
            use ark_ff::fields::batch_inversion;

            let group_gen_inv = d.group_gen_inv();
            let v_0_inv = d.size_as_field_element() * offset.pow([size as u64 - 1]);
            let mut l_i = z_h_at_tau.inverse().unwrap() * v_0_inv;
            let mut negative_cur_elem = -offset;
            let mut lagrange_coefficients_inverse = vec![E::ScalarField::zero(); size];
            for coeff in &mut lagrange_coefficients_inverse {
                let r_i = tau + negative_cur_elem;
                *coeff = l_i * r_i;
                l_i *= &group_gen_inv;
                negative_cur_elem *= &group_gen;
            }
            lagrange_coefficients_inverse
        }
    }

    fn merge_and_invert<F: Field>(a: &mut [F], b: &mut [F]) {
        let len_a = a.len();
        let mut tmp = a.iter().chain(b.iter()).cloned().collect::<Vec<_>>();
        batch_inversion(&mut tmp);
        let (a_inv, b_inv) = tmp.split_at(len_a);
        a.copy_from_slice(a_inv);
        b.copy_from_slice(b_inv);
    }
}
