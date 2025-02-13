use crate::utils::compute_chall;
use crate::{
    data_structures::{Proof, VerifyingKey},
    Pari,
};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_ff::{FftField, Field, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{end_timer, rand::RngCore, start_timer};
use shared_utils::transcript::IOPTranscript;
impl<E, R> Pari<E, R>
where
    E: Pairing,
    R: RngCore,
{
    pub fn verify(
        proof: &Proof<E>,
        vk: &VerifyingKey<E>,
        public_input: &[E::ScalarField],
    ) -> bool
    where
        E: Pairing,
        E::ScalarField: Field,
        E::BaseField: PrimeField,
        <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField,
    {
        let timer_verify =
            start_timer!(|| format!("Verification (|x|={})", vk.succinct_index.instance_len));
        debug_assert_eq!(public_input.len(), vk.succinct_index.instance_len - 1);
        let Proof { t_g, u_g, v_a, v_b } = proof;

        /////////////////////// Challenge Computation ///////////////////////
        let timer_transcript_init = start_timer!(|| "Computing Challenge");
        let challenge = compute_chall::<E>(vk, public_input, t_g);
        end_timer!(timer_transcript_init);
        /////////////////////// Computing polynomials x_A ///////////////////////

        let timer_x_poly = start_timer!(|| "Compute x_a polynomial");
        let domain: GeneralEvaluationDomain<E::ScalarField> =
            GeneralEvaluationDomain::new(vk.succinct_index.num_constraints).unwrap();
        let mut px_evaluations: Vec<E::ScalarField> =
            Vec::with_capacity(vk.succinct_index.instance_len);
        let r1cs_orig_num_cnstrs =
            vk.succinct_index.num_constraints - vk.succinct_index.instance_len;
        px_evaluations.push(E::ScalarField::ONE);
        for i in 1..vk.succinct_index.instance_len {
            px_evaluations.push(public_input[i - 1]);
        }
        let mut lagrange_ceoffs = Self::eval_last_lagrange_coeffs::<E::ScalarField>(
            &domain,
            challenge,
            r1cs_orig_num_cnstrs,
            vk.succinct_index.instance_len,
        );
        #[cfg(feature = "sol")]
        {
            use crate::solidity::Solidifier;
            let mut solidifier = Solidifier::<E>::new();
            solidifier.set_vk(&vk);
            solidifier.set_proof(&proof);
            solidifier.set_input(public_input);
            let (lagrange_ceoffs, neg_h_i, nom_i) =
                Self::eval_last_lagrange_coeffs_traced::<E::ScalarField>(
                    &domain,
                    challenge,
                    r1cs_orig_num_cnstrs,
                    vk.succinct_index.instance_len,
                );
            solidifier.coset_size = Some(domain.size());
            solidifier.coset_offset = Some(domain.coset_offset());
            solidifier.neg_h_gi = Some(neg_h_i);
            solidifier.nom_i = Some(nom_i);
            solidifier.minus_coset_offset_to_coset_size =
                Some(-(domain.coset_offset().pow([domain.size() as u64])));
            solidifier.coset_offset_to_coset_size_inverse =
                Some(E::ScalarField::ONE / domain.evaluate_vanishing_polynomial(challenge));
            solidifier.solidify();
        }
        let x_a = lagrange_ceoffs
            .iter()
            .zip(px_evaluations.iter())
            .fold(E::ScalarField::zero(), |acc, (x, d)| acc + (*x) * (*d));
        let z_a = x_a + v_a;
        end_timer!(timer_x_poly);

        /////////////////////// Computing the quotient evaluation///////////////////////


        let timer_q = start_timer!(|| "Computing the quotient evaluation");

        let v_q: E::ScalarField =
            (z_a * z_a - v_b) / domain.evaluate_vanishing_polynomial(challenge);
        end_timer!(timer_q);
        /////////////////////// Final Pairing///////////////////////

        let timer_pairing = start_timer!(|| "Final Pairing");

        let right_first_right = vk.tau_h;
        let right_second_left = vk.alpha_g * v_a + vk.beta_g * v_b + vk.g * v_q - *u_g * challenge;

        let right = E::multi_pairing(
            [t_g, u_g, &right_second_left.into()],
            [
                vk.delta_two_h_prep.clone(),
                right_first_right.into().into(),
                vk.h_prep.clone(),
            ],
        );
        assert!(right.is_zero());
        end_timer!(timer_pairing);
        end_timer!(timer_verify);
        true
    }

    #[cfg(feature = "sol")]
    fn eval_last_lagrange_coeffs_traced<F: FftField>(
        domain: &GeneralEvaluationDomain<F>,
        tau: F,
        start_ind: usize,
        count: usize,
    ) -> (Vec<F>, Vec<F>, Vec<F>)
    where
        E::ScalarField: Field,
        E::BaseField: PrimeField,
        E::BaseField: FftField,
    {
        use ark_ff::fields::batch_inversion;
        let size: usize = domain.size();
        let z_h_at_tau: F = domain.evaluate_vanishing_polynomial(tau);
        let mut neg_hi = Vec::new();
        let mut nom_i = Vec::new();
        let offset: F = domain.coset_offset();
        let group_gen: F = domain.group_gen();
        let starting_g: F = offset * group_gen.pow([start_ind as u64]);
        let group_gen_inv = domain.group_gen_inv();
        let v_0_inv = domain.size_as_field_element() * offset.pow([size as u64 - 1]);
        let start_gen = group_gen.pow([start_ind as u64]);
        let mut l_i = z_h_at_tau.inverse().unwrap() * v_0_inv;
        let mut negative_cur_elem = (-offset) * (start_gen);
        let mut lagrange_coefficients_inverse = vec![F::zero(); count];
        for (i, coeff) in &mut lagrange_coefficients_inverse.iter_mut().enumerate() {
            neg_hi.push(negative_cur_elem);
            let nom = start_gen * (l_i.inverse().unwrap());
            nom_i.push(nom);
            let r_i = tau + negative_cur_elem;
            *coeff = l_i * r_i;
            l_i *= &group_gen_inv;
            negative_cur_elem *= &group_gen;
        }
        batch_inversion(lagrange_coefficients_inverse.as_mut_slice());
        for x in lagrange_coefficients_inverse.iter_mut() {
            *x *= &start_gen;
        }
        (lagrange_coefficients_inverse, neg_hi, nom_i)
    }

    fn eval_last_lagrange_coeffs<F: FftField>(
        domain: &GeneralEvaluationDomain<F>,
        tau: F,
        start_ind: usize,
        count: usize,
    ) -> Vec<F> {
        let size: usize = domain.size();

        let z_h_at_tau: F = domain.evaluate_vanishing_polynomial(tau);
        let offset: F = domain.coset_offset();
        let group_gen: F = domain.group_gen();
        let starting_g: F = offset * group_gen.pow([start_ind as u64]);
        if z_h_at_tau.is_zero() {
            let mut u = vec![F::zero(); count];
            let mut omega_i = starting_g;
            for u_i in u.iter_mut().take(count) {
                if omega_i == tau {
                    *u_i = F::one();
                    break;
                }
                omega_i *= &group_gen;
            }
            u
        } else {
            use ark_ff::fields::batch_inversion;
            let group_gen_inv = domain.group_gen_inv();
            let v_0_inv = domain.size_as_field_element() * offset.pow([size as u64 - 1]);
            let start_gen = group_gen.pow([start_ind as u64]);
            let mut l_i = z_h_at_tau.inverse().unwrap() * v_0_inv;
            let mut negative_cur_elem = (-offset) * (start_gen);
            let mut lagrange_coefficients_inverse = vec![F::zero(); count];
            for (i, coeff) in &mut lagrange_coefficients_inverse.iter_mut().enumerate() {
                let r_i = tau + negative_cur_elem;
                *coeff = l_i * r_i;
                l_i *= &group_gen_inv;
                negative_cur_elem *= &group_gen;
            }
            batch_inversion(lagrange_coefficients_inverse.as_mut_slice());
            for x in lagrange_coefficients_inverse.iter_mut() {
                *x *= &start_gen;
            }
            lagrange_coefficients_inverse
        }
    }
}
