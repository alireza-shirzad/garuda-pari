use crate::utils::compute_chall;
use crate::{
    data_structures::{Proof, VerifyingKey},
    Pari,
};
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{end_timer, rand::RngCore, start_timer};
use shared_utils::transcript::IOPTranscript;
impl<E, R> Pari<E, R>
where
    E: Pairing,
    R: RngCore,
{
    pub fn verify(proof: &Proof<E>, vk: &VerifyingKey<E>, public_input: &[E::ScalarField]) -> bool
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let timer_verify =
            start_timer!(|| format!("Verification (|x|={})", vk.succinct_index.instance_len));
        debug_assert_eq!(public_input.len(), vk.succinct_index.instance_len - 1);
        #[cfg(feature = "sol")]
        {
            println!("public_input_0: {:?}", E::ScalarField::ONE);
            public_input.iter().enumerate().for_each(|(i, x)| {
                println!("public_input_{}: {:?}", i + 1, x);
            });
        }
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
        let lagrange_ceoffs = Self::eval_last_lagrange_coeffs::<E::ScalarField>(
            &domain,
            challenge,
            r1cs_orig_num_cnstrs,
            vk.succinct_index.instance_len,
        );
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
        use ark_ff::PrimeField;
        #[cfg(feature = "sol")]
        {
            println!("COSET_SIZE: {:?}", domain.size());
            println!("COSET_OFFSET: {:?}", domain.coset_offset());
            println!(
                "MINUS_COSET_OFFSET_TO_COSET_SIZE: {:?}",
                -(domain.coset_offset().pow([domain.size() as u64]))
            );
            println!(
                "COSET_OFFSET_TO_COSET_SIZE_INVERSE: {:?}",
                E::ScalarField::ONE / domain.evaluate_vanishing_polynomial(challenge)
            );
        }
        end_timer!(timer_q);

        /////////////////////// Final Pairing///////////////////////

        let timer_pairing = start_timer!(|| "Final Pairing");

        let right_first_right = vk.tau_h;
        let right_second_left = vk.alpha_g * v_a + vk.beta_g * v_b + vk.g * v_q - *u_g * challenge;
        dbg!(t_g.clone());
        dbg!(vk.delta_two_h.clone().into());
        dbg!(u_g.clone());
        dbg!(right_first_right.clone().into());
        dbg!(right_second_left.clone().into());
        dbg!(vk.h.clone().into());
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

    /// The lagrange polynomial evaluations are L_0(tau), L_1(tau), ..., L_{i-1}(tau), L_{i}(tau), L_{i+1}(tau),..., Ln(tau)
    /// We want to fetch L_{i}(tau), L_{i+1}(tau),..., Ln(tau) where i=start_ind and n=size-1
    /// Note that the start_ind is inclusive and the size is exclusive
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
                #[cfg(feature = "sol")]
                {
                    println!("NEG_H_Gi_{}: {:?}", i, negative_cur_elem);
                    println!("NOM_{}: {:?}", i, start_gen*(l_i.inverse().unwrap()));
                }
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
