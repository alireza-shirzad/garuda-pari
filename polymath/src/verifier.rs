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
use ark_relations::gr1cs::{Matrix, SynthesisError};
use ark_relations::sr1cs::Sr1csAdapter;
use ark_std::cfg_iter_mut;
use ark_std::{One, end_timer, ops::Neg, start_timer};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use shared_utils::msm_bigint_wnaf;
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

        let full_public_input = [&[E::ScalarField::ONE], public_input].concat();

        let y_1 = x1.pow([vk.sigma as u64]);
        let y_1_inverse = y_1.inverse().unwrap();
        let y1_gamma = y_1_inverse.pow([MINUS_GAMMA as u64]).inverse().unwrap();

        let y1_inverse_alpha = y_1.pow([MINUS_ALPHA as u64]).inverse().unwrap();

        //////////////////////// Computing c_x1 ///////////////////////
        let pi_at_x1 = {
            let lagrange_coeffs = vk.k_domain.evaluate_all_lagrange_coefficients(x1);
            lagrange_coeffs
                .into_iter()
                .zip(full_public_input)
                .map(|(l_i, pi_i)| l_i * pi_i)
                .sum::<E::ScalarField>()
                * y1_gamma
        };
        let filter_at_x1 = vk.h_domain.evaluate_filter_polynomial(&vk.k_domain, x1);
        
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

    #[allow(clippy::type_complexity)]
    fn compute_xu_xw(
        n: usize,
        u_mat: &Matrix<E::ScalarField>,
        w_mat: &Matrix<E::ScalarField>,
        instance_assignment: &[E::ScalarField],
        num_constraints: usize,
    ) -> Result<(Vec<E::ScalarField>, Vec<E::ScalarField>), SynthesisError> {
        let mut x_punctured_assignment: Vec<E::ScalarField> = instance_assignment.to_vec();
        x_punctured_assignment.extend_from_slice(&vec![E::ScalarField::zero(); n]);

        let mut x_u = vec![E::ScalarField::zero(); n];
        let mut x_w = vec![E::ScalarField::zero(); n];

        cfg_iter_mut!(x_u[..num_constraints])
            .zip(&mut x_w[..num_constraints])
            .zip(u_mat)
            .zip(w_mat)
            .for_each(|(((mut u, mut w), ut_i), wt_i)| {
                *u = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    ut_i,
                    &x_punctured_assignment,
                );
                *w = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    wt_i,
                    &x_punctured_assignment,
                );
            });

        Ok((x_u, x_w))
    }
}
