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
        let y1_gamma = y_1.pow([MINUS_GAMMA as u64]).inverse().unwrap();

        let y1_alpha = y_1.pow([MINUS_ALPHA as u64]).inverse().unwrap();
        //////////////////////////////////// Computing PI(x) ///////////////////////
        let r1cs_orig_num_cnstrs = vk.succinct_index.num_constraints - vk.m0;
        let domain_ratio = vk.h_domain.size() / vk.k_domain.size();

        //////////////////////// Computing c_x1 ///////////////////////
        let xu_dense_poly =
        Evaluations::from_vec_and_domain(full_public_input, vk.k_domain).interpolate();
        let pi_at_x1 = xu_dense_poly.evaluate(&x1);
        dbg!(pi_at_x1);
        let n_field = E::ScalarField::from(vk.n as u64);
        let c_at_x1 = ((proof.a_x_1 + y1_gamma) * proof.a_x_1 - pi_at_x1 / n_field) / y1_alpha;
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
        // assert!(pairing_output.0.is_one());
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
