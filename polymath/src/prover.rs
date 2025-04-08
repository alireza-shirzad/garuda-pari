use std::{ops::Neg, rc::Rc};

use crate::utils::compute_chall;
use crate::{ALPHA, BND_A, GAMMA, MINUS_ALPHA, MINUS_GAMMA};
use crate::{
    Polymath,
    data_structures::{Proof, ProvingKey},
};
use ark_ec::AffineRepr;
use ark_ec::{VariableBaseMSM, pairing::Pairing};
use ark_ff::{BigInteger, FftField, PrimeField, batch_inversion_and_mul};
use ark_ff::{Field, Zero};
use ark_poly::Radix2EvaluationDomain;
use ark_poly::univariate::{DenseOrSparsePolynomial, SparsePolynomial};
use ark_poly::{
    DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial,
    univariate::DensePolynomial,
};
use ark_relations::{
    gr1cs::{
        self, ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
        instance_outliner::{InstanceOutliner, outline_sr1cs},
        predicate::polynomial_constraint::SR1CS_PREDICATE_LABEL,
    },
    sr1cs::Sr1csAdapter,
};
use ark_std::rand::RngCore;
use ark_std::{UniformRand, cfg_iter_mut, end_timer, start_timer};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

impl<E: Pairing> Polymath<E> {
    pub fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut R,
    ) -> Result<Proof<E>, SynthesisError>
    where
        E::G1Affine: Neg<Output = E::G1Affine>,
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
        E::BaseField: PrimeField,
        <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField,
    {
        let timer_p = start_timer!(|| "Total Proving time");
        let cs = Self::circuit_to_prover_cs(circuit)?;
        // Check if the constraint system has only one predicate which is Squared R1CS
        #[cfg(debug_assertions)]
        {
            assert_eq!(cs.num_predicates(), 1);
            assert_eq!(
                cs.num_constraints(),
                cs.get_predicate_num_constraints(SR1CS_PREDICATE_LABEL)
                    .unwrap()
            );
            assert!(cs.is_satisfied().unwrap());
        }

        /////////////////////// Extract the constraint system  information ///////////////////////
        let timer_extract_info = start_timer!(|| "Extract constraint system information");
        let num_witness_vars = cs.num_witness_variables();
        let matrices = &cs.to_matrices().unwrap()[SR1CS_PREDICATE_LABEL];
        // Make sure the extracted information is consistent with each other
        debug_assert_eq!(pk.vk.m0, cs.instance_assignment.len());
        debug_assert_eq!(num_witness_vars, cs.witness_assignment.len());
        debug_assert_eq!(matrices.len(), 2);
        debug_assert_eq!(matrices[0].len().next_power_of_two(), pk.vk.n);
        debug_assert_eq!(matrices[1].len().next_power_of_two(), pk.vk.n);
        end_timer!(timer_extract_info);

        /////////////////////// Computing (z_u, z_w), (w_u, w_w) polynomials  ///////////////////////
        let timer_compute_za_zb_wa_wb = start_timer!(|| "Computing vectors z_U, z_U, w_W, w_W");
        let ((z_u, z_w), (w_u, w_w)) = Self::compute_zu_zw_wu_ww(
            &matrices[0],
            &matrices[1],
            &cs.instance_assignment,
            &cs.witness_assignment,
            pk.vk.n,
        )
        .unwrap();
        end_timer!(timer_compute_za_zb_wa_wb);
        //////////////////////// Interpolating polynomials ///////////////////////
        let timer_interp = start_timer!(|| "Interpolating z_u, z_w, w_u, w_w polynomials");
        let z_u_hat = Evaluations::from_vec_and_domain(z_u, pk.vk.h_domain).interpolate();
        let z_w_hat = Evaluations::from_vec_and_domain(z_w, pk.vk.h_domain).interpolate();
        let pi_poly =
            Evaluations::from_vec_and_domain(cs.instance_assignment.to_vec(), pk.vk.k_domain)
                .interpolate();
        let w_u_hat = &z_u_hat - &pi_poly;
        let w_w_hat = &z_w_hat - &pi_poly;
        debug_assert!(z_u_hat.degree() < pk.vk.n);
        end_timer!(timer_interp);

        let timer_interp = start_timer!(|| "Sparcifying z_u, z_w, w_u, w_w polynomials");
        let z_u_hat_sparse = SparsePolynomial::from(z_u_hat.clone());
        let w_u_hat_sparse = SparsePolynomial::from(w_u_hat.clone());
        let w_w_hat_sparse = SparsePolynomial::from(w_w_hat.clone());
        debug_assert!(z_u_hat_sparse.degree() < pk.vk.n);
        end_timer!(timer_interp);
        /////////////////////// Computing h(X) ///////////////////////
        let timer_h = start_timer!(|| "Computing h(X)");
        let (h, rem) = (&z_u_hat * &z_u_hat - &z_w_hat).divide_by_vanishing_poly(pk.vk.h_domain);
        debug_assert!(rem.is_zero());
        end_timer!(timer_h);
        /////////////////////// Computing ra(X) of degree bnd_a=1 ///////////////////////
        let timer_ra = start_timer!(|| "Computing ra(X) of degree bnd_a=1");
        let ra_sparse_poly = SparsePolynomial::from_coefficients_vec(vec![
            (0, E::ScalarField::rand(rng)),
            (1, E::ScalarField::rand(rng)),
        ]);

        let ra_dense_poly = DensePolynomial::from(ra_sparse_poly.clone());
        debug_assert!(ra_dense_poly.degree() <= BND_A);
        debug_assert!(ra_sparse_poly.degree() <= BND_A);
        end_timer!(timer_ra);
        /////////////////////// Computing A(X) and [a]_1 ///////////////////////
        let timer_a = start_timer!(|| "Computing A(X) and [a]_1");
        let u_at_x_g1: E::G1Affine = Self::msm(&z_u_hat.coeffs, &pk.x_to_j_g1_vec).into();
        let ra_of_x_y_to_alpha_g1: E::G1Affine =
            Self::msm(&ra_dense_poly.coeffs, &pk.x_to_i_y_to_alpha_g1_vec).into();
        let a: <E as Pairing>::G1Affine = (u_at_x_g1 + ra_of_x_y_to_alpha_g1).into();

        end_timer!(timer_a);

        ////////////////////// Computing R(X) and [R(X)]_1 ///////////////////////
        let timer_r = start_timer!(|| "Computing R(X) and [R(X)]_1");
        let ra_u_poly = &ra_dense_poly + &z_u_hat;
        let ra_u_g1: E::G1Affine = Self::msm(&ra_u_poly.coeffs, &pk.x_to_j_g1_vec).into();

        let ra2_y_poly = &ra_dense_poly * &ra_dense_poly;
        let r_a2_y_to_alpha_g1: E::G1Affine =
            Self::msm(&ra2_y_poly.coeffs, &pk.x_to_i_y_to_alpha_g1_vec).into();

        let ra_y_to_gamma_g1: E::G1Affine =
            Self::msm(&ra_dense_poly.coeffs, &pk.x_to_i_y_to_gamma_g1_vec).into();

        let r_x_g1 = ra_u_g1 + ra_u_g1 + r_a2_y_to_alpha_g1 + ra_y_to_gamma_g1;

        end_timer!(timer_r);
        /////////////////////// Computing C(X) and [c]_1 ///////////////////////
        let timer_c = start_timer!(|| "Computing C(X) and [C(X)]_1");
        let zh_poly = pk.vk.h_domain.vanishing_polynomial();

        let u_w_g1: E::G1Affine = Self::msm(&cs.witness_assignment, &pk.u_w_g1_vec).into();

        let zh_poly_dense = DensePolynomial::from(zh_poly.clone());
        let h_zh_poly_sparse = SparsePolynomial::from(&h * &zh_poly_dense);

        let h_zh_x_over_y_to_alpha_g1: E::G1Affine =
            Self::msm(&h.coeffs, &pk.x_zh_over_y_alpha_g1_vec).into();

        let c: <E as Pairing>::G1Affine = (u_w_g1 + h_zh_x_over_y_to_alpha_g1 + r_x_g1).into();
        end_timer!(timer_c);
        /////////////////////// initilizing the transcript ///////////////////////
        let timer_x1 = start_timer!(|| "Computing Challenge x_1");
        let x_1 = compute_chall::<E>(&pk.vk, &cs.instance_assignment[1..], &a, &c, None);
        end_timer!(timer_x1);

        ///////////////////// Computing y1 , Ax1 ///////////////////////

        let timer_ax1 = start_timer!(|| "Computint y1 and Ax1");
        let y1 = x_1.pow([pk.vk.sigma as u64]);
        let y1_to_gamma = y1.pow([MINUS_GAMMA as u64]).inverse().unwrap();
        let y1_to_alpha = y1.pow([MINUS_ALPHA as u64]).inverse().unwrap();
        let a_x_1 = z_u_hat.evaluate(&x_1) + ra_u_poly.evaluate(&x_1) * y1_to_alpha;
        end_timer!(timer_ax1);
        //////////////////////// Computing x2 ///////////////////////
        let timer_x2 = start_timer!(|| "Computing x2");
        let x_2 = compute_chall::<E>(
            &pk.vk,
            &cs.instance_assignment[1..],
            &a,
            &c,
            Some((x_1, a_x_1)),
        );
        end_timer!(timer_x2);

        ///////////////////////////// Computing PI(X) ///////////////////////
        let c_at_x1 = Self::compute_c_at_x1(
            y1_to_gamma,
            y1_to_alpha,
            a_x_1,
            &cs.instance_assignment,
            x_1,
            &pk.vk,
        );
        ///////////////////// Computing D(X) ///////////////////////

        let a_over_y_to_gamma_poly =
            Self::mul_by_x_power(&z_u_hat_sparse, pk.vk.sigma * MINUS_GAMMA)
                + Self::mul_by_x_power(&ra_sparse_poly, pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA));
        let r_poly_term_one = &Self::mul_by_x_power(&z_u_hat_sparse, pk.vk.sigma * MINUS_GAMMA)
            .mul(&ra_sparse_poly)
            * E::ScalarField::from(2_i32);
        let r_poly_term_two = Self::mul_by_x_power(
            &ra_sparse_poly.mul(&ra_sparse_poly),
            pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA),
        );
        let r_over_y_to_gamma_poly = r_poly_term_one + r_poly_term_two + ra_sparse_poly;
        let c_over_y_to_gamma_poly: SparsePolynomial<E::ScalarField> =
            Self::mul_by_x_power(&w_u_hat_sparse, pk.vk.sigma * MINUS_ALPHA)
                + Self::mul_by_x_power(&w_w_hat_sparse, pk.vk.sigma * (MINUS_GAMMA + MINUS_ALPHA))
                + Self::mul_by_x_power(
                    &h_zh_poly_sparse,
                    pk.vk.sigma * (MINUS_GAMMA + MINUS_ALPHA),
                )
                + r_over_y_to_gamma_poly;

        let d_right_coeff_poly =
            SparsePolynomial::from_coefficients_vec(vec![(0, a_x_1 + x_2 * c_at_x1)]);
        let d_over_y_to_gamma_nom_poly: DenseOrSparsePolynomial<E::ScalarField> =
            DenseOrSparsePolynomial::from(
                (a_over_y_to_gamma_poly + &c_over_y_to_gamma_poly * x_2)
                    + (-Self::mul_by_x_power(&d_right_coeff_poly, pk.vk.sigma * MINUS_GAMMA)),
            );
        let d_denom_poly =
            DenseOrSparsePolynomial::from(DensePolynomial::from_coefficients_slice(&[
                -x_1,
                E::ScalarField::ONE,
            ]));

        let (d_over_y_to_gamma_poly, d_rem_poly) = d_over_y_to_gamma_nom_poly
            .divide_with_q_and_r(&d_denom_poly)
            .unwrap();
        // Compute the group element d
        assert!(
            d_over_y_to_gamma_poly.degree()
                <= 2 * (pk.vk.n - 1) + (pk.vk.sigma * (MINUS_ALPHA + MINUS_GAMMA))
        );
        debug_assert!(d_rem_poly.is_zero());

        let d = Self::msm(&d_over_y_to_gamma_poly.coeffs, &pk.x_z_g1_vec);

        /////////////////////////////// Assembling the proof ///////////////////////
        let output = Ok(Proof {
            a,
            c,
            d: d.into(),
            a_x_1,
        });

        end_timer!(timer_p);
        output
    }

    fn circuit_to_prover_cs<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
    ) -> Result<ConstraintSystem<E::ScalarField>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
        // Start up the constraint System and synthesize the circuit
        let timer_cs_startup = start_timer!(|| "Prover constraint System Startup");
        let cs: gr1cs::ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        let sr1cs_cs =
            Sr1csAdapter::r1cs_to_sr1cs_with_assgnmnt(&mut cs.into_inner().unwrap()).unwrap();
        sr1cs_cs.set_instance_outliner(InstanceOutliner {
            pred_label: SR1CS_PREDICATE_LABEL.to_string(),
            func: Rc::new(outline_sr1cs),
        });
        let timer_synthesize_circuit = start_timer!(|| "Synthesize Circuit");
        end_timer!(timer_synthesize_circuit);

        let timer_inlining = start_timer!(|| "Inlining constraints");
        sr1cs_cs.finalize();
        end_timer!(timer_inlining);
        end_timer!(timer_cs_startup);
        Ok(sr1cs_cs.into_inner().unwrap())
    }

    #[allow(clippy::type_complexity)]
    fn compute_zu_zw_wu_ww(
        a_mat: &Matrix<E::ScalarField>,
        b_mat: &Matrix<E::ScalarField>,
        instance_assignment: &[E::ScalarField],
        witness_assignment: &[E::ScalarField],
        num_constraints: usize,
    ) -> Result<
        (
            (Vec<E::ScalarField>, Vec<E::ScalarField>),
            (Vec<E::ScalarField>, Vec<E::ScalarField>),
        ),
        SynthesisError,
    > {
        let mut assignment: Vec<E::ScalarField> = instance_assignment.to_vec();
        let mut punctured_assignment: Vec<E::ScalarField> =
            vec![E::ScalarField::zero(); assignment.len()];
        assignment.extend_from_slice(witness_assignment);
        punctured_assignment.extend_from_slice(witness_assignment);

        let mut z_a = vec![E::ScalarField::zero(); num_constraints];
        let mut z_b = vec![E::ScalarField::zero(); num_constraints];

        cfg_iter_mut!(z_a[..num_constraints])
            .zip(&mut z_b[..num_constraints])
            .zip(a_mat)
            .zip(b_mat)
            .for_each(|(((mut a, mut b), at_i), bt_i)| {
                *a = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(at_i, &assignment);
                *b = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(bt_i, &assignment);
            });

        let mut w_a = vec![E::ScalarField::zero(); num_constraints];
        let mut w_b = vec![E::ScalarField::zero(); num_constraints];

        cfg_iter_mut!(w_a[..num_constraints])
            .zip(&mut w_b[..num_constraints])
            .zip(a_mat)
            .zip(b_mat)
            .for_each(|(((mut a, mut b), at_i), bt_i)| {
                *a = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    at_i,
                    &punctured_assignment,
                );
                *b = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    bt_i,
                    &punctured_assignment,
                );
            });

        Ok(((z_a, z_b), (w_a, w_b)))
    }
    fn mul_by_x_power(
        poly: &SparsePolynomial<E::ScalarField>,
        power_of_x: usize,
    ) -> SparsePolynomial<E::ScalarField> {
        SparsePolynomial::from_coefficients_vec(
            poly.iter().map(|(i, c)| (i + power_of_x, *c)).collect(),
        )
    }

    #[inline]
    fn msm(scalars: &Vec<E::ScalarField>, g1_elems: &Vec<E::G1Affine>) -> E::G1 {
        debug_assert!(scalars.len() <= g1_elems.len());
        E::G1::msm_unchecked(g1_elems.as_slice(), scalars.as_slice())
    }
}
