use std::{ops::Neg, rc::Rc};

use crate::utils::{compute_chall, eval_last_lagrange_coeffs};
use crate::{ALPHA, GAMMA, MINUS_ALPHA, MINUS_GAMMA};
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
        let num_constraints = cs.num_constraints();
        let num_instance_vars = cs.num_instance_variables();
        let num_witness_vars = cs.num_witness_variables();
        let num_vars = cs.num_variables();
        let instance_assignment = &cs.instance_assignment;
        let witness_assignment = &cs.witness_assignment;
        let matrices = &cs.to_matrices().unwrap()[SR1CS_PREDICATE_LABEL];
        // Make sure the extracted information is consistent with each other
        debug_assert_eq!(num_instance_vars, instance_assignment.len());
        debug_assert_eq!(num_witness_vars, witness_assignment.len());
        debug_assert_eq!(matrices.len(), 2);
        debug_assert_eq!(matrices[0].len(), num_constraints);
        debug_assert_eq!(matrices[1].len(), num_constraints);
        end_timer!(timer_extract_info);
        /////////////////////////// Computing the evaluation domain ///////////////////////

        let timer_eval_domain = start_timer!(|| "Computing the evaluation domain");
        let domain = GeneralEvaluationDomain::<E::ScalarField>::new(num_constraints).unwrap();
        debug_assert_eq!(domain.size(), num_constraints);
        end_timer!(timer_eval_domain);

        ////////////////////////// Adapt the notation of the paper ///////////////////////
        let n = domain.size();
        let m0 = num_instance_vars;
        let sigma = n + 3;
        let r1cs_orig_num_cnstrs = num_constraints - num_instance_vars;
        /////////////////////// Computing polynomials  ///////////////////////
        let timer_compute_za_zb_wa_wb = start_timer!(|| "Computing vectors z_U, z_U, w_W, w_W");
        let ((z_u, z_w), (w_u, w_w)) = Self::compute_zu_zw_wu_ww(
            &matrices[0],
            &matrices[1],
            instance_assignment,
            witness_assignment,
            num_constraints,
        )
        .unwrap();
        end_timer!(timer_compute_za_zb_wa_wb);
        let y_poly = SparsePolynomial::<E::ScalarField>::from_coefficients_slice(&[(
            sigma,
            E::ScalarField::ONE,
        )]);
        let y_dense_poly = DensePolynomial::from(y_poly.clone());
        let y_to_gamma_minus_alpha_poly = Self::mul_by_x_power(&y_poly, 2);
        //////////////////////// Interpolating polynomials ///////////////////////
        let timer_interp = start_timer!(|| "Interpolating z_u, z_w, w_u, w_w polynoials");
        let z_u_hat = Evaluations::from_vec_and_domain(z_u, domain).interpolate();
        let z_w_hat = Evaluations::from_vec_and_domain(z_w, domain).interpolate();
        let w_u_hat = Evaluations::from_vec_and_domain(w_u, domain).interpolate();
        let w_w_hat = Evaluations::from_vec_and_domain(w_w, domain).interpolate();
        end_timer!(timer_interp);

        /////////////////////// Computing ra(X) of degree bnd_a=1 ///////////////////////
        let timer_ra = start_timer!(|| "Computing ra(X) of degree bnd_a=1");
        let ra_poly = DensePolynomial::from_coefficients_vec(vec![
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
        ]);
        let ra_sparse_poly = SparsePolynomial::from(ra_poly.clone());
        end_timer!(timer_ra);
        /////////////////////// Computing A(X) and [a]_1 ///////////////////////
        let timer_a = start_timer!(|| "Computing A(X) and [a]_1");
        let a_poly =
            &z_u_hat + &Self::mul_by_x_power(&ra_sparse_poly, (sigma * (MINUS_ALPHA)) as usize);

        let u_of_x_g1: E::G1Affine =
            <E::G1 as VariableBaseMSM>::msm_unchecked(&pk.x_to_j_g1_vec, &z_u_hat.coeffs).into();
        let ra_of_x_y_to_alpha_g1: E::G1Affine = <E::G1 as VariableBaseMSM>::msm_unchecked(
            &pk.x_to_i_y_to_alpha_g1_vec,
            &z_u_hat.coeffs,
        )
        .into();
        let a: <E as Pairing>::G1Affine = (u_of_x_g1 + ra_of_x_y_to_alpha_g1).into();

        end_timer!(timer_a);
        /////////////////////// Computing h(X) ///////////////////////
        let timer_h = start_timer!(|| "Computing h(X)");
        let (h, _) = (&z_u_hat * &z_u_hat - &z_w_hat).divide_by_vanishing_poly(domain);
        end_timer!(timer_h);
        ////////////////////// Computing R(X) and [R(X)]_1 ///////////////////////
        let timer_r = start_timer!(|| "Computing R(X) and [R(X)]_1");
        let ra_u_poly = &ra_poly + &z_u_hat;
        let ra_u_g1: E::G1Affine =
            <E::G1 as VariableBaseMSM>::msm_unchecked(&pk.x_to_j_g1_vec, &ra_u_poly.coeffs).into();

        let ra2_y_poly = &ra_poly * &ra_poly;
        let r_a2_y_to_alpha_g1: E::G1Affine = <E::G1 as VariableBaseMSM>::msm_unchecked(
            &pk.x_to_i_y_to_alpha_g1_vec,
            &ra2_y_poly.coeffs,
        )
        .into();

        let ra_y_to_gamma_g1: E::G1Affine = <E::G1 as VariableBaseMSM>::msm_unchecked(
            &pk.x_to_i_y_to_gamma_g1_vec,
            &ra_poly.coeffs,
        )
        .into();

        let r_x_g1 = ra_u_g1 + ra_u_g1 + r_a2_y_to_alpha_g1 + ra_y_to_gamma_g1;

        let r_poly = &ra_u_poly * E::ScalarField::from(2_i32)
            + ra2_y_poly / (&y_dense_poly * &y_dense_poly * &y_dense_poly)
            + ra_poly
                / (&y_dense_poly * &y_dense_poly * &y_dense_poly * &y_dense_poly * &y_dense_poly);
        end_timer!(timer_r);
        /////////////////////// Computing C(X) and [c]_1 ///////////////////////
        let timer_c = start_timer!(|| "Computing C(X) and [C(X)]_1");
        let zh_poly = domain.vanishing_polynomial();
        let zh_poly_dense = DensePolynomial::from(zh_poly.clone());

        let c_poly = w_u_hat / (&y_dense_poly * &y_dense_poly)
            + w_w_hat * (&y_dense_poly * &y_dense_poly * &y_dense_poly)
            + (&z_u_hat * &z_u_hat - &z_w_hat) * zh_poly_dense
            + &r_poly;

        let u_w_g1: E::G1Affine =
            <E::G1 as VariableBaseMSM>::msm_unchecked(&pk.u_w_g1_vec, &witness_assignment).into();

        let zh_poly_dense = DensePolynomial::from(zh_poly.clone());
        let h_zh_poly = &h * &zh_poly_dense;

        let h_zh_x_over_y_to_alpha_g1: E::G1Affine =
            <E::G1 as VariableBaseMSM>::msm_unchecked(&pk.x_zh_over_y_alpha_g1_vec, &h.coeffs)
                .into();

        let c: <E as Pairing>::G1Affine = (u_w_g1 + h_zh_x_over_y_to_alpha_g1 + r_x_g1).into();
        end_timer!(timer_c);
        /////////////////////// initilizing the transcript ///////////////////////
        let timer_x1 = start_timer!(|| "Computing Challenge x_1");
        let x_1 = compute_chall::<E>(&pk.vk, &instance_assignment[1..].to_vec(), &a, &c, None);
        end_timer!(timer_x1);

        ///////////////////// Computing y1 , Ax1 ///////////////////////

        let timer_ax1 = start_timer!(|| "Computint y1 and Ax1");
        let y1 = x_1.pow(&[sigma as u64]);
        let a_x_1 = z_u_hat.evaluate(&x_1) + ra_u_poly.evaluate(&x_1) * y1.pow(&[ALPHA as u64]);
        end_timer!(timer_ax1);
        //////////////////////// Computing x2 ///////////////////////
        let timer_x2 = start_timer!(|| "Computing x2");
        let x_2 = compute_chall::<E>(
            &pk.vk,
            &instance_assignment[1..].to_vec(),
            &a,
            &c,
            Some((x_1, a_x_1)),
        );
        end_timer!(timer_x2);

        ///////////////////////////// Computing PI(X) ///////////////////////
        let lag_coeffs_time = start_timer!(|| "Computing last lagrange coefficients");
        let (lagrange_coeffs, vanishing_poly_at_chall_inv) =
            eval_last_lagrange_coeffs::<E::ScalarField>(
                &pk.vk.domain,
                x_1,
                r1cs_orig_num_cnstrs,
                num_instance_vars,
            );
        end_timer!(lag_coeffs_time);

        let mut px_evaluations = instance_assignment.to_vec();
        let y1_to_gamma = y1.pow(&[GAMMA as u64]);
        let pi_of_x1 = lagrange_coeffs
            .into_iter()
            .zip(px_evaluations)
            .fold(E::ScalarField::zero(), |acc, (x, d)| {
                acc + x * d * y1_to_gamma
            });

        /////////////////////////////////// Computing D(X) and [D(x)z]_1 ///////////////////////
        //TODO: Check this
        let z_h_over_k_of_x1 =
            zh_poly.evaluate(&x_1) / pk.vk.domain.evaluate_vanishing_polynomial(x_1);
        let y1_to_alpha = y1.pow(&[ALPHA as u64]);
        let y1_to_minus_alpha = y1_to_alpha.inverse().unwrap();
        let m0_field = E::ScalarField::from(m0 as i32);
        let n_field = E::ScalarField::from(n as i32);
        let n_field_inv = n_field.inverse().unwrap();
        let c_x_1 = ((a_x_1 + y1_to_gamma) * a_x_1
            - pi_of_x1 * m0_field * n_field_inv * z_h_over_k_of_x1)
            * y1_to_minus_alpha;

        ///////////////////// Computing D(X) ///////////////////////

        let d_nom_poly: DenseOrSparsePolynomial<E::ScalarField> =
            DenseOrSparsePolynomial::from(a_poly);
        let d_denom_poly =
            DenseOrSparsePolynomial::from(DensePolynomial::from_coefficients_slice(&[
                -x_1,
                E::ScalarField::ONE,
            ]));

        let (d_poly, d_rem_poly) = DenseOrSparsePolynomial::from(d_nom_poly)
            .divide_with_q_and_r(&d_denom_poly)
            .unwrap();
        // Compute the group element d
        let d = <E::G1 as VariableBaseMSM>::msm_unchecked(&pk.x_z_g1_vec, &d_poly.coeffs);

        /////////////////////////////// Assembling the proof ///////////////////////
        let output = Ok(Proof {
            a: a.into(),
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
}
