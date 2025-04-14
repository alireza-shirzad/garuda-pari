use std::{ops::Neg, rc::Rc};

use crate::utils::{sample_x1, sample_x2};
use crate::{
    data_structures::{Proof, ProvingKey},
    Polymath,
};
use crate::{ALPHA, BND_A, GAMMA, MINUS_ALPHA, MINUS_GAMMA};
use ark_ec::AffineRepr;
use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{batch_inversion_and_mul, BigInteger, FftField, PrimeField};
use ark_ff::{Field, Zero};
use ark_poly::univariate::{DenseOrSparsePolynomial, SparsePolynomial};
use ark_poly::Radix2EvaluationDomain;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial,
};
use ark_relations::{
    gr1cs::{
        self,
        instance_outliner::{outline_sr1cs, InstanceOutliner},
        predicate::polynomial_constraint::SR1CS_PREDICATE_LABEL,
        ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
    },
    sr1cs::Sr1csAdapter,
};
use ark_std::rand::RngCore;
use ark_std::{cfg_iter, cfg_iter_mut, end_timer, start_timer, UniformRand};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use shared_utils::transcript::IOPTranscript;

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
        let num_witness = cs.num_witness_variables();
        let num_instance = cs.num_instance_variables();
        let num_constraints = cs.num_constraints();
        let num_vars = num_witness + num_instance;
        let variable_assignment = cfg_iter!(cs.instance_assignment)
            .chain(cfg_iter!(cs.witness_assignment))
            .cloned()
            .collect::<Vec<_>>();
        let domain_ratio = pk.vk.h_domain.size() / pk.vk.k_domain.size();
        let domain_normalizer_poly = Self::domain_normalizer(&pk.vk.h_domain, &pk.vk.k_domain);
        let matrices = cs.to_matrices().unwrap()[SR1CS_PREDICATE_LABEL].clone();

        ///////////////////// Reshaping the matrices and assignment vector ///////////////////////
        // They should be reshaped in a way that isntance variables align with the K subgroup and witness variables are aligned with H\K

        let new_variable_assignent = Self::reshape_slice(
            &variable_assignment,
            num_witness,
            num_instance,
            domain_ratio,
        );
        let u_mat = Self::reshape_matrix(&matrices[0], num_witness, num_instance, domain_ratio);
        let w_mat = Self::reshape_matrix(&matrices[1], num_witness, num_instance, domain_ratio);
        /////////////////////// Computing z.u and z.w vectors and their interpolation  ///////////////////////

        let (zu_vec, zw_vec) = Self::compute_zu_zw(
            &u_mat,
            &w_mat,
            &new_variable_assignent,
            cs.num_constraints(),
        )
        .unwrap();
        let xu_dense_poly =
            Evaluations::from_vec_and_domain(cs.instance_assignment.clone(), pk.vk.k_domain)
                .interpolate()
                * domain_normalizer_poly;
        let u_dense_poly = Evaluations::from_vec_and_domain(zu_vec, pk.vk.h_domain).interpolate();
        let wu_dense_poly = &u_dense_poly - &xu_dense_poly;
        // Note that xw poly is zero, so we have ww = zw
        let w_dense_poly = Evaluations::from_vec_and_domain(zw_vec, pk.vk.h_domain).interpolate();

        // Creating the sparse versions of the polynomials to be later used
        let u_sparse_poly = SparsePolynomial::from(u_dense_poly.clone());
        let wu_sparse_poly = SparsePolynomial::from(wu_dense_poly.clone());
        let w_sparse_poly = SparsePolynomial::from(w_dense_poly.clone());
        /////////////////////// Computing h(X) ///////////////////////
        let (h, rem) = (&u_dense_poly * &u_dense_poly - &w_dense_poly)
            .divide_by_vanishing_poly(pk.vk.h_domain);
        // This assertion makes sure that we successfully arithmetized the problem
        assert!(rem.is_zero());
        /////////////////////// Computing ra(X) of degree bnd_a=1 ///////////////////////
        let ra_sparse_poly = SparsePolynomial::from_coefficients_vec(vec![
            (0, E::ScalarField::rand(rng)),
            (1, E::ScalarField::rand(rng)),
        ]);

        let ra_dense_poly = DensePolynomial::from(ra_sparse_poly.clone());
        /////////////////////// Computing A(X) and [a]_1 ///////////////////////
        let u_over_y_gamma_poly = Self::mul_by_x_power(&u_sparse_poly, pk.vk.sigma * MINUS_GAMMA);

        let u_at_x_g1: E::G1Affine = Self::msm(&u_dense_poly.coeffs, &pk.x_to_j_g1_vec).into();
        let ra_at_x_y_to_alpha_g1: E::G1Affine =
            Self::msm(&ra_dense_poly.coeffs, &pk.x_to_i_y_to_alpha_g1_vec).into();
        let a: <E as Pairing>::G1Affine = (u_at_x_g1 + ra_at_x_y_to_alpha_g1).into();
        let ra_y_to_alpha_minus_gamma_poly =
            Self::mul_by_x_power(&ra_sparse_poly, pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA));
        let a_over_y_to_gamma_poly = u_over_y_gamma_poly + ra_y_to_alpha_minus_gamma_poly;
        ////////////////////// Computing R(X) and [R(X)]_1 ///////////////////////

        let r_poly_term_one_over_y_to_gamma =
            &Self::mul_by_x_power(&u_sparse_poly, pk.vk.sigma * MINUS_GAMMA).mul(&ra_sparse_poly)
                * E::ScalarField::from(2_u32);
        let r_poly_term_two_over_y_to_gamma = Self::mul_by_x_power(
            &ra_sparse_poly.mul(&ra_sparse_poly),
            pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA),
        );

        let r_over_y_to_gamma_poly = r_poly_term_one_over_y_to_gamma
            + r_poly_term_two_over_y_to_gamma
            + ra_sparse_poly.clone();
        let ra_u_poly = &ra_dense_poly * &u_dense_poly;
        let ra_u_g1: E::G1Affine = Self::msm(&ra_u_poly.coeffs, &pk.x_to_j_g1_vec).into();

        let ra2_y_poly = &ra_dense_poly * &ra_dense_poly;
        let r_a2_y_to_alpha_g1: E::G1Affine =
            Self::msm(&ra2_y_poly.coeffs, &pk.x_to_i_y_to_alpha_g1_vec).into();

        let ra_y_to_gamma_g1: E::G1Affine =
            Self::msm(&ra_dense_poly.coeffs, &pk.x_to_i_y_to_gamma_g1_vec).into();

        let r_x_g1 = ra_u_g1 + ra_u_g1 + r_a2_y_to_alpha_g1 + ra_y_to_gamma_g1;

        /////////////////////// Computing C(X) and [c]_1 ///////////////////////

        let zh_poly = pk.vk.h_domain.vanishing_polynomial();
        let zh_poly_dense = DensePolynomial::from(zh_poly.clone());
        let h_zh_poly_sparse = SparsePolynomial::from(&h * &zh_poly_dense);

        let c_poly_term_one = Self::mul_by_x_power(&wu_sparse_poly, pk.vk.sigma * MINUS_ALPHA)
            + Self::mul_by_x_power(&w_sparse_poly, pk.vk.sigma * (MINUS_GAMMA + MINUS_ALPHA));
        let c_over_y_to_gamma_poly: SparsePolynomial<E::ScalarField> = c_poly_term_one.clone()
            + Self::mul_by_x_power(&h_zh_poly_sparse, pk.vk.sigma * (MINUS_GAMMA + MINUS_ALPHA))
            + r_over_y_to_gamma_poly;

        let u_w_g1: E::G1Affine = Self::msm(&cs.witness_assignment, &pk.u_w_g1_vec).into();

        let h_zh_x_over_y_to_alpha_g1: E::G1Affine =
            Self::msm(&h.coeffs, &pk.x_zh_over_y_alpha_g1_vec).into();

        let c: <E as Pairing>::G1Affine = (u_w_g1 + h_zh_x_over_y_to_alpha_g1 + r_x_g1).into();
        debug_assert_eq!(
            pk.vk.g * (c_poly_term_one.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]))),
            u_w_g1.into()
        );

        /////////////////////// Sampling x1 ///////////////////////

        let mut transcript = IOPTranscript::<E::ScalarField>::new(crate::Polymath::<E>::SNARK_NAME);
        let x1 = sample_x1::<E>(
            &mut transcript,
            &pk.vk,
            &cs.instance_assignment[1..],
            &a,
            &c,
        );

        ///////////////////// Computing y1 , Ax1 ///////////////////////

        let y1 = x1.pow([pk.vk.sigma as u64]);
        let y1_to_gamma = y1.pow([MINUS_GAMMA as u64]).inverse().unwrap();
        let y1_to_alpha = y1.pow([MINUS_ALPHA as u64]).inverse().unwrap();
        let a_x1 = u_dense_poly.evaluate(&x1) + ra_u_poly.evaluate(&x1) * y1_to_alpha;
        //////////////////////// Sampling x2 ///////////////////////
        let x_2 = sample_x2::<E>(&mut transcript, x1, a_x1);

        ///////////////////////////// Computing PI(X) ///////////////////////
        let c_at_x1 =
            Self::compute_c_at_x1(y1_to_gamma, y1_to_alpha, a_x1, x1, &pk.vk, &xu_dense_poly);
        // ///////////////////// Computing D(X) ///////////////////////

        let d_right_coeff_poly =
            SparsePolynomial::from_coefficients_vec(vec![(0, a_x1 + x_2 * c_at_x1)]);
        let d_over_y_to_gamma_nom_poly: DenseOrSparsePolynomial<E::ScalarField> =
            DenseOrSparsePolynomial::from(
                (a_over_y_to_gamma_poly + &c_over_y_to_gamma_poly * x_2)
                    + (-Self::mul_by_x_power(&d_right_coeff_poly, pk.vk.sigma * MINUS_GAMMA)),
            );
        let d_denom_poly =
            DenseOrSparsePolynomial::from(DensePolynomial::from_coefficients_slice(&[
                -x1,
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
        // assert!(d_rem_poly.is_zero());

        let d = Self::msm(&d_over_y_to_gamma_poly.coeffs, &pk.x_z_g1_vec);

        /////////////////////////////// Assembling the proof ///////////////////////

        Ok(Proof {
            a,
            c,
            d: d.into(),
            a_x_1: a_x1,
        })
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
            Sr1csAdapter::r1cs_to_sr1cs_with_assignment(&mut cs.into_inner().unwrap()).unwrap();
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
    fn compute_zu_zw(
        u_mat: &Matrix<E::ScalarField>,
        w_mat: &Matrix<E::ScalarField>,
        variable_assignment: &[E::ScalarField],
        num_constraints: usize,
    ) -> Result<(Vec<E::ScalarField>, Vec<E::ScalarField>), SynthesisError> {
        let mut z_u = vec![E::ScalarField::zero(); num_constraints];
        let mut z_w = vec![E::ScalarField::zero(); num_constraints];

        cfg_iter_mut!(z_u[..num_constraints])
            .zip(&mut z_w[..num_constraints])
            .zip(u_mat)
            .zip(w_mat)
            .for_each(|(((mut u, mut w), ut_i), wt_i)| {
                *u = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(ut_i, variable_assignment);
                *w = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(wt_i, variable_assignment);
            });

        Ok((z_u, z_w))
    }
    fn mul_by_x_power(
        poly: &SparsePolynomial<E::ScalarField>,
        power_of_x: usize,
    ) -> SparsePolynomial<E::ScalarField> {
        SparsePolynomial::from_coefficients_vec(
            cfg_iter!(poly).map(|(i, c)| (i + power_of_x, *c)).collect(),
        )
    }

    #[inline]
    fn msm(scalars: &Vec<E::ScalarField>, g1_elems: &Vec<E::G1Affine>) -> E::G1 {
        assert!(scalars.len() <= g1_elems.len());
        E::G1::msm_unchecked(g1_elems.as_slice(), scalars.as_slice())
    }
}
