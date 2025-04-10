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
        let r1cs_orig_num_cnstrs = pk.vk.succinct_index.num_constraints - pk.vk.m0;
        let domain_ratio = pk.vk.h_domain.size() / pk.vk.k_domain.size();
        let matrices = &cs.to_matrices().unwrap()[SR1CS_PREDICATE_LABEL];
        // Make sure the extracted information is consistent with each other
        assert_eq!(pk.vk.m0, cs.instance_assignment.len());
        assert_eq!(num_witness_vars, cs.witness_assignment.len());
        assert_eq!(matrices.len(), 2);
        assert_eq!(matrices[0].len().next_power_of_two(), pk.vk.n);
        assert_eq!(matrices[1].len().next_power_of_two(), pk.vk.n);
        end_timer!(timer_extract_info);
        /////////////////////// Computing (z_u, z_w), (w_u, w_w) polynomials  ///////////////////////
        let (xu_vec, (mut wu_vec, ww_vec)) = Self::compute_xu_wu_ww(
            pk.vk.n,
            &matrices[0],
            &matrices[1],
            &cs.instance_assignment,
            &cs.witness_assignment,
            pk.vk.n,
        )
        .unwrap();
        let zu_vec = xu_vec
            .iter()
            .zip(wu_vec.iter())
            .map(|(a, b)| *a + *b)
            .collect::<Vec<E::ScalarField>>();
        let wu_clone = wu_vec.clone();
        let w_leftover = &wu_clone[r1cs_orig_num_cnstrs..r1cs_orig_num_cnstrs + pk.vk.m0];
        let x_leftover = &xu_vec[r1cs_orig_num_cnstrs..r1cs_orig_num_cnstrs + pk.vk.m0];
        Self::zero_tail(&mut wu_vec, r1cs_orig_num_cnstrs);
        let xu_reshaped_vec = Self::fragment_with_separator(
            &vec![E::ScalarField::zero(); wu_vec.len()],
            domain_ratio,
            Some(x_leftover),
        );
        let wu_reshaped_vec =
            Self::fragment_with_separator(&wu_vec, domain_ratio, Some(w_leftover));
        let zu_reshaped_vec = Self::fragment_with_separator(&zu_vec, domain_ratio, None);
        let w_reshaped_vec = Self::fragment_with_separator(&ww_vec, domain_ratio, None);
        //////////////////////// Interpolating polynomials ///////////////////////
        let timer_interp = start_timer!(|| "Interpolating z_u, z_w, w_u, w_w polynomials");
        let xu_dense_poly =
            Evaluations::from_vec_and_domain(xu_reshaped_vec, pk.vk.h_domain).interpolate();
        let wu_dense_poly =
            Evaluations::from_vec_and_domain(wu_reshaped_vec, pk.vk.h_domain).interpolate();
        let u_dense_poly =
            Evaluations::from_vec_and_domain(zu_reshaped_vec.clone(), pk.vk.h_domain).interpolate();
        let w_dense_poly =
            Evaluations::from_vec_and_domain(w_reshaped_vec.clone(), pk.vk.h_domain).interpolate();
        assert_eq!(&xu_dense_poly + &wu_dense_poly, u_dense_poly);
        // Check if the hadamard product of z_u_reshaped_vec and z_u_reshaped_vec is equal to zw_reshaped_vec

        end_timer!(timer_interp);

        let timer_interp = start_timer!(|| "Sparcifying z_u, z_w, w_u, w_w polynomials");
        let u_sparse_poly = SparsePolynomial::from(u_dense_poly.clone());
        let w_sparse_poly = SparsePolynomial::from(w_dense_poly.clone());
        assert!(u_sparse_poly.degree() < pk.vk.n);
        end_timer!(timer_interp);
        /////////////////////// Computing h(X) ///////////////////////
        let timer_h = start_timer!(|| "Computing h(X)");
        let (h, rem) = (&u_dense_poly * &u_dense_poly - &w_dense_poly)
            .divide_by_vanishing_poly(pk.vk.h_domain);
        assert!(rem.is_zero());
        end_timer!(timer_h);
        /////////////////////// Computing ra(X) of degree bnd_a=1 ///////////////////////
        let timer_ra = start_timer!(|| "Computing ra(X) of degree bnd_a=1");
        let ra_sparse_poly = SparsePolynomial::from_coefficients_vec(vec![
            (0, E::ScalarField::rand(rng)),
            (1, E::ScalarField::rand(rng)),
        ]);

        let ra_dense_poly = DensePolynomial::from(ra_sparse_poly.clone());
        assert!(ra_dense_poly.degree() <= BND_A);
        assert!(ra_sparse_poly.degree() <= BND_A);
        end_timer!(timer_ra);
        /////////////////////// Computing A(X) and [a]_1 ///////////////////////
        let timer_a = start_timer!(|| "Computing A(X) and [a]_1");
        let u_at_x_g1: E::G1Affine = Self::msm(&u_dense_poly.coeffs, &pk.x_to_j_g1_vec).into();
        let uu = u_dense_poly.evaluate(&pk.vk.x);
        let uuu = pk.vk.g * uu;
        assert!(u_at_x_g1 == uuu.into());
        let ra_at_x_y_to_alpha_g1: E::G1Affine =
            Self::msm(&ra_dense_poly.coeffs, &pk.x_to_i_y_to_alpha_g1_vec).into();
        let a: <E as Pairing>::G1Affine = (u_at_x_g1 + ra_at_x_y_to_alpha_g1).into();
        let u_over_y_gamma_poly = Self::mul_by_x_power(&u_sparse_poly, pk.vk.sigma * MINUS_GAMMA);
        let uuu = pk.vk.g * uu * pk.vk.y.pow([MINUS_GAMMA as u64]);
        assert!(pk.vk.g * u_over_y_gamma_poly.evaluate(&pk.vk.x) == uuu);
        let ra_y_to_alpha_minus_gamma_poly =
            Self::mul_by_x_power(&ra_sparse_poly, pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA));
        let rr =
            ra_y_to_alpha_minus_gamma_poly.evaluate(&pk.vk.x) / pk.vk.y.pow([MINUS_GAMMA as u64]);
        let rrr = pk.vk.g * rr;
        assert!(ra_at_x_y_to_alpha_g1 == rrr.into());
        let a_over_y_to_gamma_poly = u_over_y_gamma_poly + ra_y_to_alpha_minus_gamma_poly;
        let aa = a_over_y_to_gamma_poly.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]));
        let aaa = pk.vk.g * aa;
        assert!(a == aaa.into());
        end_timer!(timer_a);

        ////////////////////// Computing R(X) and [R(X)]_1 ///////////////////////
        let timer_r = start_timer!(|| "Computing R(X) and [R(X)]_1");

        let r_poly_term_one = &Self::mul_by_x_power(&u_sparse_poly, pk.vk.sigma * MINUS_GAMMA)
            .mul(&ra_sparse_poly)
            * E::ScalarField::from(2_u32);
        let r1_r = r_poly_term_one.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]));
        let r1_rr = pk.vk.g * r1_r;
        let r_poly_term_two = Self::mul_by_x_power(
            &ra_sparse_poly.mul(&ra_sparse_poly),
            pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA),
        );
        let r2_r = r_poly_term_two.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]));
        let r2_rr = pk.vk.g * r2_r;

        let r_over_y_to_gamma_poly = r_poly_term_one + r_poly_term_two + ra_sparse_poly.clone();
        let r3_r = ra_sparse_poly.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]));
        let r3_rr = pk.vk.g * r3_r;
        let rr = r_over_y_to_gamma_poly.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]));
        let rrr = pk.vk.g * rr;
        let ra_u_poly = &ra_dense_poly * &u_dense_poly;
        let ra_u_g1: E::G1Affine = Self::msm(&ra_u_poly.coeffs, &pk.x_to_j_g1_vec).into();

        let ra2_y_poly = &ra_dense_poly * &ra_dense_poly;
        let r_a2_y_to_alpha_g1: E::G1Affine =
            Self::msm(&ra2_y_poly.coeffs, &pk.x_to_i_y_to_alpha_g1_vec).into();

        let ra_y_to_gamma_g1: E::G1Affine =
            Self::msm(&ra_dense_poly.coeffs, &pk.x_to_i_y_to_gamma_g1_vec).into();

        let r_x_g1 = ra_u_g1 + ra_u_g1 + r_a2_y_to_alpha_g1 + ra_y_to_gamma_g1;
        assert_eq!(ra_u_g1 + ra_u_g1, r1_rr);
        assert_eq!(r_a2_y_to_alpha_g1, r2_rr.into());
        assert_eq!(ra_y_to_gamma_g1, r3_rr.into());
        assert_eq!(r_x_g1, rrr);
        end_timer!(timer_r);
        /////////////////////// Computing C(X) and [c]_1 ///////////////////////
        let timer_c = start_timer!(|| "Computing C(X) and [C(X)]_1");

        let zh_poly = pk.vk.h_domain.vanishing_polynomial();
        let zh_poly_dense = DensePolynomial::from(zh_poly.clone());
        let h_zh_poly_sparse = SparsePolynomial::from(&h * &zh_poly_dense);

        let c_poly_term_one = Self::mul_by_x_power(&u_sparse_poly, pk.vk.sigma * MINUS_ALPHA)
            + Self::mul_by_x_power(&w_sparse_poly, pk.vk.sigma * (MINUS_GAMMA + MINUS_ALPHA));
        let c1_c = c_poly_term_one.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]));
        let c1_cc = pk.vk.g * c1_c;
        let c_over_y_to_gamma_poly: SparsePolynomial<E::ScalarField> = c_poly_term_one
            + Self::mul_by_x_power(&h_zh_poly_sparse, pk.vk.sigma * (MINUS_GAMMA + MINUS_ALPHA))
            + r_over_y_to_gamma_poly;

        let cc = c_over_y_to_gamma_poly.evaluate(&pk.vk.x) / (pk.vk.y.pow([MINUS_GAMMA as u64]));
        let ccc = pk.vk.g * cc;
        let u_w_g1: E::G1Affine = Self::msm(&cs.witness_assignment, &pk.u_w_g1_vec).into();

        let h_zh_x_over_y_to_alpha_g1: E::G1Affine =
            Self::msm(&h.coeffs, &pk.x_zh_over_y_alpha_g1_vec).into();

        let c: <E as Pairing>::G1Affine = (u_w_g1 + h_zh_x_over_y_to_alpha_g1 + r_x_g1).into();
        assert_eq!(c1_cc, u_w_g1.into());
        assert_eq!(ccc, c.into());
        
        end_timer!(timer_c);
        /////////////////////// Sampling x1 ///////////////////////
        let timer_x1 = start_timer!(|| "Computing Challenge x1");
        let x1 = compute_chall::<E>(&pk.vk, &cs.instance_assignment[1..], &a, &c, None);
        end_timer!(timer_x1);

        ///////////////////// Computing y1 , Ax1 ///////////////////////

        let timer_ax1 = start_timer!(|| "Computint y1 and Ax1");
        let y1 = x1.pow([pk.vk.sigma as u64]);
        let y1_to_gamma = y1.pow([MINUS_GAMMA as u64]).inverse().unwrap();
        let y1_to_alpha = y1.pow([MINUS_ALPHA as u64]).inverse().unwrap();
        let a_x1 = u_dense_poly.evaluate(&x1) + ra_u_poly.evaluate(&x1) * y1_to_alpha;
        end_timer!(timer_ax1);
        //////////////////////// Sampling x2 ///////////////////////
        let timer_x2 = start_timer!(|| "Computing x2");
        let x_2 = compute_chall::<E>(
            &pk.vk,
            &cs.instance_assignment[1..],
            &a,
            &c,
            Some((x1, a_x1)),
        );
        end_timer!(timer_x2);

        ///////////////////////////// Computing PI(X) ///////////////////////
        let c_at_x1 =
            Self::compute_c_at_x1(y1_to_gamma, y1_to_alpha, a_x1, x1, &pk.vk, &xu_dense_poly);
        // ///////////////////// Computing D(X) ///////////////////////

        let d_right_coeff_poly =
            SparsePolynomial::from_coefficients_vec(vec![(0, a_x1 + x_2 * c_at_x1)]);
        // let temp1 = (a_over_y_to_gamma_poly + &c_over_y_to_gamma_poly * x_2);
        // let temp2 = (-Self::mul_by_x_power(&d_right_coeff_poly, pk.vk.sigma * MINUS_GAMMA));
        // dbg!(temp1.evaluate(&x1));
        // dbg!(temp2.evaluate(&x1));
        // todo!();
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
        assert!(d_rem_poly.is_zero());

        let d = Self::msm(&d_over_y_to_gamma_poly.coeffs, &pk.x_z_g1_vec);

        /////////////////////////////// Assembling the proof ///////////////////////

        let output = Ok(Proof {
            a,
            c,
            d: d.into(),
            a_x_1: a_x1.into(),
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
    fn compute_xu_wu_ww(
        n: usize,
        u_mat: &Matrix<E::ScalarField>,
        w_mat: &Matrix<E::ScalarField>,
        instance_assignment: &[E::ScalarField],
        witness_assignment: &[E::ScalarField],
        num_constraints: usize,
    ) -> Result<
        (
            Vec<E::ScalarField>,
            (Vec<E::ScalarField>, Vec<E::ScalarField>),
        ),
        SynthesisError,
    > {
        let mut x_punctured_assignment: Vec<E::ScalarField> = instance_assignment.to_vec();
        let mut w_punctured_assignment: Vec<E::ScalarField> =
            vec![E::ScalarField::zero(); x_punctured_assignment.len()];
        x_punctured_assignment
            .extend_from_slice(&vec![E::ScalarField::zero(); witness_assignment.len()]);
        w_punctured_assignment.extend_from_slice(witness_assignment);

        let mut x_u = vec![E::ScalarField::zero(); n];

        cfg_iter_mut!(x_u[..num_constraints])
            .zip(u_mat)
            .zip(w_mat)
            .for_each(|((mut u, ut_i), wt_i)| {
                *u = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    ut_i,
                    &x_punctured_assignment,
                );
            });

        let mut w_u = vec![E::ScalarField::zero(); n];
        let mut w_w = vec![E::ScalarField::zero(); n];

        cfg_iter_mut!(w_u[..num_constraints])
            .zip(&mut w_w[..num_constraints])
            .zip(u_mat)
            .zip(w_mat)
            .for_each(|(((mut u, mut w), ut_i), wt_i)| {
                *u = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    ut_i,
                    &w_punctured_assignment,
                );
                *w = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    wt_i,
                    &w_punctured_assignment,
                );
            });

        Ok((x_u, (w_u, w_w)))
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
        assert!(scalars.len() <= g1_elems.len());
        E::G1::msm_unchecked(g1_elems.as_slice(), scalars.as_slice())
    }

    pub(crate) fn fragment_with_separator(
        v: &[E::ScalarField],
        k: usize,
        separator: Option<&[E::ScalarField]>,
    ) -> Vec<E::ScalarField> {
        assert!(k >= 1, "k must be at least 1");

        let sep_slice = separator.unwrap_or(&[]);
        let mut sep_iter = sep_slice.iter();

        let mut result = Vec::with_capacity(v.len() + (v.len() + k - 1) / k); // estimate max size
        let mut data_iter = v.into_iter();

        let mut index = 0;
        loop {
            if index % k == 0 {
                // insert separator
                let sep = sep_iter.next().cloned().unwrap_or(E::ScalarField::zero());
                result.push(sep);
            } else if let Some(val) = data_iter.next() {
                result.push(*val);
            } else {
                break;
            }
            index += 1;
        }

        result
    }
    fn zero_tail(v: &mut [E::ScalarField], k: usize) {
        assert!(k <= v.len(), "Index k out of bounds");

        for elem in &mut v[k..] {
            *elem = E::ScalarField::zero();
        }
    }
}
