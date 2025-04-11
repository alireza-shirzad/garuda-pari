use std::{cmp::max, rc::Rc};

use crate::{
    MINUS_ALPHA, MINUS_GAMMA, Polymath,
    data_structures::{ProvingKey, SuccinctIndex, VerifyingKey},
};
use ark_ec::{pairing::Pairing, scalar_mul::BatchMulPreprocessing};
use ark_ff::{Field, Zero};
use ark_poly::{
    EvaluationDomain, GeneralEvaluationDomain, Polynomial, Radix2EvaluationDomain, domain,
};
use ark_relations::{
    gr1cs::{
        self, ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
        SynthesisMode,
        instance_outliner::{InstanceOutliner, outline_sr1cs},
        predicate::polynomial_constraint::SR1CS_PREDICATE_LABEL,
        transpose,
    },
    sr1cs::Sr1csAdapter,
};
use ark_std::{UniformRand, end_timer, rand::RngCore, start_timer, vec::Vec};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

impl<E: Pairing> Polymath<E> {
    pub fn keygen<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let cs = Self::circuit_to_keygen_cs(circuit).unwrap();
        // Check if the constraint system has only one predicate which is Sqaured R1CS
        #[cfg(debug_assertions)]
        {
            assert_eq!(cs.num_predicates(), 1);
            assert_eq!(
                cs.num_constraints(),
                cs.get_predicate_num_constraints(SR1CS_PREDICATE_LABEL)
                    .unwrap()
            );
        }

        /////////////////////// Extract the constraint system  information ///////////////////////
        let num_instance = cs.num_instance_variables();
        let num_witness = cs.num_witness_variables();
        let num_total_variables = num_instance + num_witness;
        let num_constraints = cs.num_constraints();

        /////////////////////// Computing the FFT domain ///////////////////////
        let h_domain = GeneralEvaluationDomain::new(num_constraints).unwrap();
        let k_domain = GeneralEvaluationDomain::new(num_instance).unwrap();
        /////////////////////// Trapdoor and parameter generation ///////////////////////

        let x: E::ScalarField = h_domain.sample_element_outside_domain(rng);
        let z: E::ScalarField = h_domain.sample_element_outside_domain(rng);
        let z_h_x = h_domain.evaluate_vanishing_polynomial(x);
        let n = h_domain.size();
        let m = num_total_variables;
        let m0 = num_instance;
        let bnd_a: usize = 1;
        let sigma = n + 3;
        let y: E::ScalarField = x.pow([sigma as u64]);
        let d_min: isize = -5 * n as isize - 15;
        let d_max: usize = 5 * n + 7;
        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);
        let x_h = h * x;
        let z_h = h * z;
        let max_degree: usize = d_max;
        let y_to_minus_alpha = y.pow([MINUS_ALPHA as u64]);
        let y_to_alpha = y_to_minus_alpha.inverse().unwrap();
        let y_to_gamma = y.inverse().unwrap().pow([MINUS_GAMMA as u64]);

        ///////////////////////////////////// Computing the batch mul prep ///////////////////////
        let table = BatchMulPreprocessing::new(g, max_degree + 1);

        /////////////////////////////////// Producing x_to_j_g1_vec ///////////////////////////////
        // Exponents: (x^j)_{j=0}^{n+bnd_a-1}
        let mut x_vec = Vec::with_capacity(n + bnd_a);
        let mut cur = E::ScalarField::ONE;
        for _ in 0..=(n + bnd_a - 1) {
            x_vec.push(cur);
            cur *= &x;
        }
        let x_to_j_g1_vec = table.batch_mul(&x_vec);
        ///////////////////////////// Producing x_y_alpha_vec ///////////////////////
        // Exponents: (x^i.y^α)_{i=0}^{2*bnd_a}

        let mut x_y_alpha_vec = Vec::with_capacity(2 * bnd_a + 1);
        let mut cur = E::ScalarField::ONE;
        for _ in 0..=(2 * bnd_a) {
            x_y_alpha_vec.push(cur * y_to_alpha);
            cur *= &x;
        }
        let x_to_i_y_to_alpha_g1_vec = table.batch_mul(&x_y_alpha_vec);

        /////////////////////// Computing u_w_g1_vec ////////////////////////
        // Exponents: ((uj(x)y^γ + wj(x))/y^α)
        let (ui_vec, wi_vec) = Self::compute_ui_wi_at_x(x, &cs, h_domain, k_domain).unwrap();

        let u_w_vec = ui_vec
            .par_iter()
            .zip(&wi_vec)
            .map(|(u_i, w_i)| (*u_i * y_to_gamma + *w_i) * y_to_minus_alpha)
            .collect::<Vec<_>>();
        let u_w_g1_vec = table.batch_mul(&u_w_vec);

        /////////////////////// Computing x_zh_over_y_alpha_g1_vec ////////////////////////

        let mut x_zh_over_y_alpha_vec = vec![E::ScalarField::ONE];
        let mut cur = x;
        for _ in 0..=(n - 2) {
            x_zh_over_y_alpha_vec.push(cur * z_h_x * y_to_minus_alpha);
            cur *= &x;
        }
        let x_zh_over_y_alpha_g1_vec = table.batch_mul(&x_zh_over_y_alpha_vec);

        /////////////////////// Computing x_y_gamma_vec ////////////////////////

        let mut x_y_gamma_vec = Vec::with_capacity(bnd_a + 1);
        let mut cur = E::ScalarField::ONE;
        for _ in 0..=(bnd_a) {
            x_y_gamma_vec.push(cur * y_to_gamma);
            cur *= &x;
        }
        let x_to_i_y_to_gamma_g1_vec = table.batch_mul(&x_y_gamma_vec);

        /////////////////////// Computing x_z_vec ////////////////////////
        let mut x_z_vec = vec![E::ScalarField::ONE];
        let mut cur = x;
        for _ in d_min..=((d_max - 1) as isize) {
            x_z_vec.push(cur * z);
            cur *= &x;
        }
        let x_z_g1_vec = table.batch_mul(&x_z_vec);

        /////////////////////// Succinct Index ///////////////////////
        let succinct_index = SuccinctIndex {
            num_constraints,
            num_instance,
        };
        let g = g.into();
        let h = h.into();
        let x_h = x_h.into();
        let z_h = z_h.into();

        /////////////////////////////////////////////////////////////////
        let vk = VerifyingKey {
            g,
            x_h,
            z_h,
            h,
            h_prep: h.into(),
            x_h_prep: x_h.into(),
            z_h_prep: z_h.into(),
            succinct_index,
            m0,
            n,
            sigma,
            h_domain,
            k_domain,
            //TODO: Remove these
            x,
            z,
            y,
        };

        let pk = ProvingKey {
            vk: vk.clone(),
            x_to_j_g1_vec,
            x_to_i_y_to_alpha_g1_vec,
            x_to_i_y_to_gamma_g1_vec,
            u_w_g1_vec,
            x_zh_over_y_alpha_g1_vec,
            x_z_g1_vec,
        };

        (pk, vk)
    }

    fn circuit_to_keygen_cs<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
    ) -> Result<ConstraintSystem<E::ScalarField>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
        // Start up the constraint System and synthesize the circuit
        let cs: gr1cs::ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        let sr1cs_cs = Sr1csAdapter::r1cs_to_sr1cs(&cs).unwrap();
        sr1cs_cs.set_instance_outliner(InstanceOutliner {
            pred_label: SR1CS_PREDICATE_LABEL.to_string(),
            func: Rc::new(outline_sr1cs),
        });

        sr1cs_cs.finalize();
        Ok(sr1cs_cs.into_inner().unwrap())
    }

    #[allow(clippy::type_complexity)]
    fn compute_ui_wi_at_x(
        x: E::ScalarField,
        new_cs: &ConstraintSystem<E::ScalarField>,
        h_domain: GeneralEvaluationDomain<E::ScalarField>,
        k_domain: GeneralEvaluationDomain<E::ScalarField>,
    ) -> Result<(Vec<E::ScalarField>, Vec<E::ScalarField>), SynthesisError> {
        // Compute all the lagrange polynomials
        let domain_ratio = h_domain.size() / k_domain.size();
        let h_lagrange_polys_at_x = h_domain.evaluate_all_lagrange_coefficients(x);
        let num_instance = new_cs.num_instance_variables();
        let num_witness = new_cs.num_witness_variables();
        let num_constraints = new_cs.num_constraints();
        let matrices = new_cs.to_matrices().unwrap()[SR1CS_PREDICATE_LABEL].clone();
        let u_mat = Self::reshape_matrix(&matrices[0], num_witness, num_instance, domain_ratio);
        let w_mat = Self::reshape_matrix(&matrices[1], num_witness, num_instance, domain_ratio);
        let new_num_vars = max(
            (num_witness / (domain_ratio - 1)) * domain_ratio
                + num_witness % (domain_ratio - 1)
                + 1,
            (num_instance - 1) * domain_ratio + 1,
        );
        let mut u = vec![E::ScalarField::zero(); new_num_vars];
        let mut w = vec![E::ScalarField::zero(); new_num_vars];
        for (i, l_i) in h_lagrange_polys_at_x
            .iter()
            .enumerate()
            .take(num_constraints)
        {
            for &(ref coeff, index) in &u_mat[i] {
                u[index] += &(*l_i * coeff);
            }
            for &(ref coeff, index) in &w_mat[i] {
                w[index] += &(*l_i * coeff);
            }
        }
        let uu: Vec<E::ScalarField> = u
            .iter()
            .enumerate()
            .filter(|(i, _)| i % domain_ratio != 0)
            .map(|(_, val)| *val)
            .take(num_witness)
            .collect();
        let ww: Vec<E::ScalarField> = w
            .iter()
            .enumerate()
            .filter(|(i, _)| i % domain_ratio != 0)
            .map(|(_, val)| *val)
            .take(num_witness)
            .collect();
        Ok((uu, ww))
    }
}
