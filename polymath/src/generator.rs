use std::rc::Rc;

use crate::{
    Polymath,
    data_structures::{ProvingKey, SuccinctIndex, VerifyingKey},
};
use ark_ec::{pairing::Pairing, scalar_mul::BatchMulPreprocessing};
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_relations::{
    gr1cs::{
        self, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
        SynthesisMode,
        instance_outliner::{InstanceOutliner, outline_sr1cs},
        predicate::polynomial_constraint::SR1CS_PREDICATE_LABEL,
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
        let timer_fft_domain = start_timer!(|| "Computing the FFT domain");
        let h_domain = GeneralEvaluationDomain::new(num_constraints).unwrap();
        let k_domain = GeneralEvaluationDomain::new(num_instance).unwrap();
        end_timer!(timer_fft_domain);
        /////////////////////// Trapdoor and parameter generation ///////////////////////

        let x: E::ScalarField = h_domain.sample_element_outside_domain(rng);
        let z: E::ScalarField = h_domain.sample_element_outside_domain(rng);
        let z_h_x = h_domain.evaluate_vanishing_polynomial(x);
        let n = h_domain.size();
        let m = num_total_variables;
        let m0 = cs.num_instance_variables();
        let bnd_a: usize = 1;
        let sigma = n + 3;
        let y: E::ScalarField = x.pow([sigma as u64]);
        let alpha: isize = -3;
        let minus_alpha = -alpha;
        let gamma: isize = -5;
        let minus_gamma = -gamma;
        let d_min: isize = -5 * n as isize - 15;
        let d_max: usize = 5 * n + 7;
        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);
        let x_h = h * x;
        let z_h = h * z;
        let max_degree: usize = d_max;
        let y_to_alpha = y.inverse().unwrap().pow([minus_alpha as u64]);
        let y_to_minus_alpha = y_to_alpha.inverse().unwrap();
        let y_to_gamma = y.inverse().unwrap().pow([minus_gamma as u64]);

        ///////////////////////////////////// Computing the batch mul prep ///////////////////////
        let timer_batch_mul_prep = start_timer!(|| "Batch Mul Preprocessing startup");
        let table = BatchMulPreprocessing::new(g, max_degree + 1);
        end_timer!(timer_batch_mul_prep);

        /////////////////////////////////// Producing x_to_j_g1_vec ///////////////////////////////
        // Exponents: (x^j)_{j=0}^{n+bnd_a-1}
        let timer_x_vec = start_timer!(|| "Computing powers of x_to_j_g1_vec");
        let mut x_vec = vec![E::ScalarField::ONE];
        let mut cur = x;
        for _ in 0..=(n + bnd_a - 1) {
            x_vec.push(cur);
            cur *= &x;
        }
        let x_to_j_g1_vec = table.batch_mul(&x_vec);
        end_timer!(timer_x_vec);
        ///////////////////////////// Producing x_y_alpha_vec ///////////////////////
        // Exponents: (x^i.y^α)_{i=0}^{2*bnd_a}

        let timer_x_y_alpha_vec = start_timer!(|| "Computing powers of x_to_i_y_to_alpha_g1_vec");
        let mut x_y_alpha_vec = vec![E::ScalarField::ONE];
        let mut cur = x;
        for _ in 0..=(2 * bnd_a) {
            x_y_alpha_vec.push(cur * y_to_alpha);
            cur *= &x;
        }
        let x_to_i_y_to_alpha_g1_vec = table.batch_mul(&x_y_alpha_vec);
        end_timer!(timer_x_y_alpha_vec);

        /////////////////////// Computing u_w_g1_vec ////////////////////////
        // Exponents: ((uj(x)y^γ + wj(x))/y^α)
        let timer_u_w_g1_vec = start_timer!(|| "Computing u_w_g1_vec");
        let (ui_vec, wi_vec) = Self::compute_ui_wi_at_x(x, &cs, h_domain).unwrap();

        let u_w_vec = ui_vec[num_instance..]
            .par_iter()
            .zip(&wi_vec[num_instance..])
            .map(|(u_i, w_i)| (*u_i * y_to_gamma + *w_i) * y_to_minus_alpha)
            .collect::<Vec<_>>();
        let u_w_g1_vec = table.batch_mul(&u_w_vec);

        end_timer!(timer_u_w_g1_vec);

        /////////////////////// Computing x_zh_over_y_alpha_g1_vec ////////////////////////
        let timer_x_zh_over_y_alpha_g1_vec = start_timer!(|| "Computing x_zh_over_y_alpha_g1_vec");

        let mut x_zh_over_y_alpha_vec = vec![E::ScalarField::ONE];
        let mut cur = x;
        for _ in 0..=(n - 2) {
            x_zh_over_y_alpha_vec.push(cur * z_h_x * y_to_minus_alpha);
            cur *= &x;
        }
        let x_zh_over_y_alpha_g1_vec = table.batch_mul(&x_zh_over_y_alpha_vec);

        end_timer!(timer_x_zh_over_y_alpha_g1_vec);

        /////////////////////// Computing x_y_gamma_vec ////////////////////////
        let timer_x_to_i_y_to_gamma_g1_vec = start_timer!(|| "Computing x_to_i_y_to_gamma_g1_vec");

        let mut x_y_gamma_vec = vec![E::ScalarField::ONE];
        let mut cur = x;
        for _ in 0..=(bnd_a) {
            x_y_gamma_vec.push(cur * y_to_gamma);
            cur *= &x;
        }
        let x_to_i_y_to_gamma_g1_vec = table.batch_mul(&x_y_gamma_vec);
        end_timer!(timer_x_to_i_y_to_gamma_g1_vec);

        /////////////////////// Computing x_z_vec ////////////////////////
        let timer_compute_x_z = start_timer!(|| "Computing x_z");
        let mut x_z_vec = vec![E::ScalarField::ONE];
        let mut cur = x;
        for _ in d_min..=((d_max - 1) as isize) {
            x_z_vec.push(cur * z);
            cur *= &x;
        }
        let x_z_g1_vec = table.batch_mul(&x_z_vec);
        end_timer!(timer_compute_x_z);

        /////////////////////// Succinct Index ///////////////////////
        let timer_succinct_index = start_timer!(|| "Generating Succinct Index");
        let num_public_inputs = cs.num_instance_variables();
        let succinct_index = SuccinctIndex {
            num_constraints,
            num_instance,
        };
        end_timer!(timer_succinct_index);

        /////////////////////////////////////////////////////////////////
        let vk = VerifyingKey {
            g: g.into(),
            x_h: x_h.into(),
            z_h: z_h.into(),
            h: h.into(),
            h_domain,
            k_domain,
            succinct_index,
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
        let timer_cs_startup = start_timer!(|| "Constraint System Startup");
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
        let timer_synthesize_circuit = start_timer!(|| "Synthesize Circuit");
        end_timer!(timer_synthesize_circuit);

        let timer_inlining = start_timer!(|| "Inlining constraints");
        sr1cs_cs.finalize();
        end_timer!(timer_inlining);
        end_timer!(timer_cs_startup);
        Ok(sr1cs_cs.into_inner().unwrap())
    }

    #[allow(clippy::type_complexity)]
    fn compute_ui_wi_at_x(
        x: E::ScalarField,
        new_cs: &ConstraintSystem<E::ScalarField>,
        domain: GeneralEvaluationDomain<E::ScalarField>,
    ) -> Result<(Vec<E::ScalarField>, Vec<E::ScalarField>), SynthesisError> {
        // Compute all the lagrange polynomials
        let timer_eval_all_lagrange_polys = start_timer!(|| "Evaluating all Lagrange polys");
        let lagrange_polys_at_tau = domain.evaluate_all_lagrange_coefficients(x);
        end_timer!(timer_eval_all_lagrange_polys);

        let num_variables = new_cs.num_instance_variables() + new_cs.num_witness_variables();
        let num_constraints = new_cs.num_constraints();
        let matrices = &new_cs.to_matrices().unwrap()[SR1CS_PREDICATE_LABEL];

        let mut a = vec![E::ScalarField::zero(); num_variables];
        let mut b = vec![E::ScalarField::zero(); num_variables];

        let timer_compute_a_b = start_timer!(|| "Compute a_i(tau)'s and z_i(tau)'s");
        for (i, u_i) in lagrange_polys_at_tau
            .iter()
            .enumerate()
            .take(num_constraints)
        {
            for &(ref coeff, index) in &matrices[0][i] {
                a[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices[1][i] {
                b[index] += &(*u_i * coeff);
            }
        }
        // write a sanity check, make up a z, check if MV product is correct
        end_timer!(timer_compute_a_b);
        Ok((a, b))
    }
}
