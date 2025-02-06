use std::{borrow::Borrow, rc::Rc};

use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{
    multivariate::{SparsePolynomial, SparseTerm},
    univariate::DensePolynomial,
    DenseUVPolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain,
    MultilinearExtension, Polynomial,
};
use ark_relations::{
    gr1cs::{
        self,
        instance_outliner::{outline_r1cs, outline_sr1cs, InstanceOutliner},
        mat_vec_mul,
        predicate::{polynomial_constraint::SR1CS_PREDICATE_LABEL, PredicateType},
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, OptimizationGoal,
        SynthesisError, R1CS_PREDICATE_LABEL,
    },
    sr1cs::Sr1csAdapter,
};
use ark_std::{cfg_iter_mut, end_timer, iterable::Iterable, rand::RngCore, start_timer, sync::Arc};

use crate::{
    data_structures::{Index, Proof, ProvingKey, VerifyingKey},
    transcript::IOPTranscript,
    Pari,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
impl<E, R> Pari<E, R>
where
    E: Pairing,
    R: RngCore,
{
    pub fn circuit_to_prover_cs<C: ConstraintSynthesizer<E::ScalarField>>(
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
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.finalize();
        circuit.generate_constraints(cs.clone())?;
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

    pub fn prove(
        cs: &mut ConstraintSystem<E::ScalarField>,
        pk: ProvingKey<E>,
    ) -> Result<Proof<E>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
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
        let num_instance_variables = cs.num_instance_variables();
        let instance_assignment = &cs.instance_assignment;
        let witness_assignment = &cs.witness_assignment;
        let matrices = &cs.to_matrices().unwrap()[SR1CS_PREDICATE_LABEL];
        end_timer!(timer_extract_info);

        /////////////////////////// Computing the evaluation domain ///////////////////////

        let timer_eval_domain = start_timer!(|| "Computing the evaluation domain");
        let domain = GeneralEvaluationDomain::new(num_constraints).unwrap();
        end_timer!(timer_eval_domain);

        /////////////////////// initilizing the transcript ///////////////////////
        let timer_init_transcript = start_timer!(|| "Initialize Transcript");
        let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
            IOPTranscript::<E::ScalarField>::new(Self::SNARK_NAME.as_bytes());
        let verifier_key: VerifyingKey<E> = pk.verifying_key.clone();
        let _ = transcript.append_serializable_element("vk".as_bytes(), &verifier_key);
        let _ = transcript
            .append_serializable_element("input".as_bytes(), &instance_assignment[1..].to_vec());
        end_timer!(timer_init_transcript);

        /////////////////////// Computing polynomials z_A, z_B, w_A, w_B ///////////////////////
        let timer_compute_za_zb_wa_wb = start_timer!(|| "Computing vectors z_A, z_B, w_A, w_B");
        let ((z_a, z_b), (w_a, w_b)) = Self::compute_wa_wb_za_zb(
            domain,
            &matrices[0],
            &matrices[1],
            instance_assignment,
            witness_assignment,
            num_instance_variables,
            num_constraints,
        )
        .unwrap();
        end_timer!(timer_compute_za_zb_wa_wb);

        //////////////////////// Interpolating polynomials ///////////////////////
        let timer_interp = start_timer!(|| "Interpolating z_a, z_b, w_a, w_b polynoials");
        let z_a_hat = Evaluations::from_vec_and_domain(z_a, domain).interpolate();
        let z_b_hat = Evaluations::from_vec_and_domain(z_b, domain).interpolate();
        let w_a_hat = Evaluations::from_vec_and_domain(w_a, domain).interpolate();
        let w_b_hat = Evaluations::from_vec_and_domain(w_b, domain).interpolate();
        end_timer!(timer_interp);

        /////////////////////// Computing the quotient polynomial ///////////////////////
        let timer_quotient = start_timer!(|| "Computing the quotient polynomial");
        let (q, _) = (&z_a_hat * &z_a_hat - &z_b_hat).divide_by_vanishing_poly(domain);
        end_timer!(timer_quotient);

        /////////////////////// Computing the batch commitment ///////////////////////
        // This box corresponds to steps 6-8 in figure 6 of the paper: https://eprint.iacr.org/2024/1245.pdf

        let timer_batch_commit = start_timer!(|| "Batch commitment");

        let t_ab = <E::G1 as VariableBaseMSM>::msm_unchecked(&pk.sigma, witness_assignment);
        let t_q = <E::G1 as VariableBaseMSM>::msm_unchecked(&pk.sigma_q_comm, &q);
        let t = t_ab + t_q;
        let t: E::G1Affine = t.into();
        end_timer!(timer_batch_commit);

        /////////////////////// Random Evaluation of the polynomials ///////////////////////

        // This box corresponds to the steps 9-10 in figure 6 of the paper: https://eprint.iacr.org/2024/1245.pdf
        let timer_eval = start_timer!(|| "MSM");
        let _ = transcript.append_serializable_element("batched_commitments".as_bytes(), &t);

        let challenge = transcript.get_and_append_challenge("r".as_bytes()).unwrap();
        let one = E::ScalarField::ONE;

        let v_a = w_a_hat.evaluate(&challenge);
        let v_b = w_b_hat.evaluate(&challenge);
        let v_q = q.evaluate(&challenge);
        dbg!(z_a_hat.evaluate(&challenge));
        dbg!(z_b_hat.evaluate(&challenge));
        dbg!(v_q);

        end_timer!(timer_eval);
        /////////////////////// Proof of correct opening ///////////////////////
        // This box corresponds to the steps 11-13 in figure 6 of the paper: https://eprint.iacr.org/2024/1245.pdf

        let timer_open = start_timer!(|| "MSM");
        let timer_open_poly = start_timer!(|| "Opening polynomial computation");
        let w_a_r = DensePolynomial::from_coefficients_vec(vec![v_a]);
        let w_b_r = DensePolynomial::from_coefficients_vec(vec![v_b]);
        let q_r = DensePolynomial::from_coefficients_vec(vec![v_q]);
        let chall_vanishing_poly = DensePolynomial::from_coefficients_vec(vec![-challenge, one]);
        let witness_a = (&w_a_hat - &w_a_r) / &chall_vanishing_poly;
        let witness_b = (&w_b_hat - &w_b_r) / &chall_vanishing_poly;
        let witness_q = (&q - &q_r) / &chall_vanishing_poly;
        end_timer!(timer_open_poly);
        let timer_msms = start_timer!(|| "Opening MSMs");
        let w_a_proof = E::G1::msm_unchecked(&pk.sigma_a, &witness_a.coeffs);
        let w_b_proof = E::G1::msm_unchecked(&pk.sigma_b, &witness_b.coeffs);
        let q_proof = E::G1::msm_unchecked(&pk.sigma_q_opening, &witness_q.coeffs);
        let u = w_a_proof + w_b_proof + q_proof;
        end_timer!(timer_msms);
        end_timer!(timer_open);

        Ok(Proof {
            t_g: t,
            u_g: u.into(),
            v_a,
            v_b,
        })
    }

    fn compute_wa_wb_za_zb(
        domain: GeneralEvaluationDomain<E::ScalarField>,
        a_mat: &Matrix<E::ScalarField>,
        b_mat: &Matrix<E::ScalarField>,
        instance_assignment: &[E::ScalarField],
        witness_assignment: &[E::ScalarField],
        num_instance_variables: usize,
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
        assignment.extend_from_slice(&witness_assignment);
        punctured_assignment.extend_from_slice(witness_assignment);

        let domain_size = domain.size();
        let mut z_a = vec![E::ScalarField::zero(); domain_size];
        let mut z_b = vec![E::ScalarField::zero(); domain_size];

        cfg_iter_mut!(z_a[..num_constraints])
            .zip(&mut z_b[..num_constraints])
            .zip(a_mat)
            .zip(b_mat)
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(&at_i, &assignment);
                *b = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(&bt_i, &assignment);
            });

        let mut w = vec![E::ScalarField::zero(); num_instance_variables];
        w.extend_from_slice(&witness_assignment);
        let mut w_a = vec![E::ScalarField::zero(); domain_size];
        let mut w_b = vec![E::ScalarField::zero(); domain_size];

        cfg_iter_mut!(w_a[..num_constraints])
            .zip(&mut w_b[..num_constraints])
            .zip(a_mat)
            .zip(b_mat)
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    &at_i,
                    &punctured_assignment,
                );
                *b = Sr1csAdapter::<E::ScalarField>::evaluate_constraint(
                    &bt_i,
                    &punctured_assignment,
                );
            });

        Ok(((z_a, z_b), (w_a, w_b)))
    }
}
