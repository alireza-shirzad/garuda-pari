use std::borrow::Borrow;
use std::time::{Duration, Instant};

use crate::arithmetic::{DenseMultilinearExtension, VirtualPolynomial};
use crate::data_structures::{GroupParams, Index, ProvingKey, VerifyingKey};
use crate::piop::prelude::{IOPProof, ZeroCheck};
use crate::piop::PolyIOP;
use crate::timer::{self, Timer};
use crate::transcript::IOPTranscript;
use crate::utils::produce_batched_poly;
use crate::utils::{epc_constrained_commit, epc_unconstrained_commit};
use crate::utils::{generate_opening_proof, produce_opening_batch_challs};
use crate::{data_structures::Proof, Garuda};
use crate::{to_bytes, write_bench};
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::crh::CRHScheme;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, Field, PrimeField, UniformRand, Zero};
use ark_poly::multivariate::{SparsePolynomial, SparseTerm};
use ark_poly::{polynomial, MultilinearExtension, Polynomial};
use ark_relations::gr1cs::predicate::PredicateType;
use ark_relations::gr1cs::{
    self, mat_vec_mul, predicate, ConstraintSynthesizer, ConstraintSystem, Matrix,
    OptimizationGoal, SynthesisError, SynthesisMode, R1CS_PREDICATE_LABEL,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iterable::Iterable;
use ark_std::ops::Add;
use ark_std::rand::RngCore;
use ark_std::sync::Arc;
use ark_std::{end_timer, start_timer};
impl<E> Garuda<E>
where
    E: Pairing,
{
    pub fn prove<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        proving_key: ProvingKey<E>,
    ) -> Result<Proof<E>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
        let timer_prove: Timer = Timer::new("SNARK::Prove");

        // Setup the constraint System and synthesize the circuit
        let timer_circuit_setup = Timer::new("SNARK::Prove::Circuit Setup");
        let cs: gr1cs::ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        timer_circuit_setup.stop();
        let timer_synthesize_circuit = Timer::new("SNARK::Prove::Synthesize Circuit");
        circuit.generate_constraints(cs.clone())?;
        timer_synthesize_circuit.stop();

        let timer_inlining = Timer::new("SNARK::Prove::Inlining constraints");
        cs.finalize(true);
        timer_inlining.stop();
        let prover = cs.borrow().unwrap();

        // Extract the index (i), input (x), witness (w), and the full assignment z=(x||w) from the constraint system
        let timer_extract_i_x_w = Timer::new("SNARK::Prove::Extract i, x, w");
        let x_assignment: &[E::ScalarField] = &prover.instance_assignment()?;
        let w_assignment: &[E::ScalarField] = &prover.witness_assignment()?;
        let z_assignment: Vec<E::ScalarField> = [x_assignment, w_assignment].concat();
        let index: Index<E::ScalarField> = Index::new(&cs);
        timer_extract_i_x_w.stop();

        // initilizing the transcript
        let timer_init_transcript = Timer::new("SNARK::Prove::Initialize Transcript");
        let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
            IOPTranscript::<E::ScalarField>::new(b"Garuda-2024");
        let verifier_key: VerifyingKey<E> = proving_key.verifying_key.clone();
        transcript.append_serializable_element("vk".as_bytes(), &verifier_key);
        transcript.append_serializable_element("input".as_bytes(), &x_assignment[1..].to_vec());
        timer_init_transcript.stop();

        // Generate the w polynomials, i.e. w_i = M_i * (0||w) and z polynomials, i.e. z_i = M_i * z
        // Line 3-a figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_generate_w_z_polys = Timer::new("SNARK::Prove::Generate w, z Polynomials");
        let (w_polys, z_polys): (
            Vec<DenseMultilinearExtension<E::ScalarField>>,
            Vec<DenseMultilinearExtension<E::ScalarField>>,
        ) = Self::generate_w_z_polys(&index, &z_assignment);
        timer_generate_w_z_polys.stop();

        // EPC-Commit to the witness polynomials, i.e. generate c_i = EPC.Comm(w_i)
        // Line 3-b figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_epc_commit = Timer::new("SNARK::Prove::EPC Commit");
        let (individual_comms, consistency_comm) = epc_constrained_commit(
            &proving_key.group_params,
            &proving_key.consistency_pk,
            &w_polys,
            w_assignment,
        );
        timer_epc_commit.stop();

        // Append the commitments (individual and consistency) to the transcript
        let timer_append_trans = Timer::new("SNARK::Prove::Append Commitments to Transcript");
        transcript
            .append_serializable_element("individual_commitments".as_bytes(), &individual_comms);
        transcript
            .append_serializable_element("consistency_commitments".as_bytes(), &consistency_comm);
        timer_append_trans.stop();

        // Performing zero-check on the grand polynomial
        // Note that we use the z_polys here
        // Line 5 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_buid_grand_poly = Timer::new("SNARK::Prove::Build Grand Polynomial");
        let grand_poly: VirtualPolynomial<E::ScalarField> =
            Self::build_grand_poly(&z_polys, &proving_key.selector_pk, &index);
        timer_buid_grand_poly.stop();

        let timer_zero_check = Timer::new("SNARK::Prove::Zero Check");
        let zero_check_proof: IOPProof<E::ScalarField> = <PolyIOP<E::ScalarField> as ZeroCheck<
            E::ScalarField,
        >>::prove(
            &grand_poly, &mut transcript
        )
        .unwrap();
        timer_zero_check.stop();

        // Evaluate the selector and witness polynomials on the challenge point outputed by the zero-check
        // Line 7 of figure 7 of https://eprint.iacr.org/2024/1245.pdf

        let timer_eval_polys = Timer::new("SNARK::Prove::Evaluate Polynomials");
        let mut sel_poly_evals: Vec<E::ScalarField> = match index.num_predicates {
            1 => Vec::new(),
            _ => {
                let sel_poly_evals: Vec<E::ScalarField> = proving_key
                    .selector_pk
                    .iter()
                    .map(|selector| selector.evaluate(&zero_check_proof.point))
                    .collect();
                sel_poly_evals
            }
        };
        let w_poly_evals: Vec<E::ScalarField> = w_polys
            .iter()
            .map(|witness| witness.evaluate(&zero_check_proof.point))
            .collect();
        timer_eval_polys.stop();

        // Construct the set of all polynomials the corresponding commitments to be opened
        // We will batch-open these commitments
        // Note that selector polynomials are only present when there are more than one predicate
        let comms_to_be_opened: Vec<E::G1Affine> = individual_comms
            .clone()
            .into_iter()
            .chain(proving_key.verifying_key.selector_vk)
            .collect();

        let polys_to_be_opened: Vec<DenseMultilinearExtension<<E>::ScalarField>> = w_polys
            .clone()
            .into_iter()
            .chain(proving_key.selector_pk.clone())
            .collect();

        // open the commitments
        // Line 8 and 9 of figure 7 of https://eprint.iacr.org/2024/1245.pdf

        let timer_open_commitments = Timer::new("SNARK::Prove::Open Commitments");
        let opening_proof: Vec<E::G1Affine> = generate_opening_proof(
            &proving_key.group_params,
            &polys_to_be_opened,
            &comms_to_be_opened,
            &zero_check_proof.point,
        );
        timer_open_commitments.stop();

        // Construct the proof
        // Line 10 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let result = Ok(Proof {
            individual_comms,
            consistency_comm,
            zero_check_proof,
            sel_poly_evals,
            w_poly_evals,
            opening_proof,
            w_polys,
            sel_polys: proving_key.selector_pk,
        });

        timer_prove.stop();

        result
    }

    fn generate_w_z_polys(
        index: &Index<E::ScalarField>,
        z_assignment: &[E::ScalarField],
    ) -> (
        Vec<DenseMultilinearExtension<E::ScalarField>>,
        Vec<DenseMultilinearExtension<E::ScalarField>>,
    )
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut stacked_matrices: Vec<Matrix<E::ScalarField>> =
            vec![
                vec![Vec::new(); (2 as usize).pow(index.log_num_constraints as u32)];
                index.max_arity
            ];
        let mut num_of_previous_rows = 0;
        let label = R1CS_PREDICATE_LABEL;
        let matrices = index.predicate_matrices.get(label).unwrap();
        for (t, matrix_i_t) in matrices.iter().enumerate() {
            for (row_num, row) in matrix_i_t.iter().enumerate() {
                for (value, col) in row {
                    stacked_matrices[t][row_num + num_of_previous_rows].push((*value, *col));
                }
            }
        }
        num_of_previous_rows += index.predicate_num_constraints[label];

        for (_, (label, matrices)) in index.predicate_matrices.iter().enumerate() {
            if label != R1CS_PREDICATE_LABEL {
                for (t, matrix_i_t) in matrices.iter().enumerate() {
                    for (row_num, row) in matrix_i_t.iter().enumerate() {
                        for (value, col) in row {
                            stacked_matrices[t][row_num + num_of_previous_rows]
                                .push((*value, *col));
                        }
                    }
                }
                num_of_previous_rows += index.predicate_num_constraints[label];
            }
        }
        let mut pz: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        let mut pw: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        let mut i = 0;
        for matrix in stacked_matrices {
            let mz: Vec<E::ScalarField> = mat_vec_mul(&matrix, z_assignment);
            //TODO: Check this might be wrong
            let mut w_assignment: Vec<E::ScalarField> =
                vec![E::ScalarField::zero(); z_assignment.len()];
            w_assignment[index.instance_len..].copy_from_slice(&z_assignment[index.instance_len..]);
            let mw: Vec<E::ScalarField> = mat_vec_mul(&matrix, &w_assignment);
            pw.push(DenseMultilinearExtension::from_evaluations_vec(
                index.log_num_constraints,
                mw,
            ));
            pz.push(DenseMultilinearExtension::from_evaluations_vec(
                index.log_num_constraints,
                mz,
            ));
        }
        (pw, pz)
    }

    // A helper function to build the grand polynomial
    // On witness polys, selector polys, and the predicate poly (inside the index), output the grand polynomial
    fn build_grand_poly(
        z_polys: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        sel_polys: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        index: &Index<E::ScalarField>,
    ) -> VirtualPolynomial<E::ScalarField>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let z_arcs: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> =
            z_polys.iter().map(|item| Arc::new(item.clone())).collect();
        let mut target_virtual_poly: VirtualPolynomial<E::ScalarField> =
            VirtualPolynomial::new(index.log_num_constraints);

        // If there is only one predicate, The virtual poly is just L(mle(M_1z), mle(M_2z), ..., mle(M_tz)) without any selector
        if index.num_predicates == 1 {
            let predicate_poly = match index.predicate_types.values().next().unwrap().clone() {
                PredicateType::Polynomial(polynomial_predicate) => polynomial_predicate.polynomial,
                _ => unimplemented!("Only polynomial predicates are supported"),
            };
            &Self::build_grand_poly_single_pred(predicate_poly, &z_arcs, &mut target_virtual_poly);
            return target_virtual_poly;
        }

        // If there are multiple predicates, The virtual poly is the grand poly in line 5 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let sel_arcs: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = sel_polys
            .iter()
            .map(|item| Arc::new(item.clone()))
            .collect();

        for (c, (_, predicate_type)) in index.predicate_types.iter().enumerate() {
            let predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm> = match predicate_type
                .clone()
            {
                PredicateType::Polynomial(polynomial_predicate) => polynomial_predicate.polynomial,
                _ => unimplemented!("Only polynomial predicates are supported"),
            };
            &Self::build_grand_poly_multi_pred(
                predicate_poly,
                &sel_arcs[c],
                &z_arcs,
                &mut target_virtual_poly,
            );
        }
        target_virtual_poly
    }

    fn build_grand_poly_single_pred(
        predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm>,
        witness_poly_arcs: &Vec<Arc<DenseMultilinearExtension<E::ScalarField>>>,
        virtual_poly: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        for (coeff, term) in predicate_poly.terms {
            let mut mle_list: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = Vec::new();
            for (var, exponent) in term.iter() {
                for _ in 0..*exponent {
                    mle_list.push(Arc::clone(&witness_poly_arcs[*var]));
                }
            }
            virtual_poly.add_mle_list(mle_list, coeff);
        }
    }

    fn build_grand_poly_multi_pred(
        predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm>,
        selector_poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        witness_poly_arcs: &Vec<Arc<DenseMultilinearExtension<E::ScalarField>>>,
        virtual_poly: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        for (coeff, term) in predicate_poly.terms {
            let mut mle_list: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = Vec::new();
            mle_list.push(Arc::clone(&selector_poly));
            for (var, exponent) in term.iter() {
                for _ in 0..*exponent {
                    mle_list.push(Arc::clone(&witness_poly_arcs[*var]));
                }
            }
            virtual_poly.add_mle_list(mle_list, coeff);
        }
    }
}
