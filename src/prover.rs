use std::time::{Duration, Instant};

use crate::data_structures::{IndexInfo, ProverKey, VerifierKey};
use crate::write_bench;
use crate::{data_structures::Proof, Garuda};
use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use ark_ff::{BigInt, Field, PrimeField, UniformRand, Zero};
use ark_poly::Polynomial;
use ark_poly_commit::multilinear_pc::data_structures::{
    Commitment, CommitterKey, Proof as PST_proof,
};
use ark_poly_commit::multilinear_pc::MultilinearPC;
use ark_relations::gr1cs::index::{self, Index};
use ark_relations::gr1cs::predicate::LocalPredicateType;
use ark_relations::gr1cs::{
    self, predicate, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_relations::utils::variable::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iterable::Iterable;
use ark_std::ops::Add;
use ark_std::rand::RngCore;
use ark_std::sync::Arc;
use ark_std::{end_timer, start_timer};
use hp_arithmetic::{DenseMultilinearExtension, VirtualPolynomial};
use hp_subroutines::{IOPProof, PolyIOP, ZeroCheck};
use hp_transcript::IOPTranscript;
impl<E> Garuda<E>
where
    E: Pairing,
{
    pub fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        rng: &mut R,
        circuit: C,
        pk: ProverKey<E>,
    ) -> Proof<E>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
        let mut prover_circuit_generation: Duration = Duration::new(0, 0);

        let start = Instant::now();

        // Synthesize the circuit.

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.generate_constraints(cs.clone());
        // cs.finalize();

        let prover = cs.borrow().unwrap();
        let input_assignment: &[E::ScalarField] = &prover.instance_assignment[1..];
        let aux_assignment: &Vec<E::ScalarField> = &prover.witness_assignment;
        let assignment: Vec<E::ScalarField> =
            [&prover.instance_assignment, &aux_assignment[..]].concat();

        prover_circuit_generation += start.elapsed();
        // std::println!("Prover circuit generation time = {}", prover_circuit_generation.as_millis());

        // println!("Creating proofs...");

        let mut total_proving: Duration = Duration::new(0, 0);

        let start = Instant::now();

        let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
            IOPTranscript::<E::ScalarField>::new(b"Garuda-2024");
        let verifier_key: VerifierKey<E> = pk.vk.clone();
        transcript.append_serializable_element("vk".as_bytes(), &verifier_key);
        transcript.append_serializable_element("input".as_bytes(), &input_assignment.to_vec());

        //////////////////////////////////////////////////////////////////////
        let witness_polynomials: Vec<DenseMultilinearExtension<E::ScalarField>> =
            Self::produce_witness_polynomials(&pk.index, &assignment);

        //////////////////////////////////////////////////////////////////////

        //////////////////////////////////////////////////////////////////////
        let commitments: Vec<Commitment<E>> =
            Self::produce_commitments(&pk.pst_ck, &witness_polynomials);

        //////////////////////////////////////////////////////////////////////
        transcript.append_serializable_element("commitments".as_bytes(), &commitments);

        //////////////////////////////////////////////////////////////////////
        let linking_proof: E::G1 = Self::produce_linking_proof(pk.linking_pk, &aux_assignment);

        //////////////////////////////////////////////////////////////////////

        transcript.append_serializable_element("linking_proof".as_bytes(), &linking_proof);

        //////////////////////////////////////////////////////////////////////
        let target_virtual_polynomial: VirtualPolynomial<E::ScalarField> =
            Self::build_target_virtual_polynomial(&witness_polynomials, &pk.selector_pk, &pk.index);
        let zero_check_proof: IOPProof<E::ScalarField> =
            <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(
                &target_virtual_polynomial,
                &mut transcript,
            )
            .unwrap();
        //////////////////////////////////////////////////////////////////////

        //////////////////////////////////////////////////////////////////////
        let mut selector_poly_openings: Vec<E::ScalarField> = Vec::new();

        if cs.num_local_predicates() > 1 {
            selector_poly_openings = pk
                .selector_pk
                .iter()
                .map(|selector| selector.evaluate(&zero_check_proof.point))
                .collect();
        }

        let witness_poly_openings: Vec<E::ScalarField> = witness_polynomials
            .iter()
            .map(|witness| witness.evaluate(&zero_check_proof.point))
            .collect();
        let mut all_commitments: Vec<Commitment<E>> = commitments.clone();
        let mut all_polynomials: Vec<DenseMultilinearExtension<<E as Pairing>::ScalarField>> =
            witness_polynomials.clone();
        if cs.num_local_predicates() > 1 {
            all_commitments.extend_from_slice(pk.vk.selector_vk.as_slice());
            all_polynomials.extend_from_slice(&pk.selector_pk);
        }

        let opening_proof: PST_proof<E> = Self::produce_opening_proof(
            &pk.pst_ck,
            &all_polynomials,
            all_commitments.as_slice(),
            &zero_check_proof.point,
        );
        // println!("{}",zero_check_proof.point.len());
        // println!("commitments= {}",commitments.serialized_size(ark_serialize::Compress::Yes));
        // println!("linking_proof = {}",linking_proof.serialized_size(ark_serialize::Compress::Yes));
        // println!("zero_check_proof = {}",zero_check_proof.serialized_size(ark_serialize::Compress::Yes));
        // println!("selector_poly_openings = {}",selector_poly_openings.serialized_size(ark_serialize::Compress::Yes));
        // println!("witness_poly_openings = {}",witness_poly_openings.serialized_size(ark_serialize::Compress::Yes));
        // println!("opening_proof = {}",opening_proof.serialized_size(ark_serialize::Compress::Yes));
        // println!("point= {}",zero_check_proof.point.serialized_size(ark_serialize::Compress::Yes));
        // println!("proofs= {}",zero_check_proof.proofs.serialized_size(ark_serialize::Compress::Yes));

        total_proving += start.elapsed();
        write_bench!("{} ", total_proving.as_millis());
        // std::println!("Proving time = {}", total_proving.as_millis());
        //////////////////////////////////////////////////////////////////////
        Proof {
            commitments,
            linking_proof,
            zero_check_proof,
            selector_poly_openings,
            witness_poly_openings,
            opening_proof,
        }
    }

    fn sanity_check(target_virtual_polynomial: &VirtualPolynomial<E::ScalarField>, v_total: usize)
    where
        E::ScalarField: std::convert::From<i32>,
    {
        for i in 0..(1 << v_total) {
            let mut vector = Vec::new();

            // Extract individual bits from the number i and push them to the vector
            for j in (0..v_total).rev() {
                vector.push(E::ScalarField::from((i >> j) & 1));
            }
            assert_eq!(
                target_virtual_polynomial.evaluate(&vector).unwrap(),
                E::ScalarField::zero()
            );
        }
    }

    fn produce_commitments(
        ck: &CommitterKey<E>,
        witness_polynomials: &Vec<DenseMultilinearExtension<E::ScalarField>>,
    ) -> Vec<Commitment<E>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut commitments: Vec<Commitment<E>> = Vec::new();
        for polynomial in witness_polynomials {
            let commitment: Commitment<E> = MultilinearPC::<E>::commit(&ck, polynomial);

            commitments.push(commitment);
        }
        commitments
    }

    fn produce_opening_proof(
        ck: &CommitterKey<E>,
        all_polynomials: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        commitments: &[Commitment<E>],
        point: &Vec<E::ScalarField>,
    ) -> PST_proof<E>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let proof: PST_proof<E> =
            MultilinearPC::<E>::batch_open(&ck, &all_polynomials, commitments, &point);
        proof
    }

    fn produce_linking_proof(
        linking_pk: Vec<E::G1Affine>,
        input_assignment: &[E::ScalarField],
    ) -> E::G1
    where
        E: Pairing,
        E::ScalarField: Field,
        E::G1: VariableBaseMSM,
    {
        E::G1::msm(&linking_pk[..], input_assignment).unwrap()
    }

    fn produce_witness_polynomials(
        index: &Index<E::ScalarField>,
        assignment: &[E::ScalarField],
    ) -> Vec<DenseMultilinearExtension<E::ScalarField>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let t_max: usize = index.get_t_max();
        let v_total: usize = index.get_v_total();
        let mut stacked_matrices: Vec<Matrix<E::ScalarField>> =
            vec![vec![Vec::new(); (2 as usize).pow(v_total as u32)]; t_max];
        let mut num_of_previous_rows = 0;
        for (i, predicate) in index.predicates.iter().enumerate() {
            for (t, matrix_i_t) in predicate.matrices.iter().enumerate() {
                for (row_num, row) in matrix_i_t.iter().enumerate() {
                    for (value, col) in row {
                        stacked_matrices[t][row_num + num_of_previous_rows].push((*value, *col));
                    }
                }
            }
            num_of_previous_rows += predicate.m;
        }

        let mut output: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        for matrix in stacked_matrices {
            let mz: Vec<E::ScalarField> = Self::matrix_vector_multiplication(&matrix, &assignment);
            output.push(DenseMultilinearExtension::from_evaluations_vec(v_total, mz));
        }
        output
    }

    //TODO: Put this function in the matrix module (First build a matrix module)
    fn matrix_vector_multiplication(
        matrix: &Matrix<E::ScalarField>,
        vector: &[E::ScalarField],
    ) -> Vec<E::ScalarField> {
        let mut output: Vec<E::ScalarField> = Vec::new();
        for row in matrix {
            let mut sum: E::ScalarField = E::ScalarField::zero();
            for (value, col) in row {
                sum += vector[*col] * value;
            }
            output.push(sum);
        }
        output
    }

    fn build_target_virtual_polynomial(
        witness_polynomials: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        selector_polynomials: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        index: &Index<E::ScalarField>,
    ) -> VirtualPolynomial<E::ScalarField>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let witness_arcs: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = witness_polynomials
            .iter()
            .map(|item| Arc::new(item.clone()))
            .collect();
        let mut selector_arcs: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = Vec::new();

        let v_total: usize = index.get_v_total();
        let mut target_virtual_polynomial: VirtualPolynomial<E::ScalarField> =
            VirtualPolynomial::new(v_total);

        if index.c == 1 {
            let predicate_polynomial: gr1cs::polynomial::Polynomial<E::ScalarField> =
                match index.predicates[0].predicate_type.clone() {
                    LocalPredicateType::Polynomial(p) => p,
                    _ => todo!(),
                };
            &Self::add_predicate_polynomial(
                v_total,
                predicate_polynomial,
                &witness_arcs,
                &mut target_virtual_polynomial,
            );
            return target_virtual_polynomial;
        }

        selector_arcs = selector_polynomials
            .iter()
            .map(|item| Arc::new(item.clone()))
            .collect();

        for (c, predicate) in index.predicates.iter().enumerate() {
            let predicate_polynomial: gr1cs::polynomial::Polynomial<E::ScalarField> =
                match predicate.predicate_type.clone() {
                    LocalPredicateType::Polynomial(p) => p,
                    _ => todo!(),
                };
            &Self::add_predicate_polynomials(
                v_total,
                predicate_polynomial,
                &selector_arcs[c],
                &witness_arcs,
                &mut target_virtual_polynomial,
            );
        }
        target_virtual_polynomial
    }

    fn add_predicate_polynomial(
        num_variables: usize,
        predicate_polynomial: gr1cs::polynomial::Polynomial<E::ScalarField>,
        witness_polynomial_arcs: &Vec<Arc<DenseMultilinearExtension<E::ScalarField>>>,
        virtual_polynomial: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        for term in predicate_polynomial.terms {
            let mut mle_list: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = Vec::new();
            for (i, exponent) in term.exponents.iter().enumerate() {
                for _ in 0..*exponent {
                    mle_list.push(Arc::clone(&witness_polynomial_arcs[i]));
                }
            }
            virtual_polynomial.add_mle_list(mle_list, term.coefficient);
        }
    }

    fn add_predicate_polynomials(
        num_variables: usize,
        predicate_polynomial: gr1cs::polynomial::Polynomial<E::ScalarField>,
        selector_polynomial: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        witness_polynomial_arcs: &Vec<Arc<DenseMultilinearExtension<E::ScalarField>>>,
        virtual_polynomial: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        for term in predicate_polynomial.terms {
            let mut mle_list: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = Vec::new();
            mle_list.push(Arc::clone(&selector_polynomial));
            for (i, exponent) in term.exponents.iter().enumerate() {
                for _ in 0..*exponent {
                    mle_list.push(Arc::clone(&witness_polynomial_arcs[i]));
                }
            }
            virtual_polynomial.add_mle_list(mle_list, term.coefficient);
        }
    }
}

// Jellyfish Repo --> Costume gate for the ellyptic curve
