use std::collections::BTreeMap;

use crate::{
    arithmetic::DenseMultilinearExtension,
    epc::data_structures::{MLBatchedCommitment, MLCommitmentKey, MLVerifyingKey},
    piop::prelude::IOPProof,
};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::{
    gr1cs::{predicate::Predicate, ConstraintSystem, Label, Matrix},
    utils::IndexMap,
};
use ark_serialize::CanonicalSerialize;
use ark_std::log2;

/// The proving key for GARUDA
#[derive(CanonicalSerialize, Clone)]
pub struct ProvingKey<E>
where
    E: Pairing,
    E::ScalarField: Field,
{
    /// The commitment key for the multlinear EPC
    pub epc_ck: MLCommitmentKey<E>,
    /// The selector polynomials, if there is a signle predicate, there is nothing to select, then this is None
    pub sel_polys: Option<Vec<DenseMultilinearExtension<E::ScalarField>>>,
    /// A copy of the Garuda verificatyion key
    pub verifying_key: VerifyingKey<E>,
}

/// The verifying key for GARUDA
#[derive(CanonicalSerialize, Clone, Debug)]
pub struct VerifyingKey<E: Pairing> {
    /// The succinct index, enough information from GR1CS to verify the proof
    pub succinct_index: SuccinctIndex<E>,
    /// Commitments to the selectors, if there is a single predicate, there is nothing to select, then this is None
    pub sel_batched_comm: Option<MLBatchedCommitment<E>>,
    /// The verification key for the multilinear EPC
    pub epc_vk: MLVerifyingKey<E>,
}

/// The succinct index for GARUDA
/// This contains enough information from the GR1CS to verify the proof
#[derive(CanonicalSerialize, Clone, Debug)]
pub struct SuccinctIndex<E: Pairing> {
    /// The log of number of constraints rounded up, will be translated to the number of variables in the ml extensions
    pub log_num_constraints: usize,
    /// The maximum degree of the predicates, assuming that all the predicate are polynomial predicates
    pub predicate_max_deg: usize,
    /// The maximum arity of the predicates, will be translated to the number of stacked matrices
    pub max_arity: usize,
    /// The number of predicates in the constraint system
    pub num_predicates: usize,
    /// The length of the instance variables
    pub instance_len: usize,
    /// The predicate types
    pub predicate_types: BTreeMap<Label, Predicate<E::ScalarField>>,
    /// The number of r1cs constraints
    pub r1cs_num_constraints: usize,
}

#[derive(CanonicalSerialize, Clone)]
pub struct Proof<E: Pairing> {
    /// Batched EPC commitment to ML-extension of M1.w, M2.w, ..., Mt.w where t:max_arity and M1, M2, ..., Mt are the stacked matrices
    pub w_batched_comm: MLBatchedCommitment<E>,
    /// Zero-Check PIOP proof for the grand polynomial
    pub zero_check_proof: IOPProof<E::ScalarField>,
    /// Evaluation of the selector polynomials on the random point outputed by the zerocheck
    pub sel_poly_evals: Option<Vec<E::ScalarField>>,
    /// Evaluation of the w polynomials on the random point outputed by the zerocheck
    pub w_poly_evals: Vec<E::ScalarField>,
    /// A bathced opening proof for the w polynomials and the selector polynomials on the random point outputed by the zerocheck
    pub batched_opening_proof: Vec<E::G1Affine>,
}

#[derive(Debug, Clone)]
/// A datastructure representing the index of the Generalized rank1 constraint system (GR1CS)
pub struct Index<F: Field> {
    /// The number of instance variables
    pub instance_len: usize,
    /// The log of the number of constraints rounded up
    pub log_num_constraints: usize,
    /// The total number of variables, instance variables + witness variables
    pub total_variables_len: usize,
    /// The number of predicates
    pub num_predicates: usize,
    /// The maximum arity of the predicates
    pub max_arity: usize,
    /// The maximum degree of the predicates, assuming that all the predicate are polynomial predicates
    pub predicate_max_deg: usize,
    /// The individual number of constraints of the predicates
    pub predicate_num_constraints: IndexMap<Label, usize>,
    /// The matrices of the predicates
    pub predicate_matrices: BTreeMap<Label, Vec<Matrix<F>>>,
    /// The types of the predicates
    pub predicate_types: BTreeMap<Label, Predicate<F>>,
}

impl<F: Field> Index<F> {
    pub fn new(constraint_system_ref: &ConstraintSystem<F>) -> Self {
        let predicate_types = constraint_system_ref.get_all_predicate_types();
        let predicate_max_deg = Self::get_max_degree(&predicate_types);
        Self {
            instance_len: constraint_system_ref.num_instance_variables(),
            log_num_constraints: log2(constraint_system_ref.num_constraints()) as usize,
            total_variables_len: constraint_system_ref.num_instance_variables()
                + constraint_system_ref.num_witness_variables(),
            num_predicates: constraint_system_ref.num_predicates(),
            max_arity: *constraint_system_ref
                .get_all_predicate_arities()
                .values()
                .max()
                .unwrap(),
            predicate_num_constraints: constraint_system_ref.get_all_predicates_num_constraints(),
            predicate_types,
            predicate_max_deg,
            predicate_matrices: constraint_system_ref.to_matrices().unwrap(),
        }
    }

    fn get_max_degree(predicate_types: &BTreeMap<Label, Predicate<F>>) -> usize {
        let mut predicates_max_degree: usize = 0;
        for predicate_type in predicate_types.values() {
            let predicate_degree: usize = match predicate_type {
                Predicate::Polynomial(ref poly) => poly.degree(),
                _ => panic!("Only polynomial predicates are supported"),
            };
            predicates_max_degree = ark_std::cmp::max(predicates_max_degree, predicate_degree);
        }

        predicates_max_degree
    }
}
