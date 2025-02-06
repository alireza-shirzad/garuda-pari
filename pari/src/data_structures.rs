use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::gr1cs::{
    predicate::PredicateType, ConstraintSystem, ConstraintSystemRef, Label, Matrix,
};
use ark_serialize::CanonicalSerialize;
use ark_std::log2;
use std::collections::BTreeMap;

/// The proving key for Pari
/// The naming matches the one in the figure 6, item 8 of the paper: https://eprint.iacr.org/2024/1245.pdf
#[derive(CanonicalSerialize, Clone)]
pub struct ProvingKey<E>
where
    E: Pairing,
    E::ScalarField: Field,
{
    pub sigma: Vec<E::G1Affine>,
    pub sigma_a: Vec<E::G1Affine>,
    pub sigma_b: Vec<E::G1Affine>,
    pub sigma_q_comm: Vec<E::G1Affine>,
    pub sigma_q_opening: Vec<E::G1Affine>,
    pub verifying_key: VerifyingKey<E>,
}

/// The verifying key for GARUDA
#[derive(CanonicalSerialize, Clone, Debug)]
pub struct VerifyingKey<E: Pairing> {
    pub succinct_index: SuccinctIndex,
    pub alpha_g: E::G1,
    pub beta_g: E::G1,
    pub delta_one_h: E::G2,
    pub delta_two_h: E::G2,
    pub tau_h: E::G2,
    pub delta_one_tau_h: E::G2,
    pub g: E::G1,
    pub h: E::G2,
}

/// The succinct index for GARUDA
/// This contains enough information from the GR1CS to verify the proof
#[derive(CanonicalSerialize, Clone, Debug)]
pub struct SuccinctIndex {
    /// The log of number of constraints rounded up, will be translated to the number of variables in the ml extensions
    pub num_constraints: usize,
    /// The length of the instance variables
    pub instance_len: usize,
}

#[derive(Debug, Clone)]
/// A datastructure representing the index of the Square Rank 1 Constraint System (SR1CS)
pub(crate) struct Index<F: Field> {
    pub instance_len: usize,
    pub log_num_constraints: usize,
    pub total_variables_len: usize,
    pub a_matrice: Matrix<F>,
    pub b_matrice: Matrix<F>,
}

impl<F: Field> Index<F> {
    pub fn new(constraint_system_ref: &ConstraintSystem<F>) -> Self {
        //TODO: Get the SR1CS matrices from the constraint system
        Self {
            instance_len: constraint_system_ref.num_instance_variables(),
            log_num_constraints: log2(constraint_system_ref.num_constraints()) as usize,
            total_variables_len: constraint_system_ref.num_instance_variables()
                + constraint_system_ref.num_witness_variables(),
            a_matrice: todo!(),
            b_matrice: todo!(),
        }
    }
}

#[derive(CanonicalSerialize, Clone)]
pub struct Proof<E: Pairing> {
    pub t_g: E::G1Affine,
    pub u_g: E::G1Affine,
    pub v_a: E::ScalarField,
    pub v_b: E::ScalarField,
}
