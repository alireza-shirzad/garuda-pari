use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_poly::Polynomial;
use ark_relations::gr1cs::Field;
#[allow(type_alias_bounds)]
/// Evaluations over {0,1}^n for G1
pub type EvaluationHyperCubeOnG1<E: Pairing> = Vec<E::G1Affine>;


#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MLPublicParameters<E: Pairing> {
    pub num_var: usize,
    pub num_constraints: usize,
    pub generators : Generators<E>,
}


#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub(crate) struct Generators<E: Pairing> {
    pub g: E::G1,
    pub h: E::G2,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MLCommitmentKey<E: Pairing> {
    /// number of variables
    pub nv: usize,
    /// pp_k defined by libra
    pub powers_of_g: Vec<EvaluationHyperCubeOnG1<E>>,
    /// generator for G1
    pub g: E::G1Affine,
    /// generator for G2
    pub h: E::G2Affine,
    pub consistency_pk:Vec<E::G1Affine>
}

/// Public Parameter used by prover
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MLVerifyingKey<E: Pairing> {
    /// number of variables
    pub nv: usize,
    /// generator of G1
    pub g: E::G1Affine,
    /// generator of G2
    pub h: E::G2Affine,
    /// g^t1, g^t2, ...
    pub h_mask_random: Vec<E::G2Affine>,
    pub consistency_vk: Vec<E::G2>,
}

/// Public Parameter used by prover
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MLTrapdoor<E: Pairing> {
    pub tau: Vec<E::ScalarField>,
    pub consistency_challanges: Vec<E::ScalarField>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
/// commitment
pub struct MLCommitment<E: Pairing> {
    /// number of variables
    pub nv: usize,
    /// product of g as described by the vRAM paper
    pub g_product: E::G1Affine,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
/// commitment
pub struct MLBatchedCommitment<E: Pairing> {
    pub individual_comms: Vec<MLCommitment<E>>,
    pub consistency_comm: Option<E::G1>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
/// proof of opening
pub struct MLProof<E: Pairing> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}

