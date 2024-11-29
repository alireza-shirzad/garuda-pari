use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly_commit::multilinear_pc::data_structures::{
    Commitment, CommitterKey as PST_Ck, Proof as PST_proof, VerifierKey as PST_Vk,
};
use ark_relations::gr1cs::{
    index::Index,
    predicate::{self, LocalPredicateType},
    Matrix,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use ark_std::{
    format,
    io::{Read, Write},
    marker::PhantomData,
};
use derivative::Derivative;
use hp_arithmetic::DenseMultilinearExtension;
use hp_subroutines::IOPProof;

#[derive(CanonicalSerialize)]
pub struct ProverKey<E>
where
    E: Pairing,
    E::ScalarField: Field,
{
    pub index: Index<E::ScalarField>,
    pub pst_ck: PST_Ck<E>,
    pub linking_pk: Vec<E::G1Affine>,
    pub selector_pk: Vec<DenseMultilinearExtension<E::ScalarField>>,
    pub vk: VerifierKey<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct VerifierKey<E: Pairing> {
    pub index_info: IndexInfo,
    pub pst_vk: PST_Vk<E>,
    pub selector_vk: Vec<Commitment<E>>,
    pub linking_vk: Vec<E::G2>,
    pub public_input_vk: Vec<E::G1Affine>,
}

#[derive(CanonicalSerialize)]
pub struct Proof<E: Pairing> {
    pub commitments: Vec<Commitment<E>>,
    pub linking_proof: E::G1,
    pub zero_check_proof: IOPProof<E::ScalarField>,
    pub selector_poly_openings: Vec<E::ScalarField>,
    pub witness_poly_openings: Vec<E::ScalarField>,
    pub opening_proof: PST_proof<E>,
}

#[derive(Clone, Debug, Derivative, CanonicalSerialize, CanonicalDeserialize)]
pub struct IndexInfo {
    /// The total number of variables in the constraint system.
    // pub num_variables: usize,
    /// The number of input elements.
    // pub num_instance_variables: usize,
    pub v_total: usize,
    // pub t_max: usize,
    pub max_degree: usize,
    pub num_predicates: usize,
}

pub struct StackedIndex<F: Field> {
    pub k: usize,
    pub m: usize,
    pub t: usize,
    pub c: usize,
    pub matrices: Vec<Matrix<F>>,
    pub predicates: Vec<(usize, LocalPredicateType<F>)>,
}

impl<F: Field> StackedIndex<F> {
    pub fn from_index(index: Index<F>) -> Self {
        let mut t: usize = 0;
        let mut m: usize = 0;
        let mut predicates: Vec<(usize, LocalPredicateType<F>)> = vec![];
        for predicate in &index.predicates {
            t = ark_std::cmp::max(t, predicate.t);
            m += predicate.m;
            predicates.push((predicate.m, predicate.predicate_type.clone()));
        }
        let mut matrices: Vec<Matrix<F>> = vec![Matrix::new(); t];
        for predicate in index.predicates {
            for j in 0..t {
                if j >= predicate.t {
                    matrices[j].extend(vec![vec![]; predicate.m])
                }
                matrices[j].extend(predicate.matrices[j].clone());
            }
        }
        Self {
            k: index.k,
            m,
            t,
            c: index.c,
            matrices,
            predicates,
        }
    }
}
