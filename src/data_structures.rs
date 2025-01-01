use core::num;
use std::collections::BTreeMap;
use std::io::Read;

use crate::arithmetic::DenseMultilinearExtension;
use crate::piop::prelude::IOPProof;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::gr1cs::predicate::PredicateType;
use ark_relations::gr1cs::{ConstraintSystemRef, Label, Matrix};
use ark_serialize::SerializationError;
use ark_serialize::Validate;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_std::log2;
#[allow(type_alias_bounds)]
/// Evaluations over {0,1}^n for G1
pub type EvaluationHyperCubeOnG1<E: Pairing> = Vec<E::G1Affine>;

#[derive(CanonicalSerialize, Clone)]
pub struct ProvingKey<E>
where
    E: Pairing,
    E::ScalarField: Field,
{
    /// group parameters
    pub group_params: GroupParams<E>,
    pub consistency_pk: Vec<E::G1Affine>,
    pub selector_pk: Vec<DenseMultilinearExtension<E::ScalarField>>,
    pub verifying_key: VerifyingKey<E>,
}

#[derive(CanonicalSerialize, Clone, Debug)]
pub struct VerifyingKey<E: Pairing> {
    pub log_num_constraints: usize,
    pub predicate_max_deg: usize,
    pub num_predicates: usize,
    pub instance_len: usize,
    /// generator of G1
    pub g: E::G1Affine,
    /// generator of G2
    pub h: E::G2Affine,
    pub h_mask_random: Vec<E::G2Affine>,
    pub selector_vk: Vec<E::G1Affine>,
    pub consistency_vk: Vec<E::G2>,
    pub predicate_types: BTreeMap<Label, PredicateType<E::ScalarField>>,
}

#[derive(CanonicalSerialize, Clone)]
pub struct Proof<E: Pairing> {
    pub individual_comms: Vec<E::G1Affine>,
    pub consistency_comm: E::G1,
    pub zero_check_proof: IOPProof<E::ScalarField>,
    pub sel_poly_evals: Vec<E::ScalarField>,
    pub w_poly_evals: Vec<E::ScalarField>,
    pub opening_proof: Vec<E::G1Affine>,
    pub w_polys: Vec<DenseMultilinearExtension<E::ScalarField>>,
    pub sel_polys: Vec<DenseMultilinearExtension<E::ScalarField>>,
}

pub(crate) struct Index<F: Field> {
    pub instance_len: usize,
    pub num_constraints: usize,
    pub log_num_constraints: usize,
    pub witness_len: usize,
    pub total_variables_len: usize,
    pub num_predicates: usize,
    pub max_arity: usize,
    pub predicate_max_deg: usize,
    pub predicate_arities: BTreeMap<Label, usize>,
    pub predicate_num_constraints: BTreeMap<Label, usize>,
    pub predicate_matrices: BTreeMap<Label, Vec<Matrix<F>>>,
    pub predicate_types: BTreeMap<Label, PredicateType<F>>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub(crate) struct GroupParams<E: Pairing> {
    pub g: E::G1,
    pub h: E::G2,
    pub g_affine: E::G1Affine,
    pub h_affine: E::G2Affine,
    pub powers_of_g: Vec<Vec<E::G1Affine>>,
    pub h_mask_random: Vec<E::G2Affine>,
}

impl<E: Pairing> GroupParams<E> {
    pub fn new(
        g: E::G1,
        h: E::G2,
        g_affine: E::G1Affine,
        h_affine: E::G2Affine,
        powers_of_g: Vec<Vec<E::G1Affine>>,
        h_mask_random: Vec<E::G2Affine>,
    ) -> Self {
        Self {
            g,
            h,
            g_affine,
            h_affine,
            powers_of_g,
            h_mask_random,
        }
    }
}

impl<F: Field> Index<F> {
    pub fn new(constraint_system_ref: &ConstraintSystemRef<F>) -> Self {
        let num_constraints: usize = constraint_system_ref.num_constraints();
        let predicate_types = constraint_system_ref.get_predicate_types();
        let predicate_max_deg = Self::get_max_degree(&predicate_types);
        let predicate_arities = constraint_system_ref.get_predicate_arities();
        Self {
            instance_len: constraint_system_ref.num_instance_variables(),
            num_constraints,
            log_num_constraints: log2(num_constraints) as usize,
            witness_len: constraint_system_ref.num_witness_variables(),
            total_variables_len: constraint_system_ref.num_instance_variables()
                + constraint_system_ref.num_witness_variables(),
            num_predicates: constraint_system_ref.num_predicates(),
            max_arity: *predicate_arities.values().max().unwrap(),
            predicate_arities,
            predicate_num_constraints: constraint_system_ref.get_predicate_num_constraints(),
            predicate_types,
            predicate_max_deg,
            //TODO: Unwrap?
            predicate_matrices: constraint_system_ref.to_matrices().unwrap(),
        }
    }

    fn get_max_degree(predicate_types: &BTreeMap<Label, PredicateType<F>>) -> usize {
        let mut predicates_max_degree: usize = 0;
        for (_, predicate_type) in predicate_types {
            let predicate_degree: usize = match predicate_type {
                PredicateType::Polynomial(ref poly) => poly.degree(),
                _ => panic!("Only polynomial predicates are supported"),
            };
            predicates_max_degree = ark_std::cmp::max(predicates_max_degree, predicate_degree);
        }

        predicates_max_degree
    }
}

// pub struct StackedIndex<F: Field> {
//     pub k: usize,
//     pub m: usize
//     pub t: usize,
//     pub c: usize,
//     pub matrices: Vec<Matrix<F>>,
//     pub predicates: Vec<(usize, LocalPredicateType<F>)>,
// }

// impl<F: Field> StackedIndex<F> {
//     pub fn from_index(index: Index<F>) -> Self {
//         let mut t: usize = 0;
//         let mut m: usize = 0;
//         let mut predicates: Vec<(usize, LocalPredicateType<F>)> = vec![];
//         for predicate in &index.predicates {
//             t = ark_std::cmp::max(t, predicate.t);
//             m += predicate.m;
//             predicates.push((predicate.m, predicate.predicate_type.clone()));
//         }
//         let mut matrices: Vec<Matrix<F>> = vec![Matrix::new(); t];
//         for predicate in index.predicates {
//             for j in 0..t {
//                 if j >= predicate.t {
//                     matrices[j].extend(vec![vec![]; predicate.m])
//                 }
//                 matrices[j].extend(predicate.matrices[j].clone());
//             }
//         }
//         Self {
//             k: index.k,
//             m,
//             t,
//             c: index.c,
//             matrices,
//             predicates,
//         }
//     }
// }
