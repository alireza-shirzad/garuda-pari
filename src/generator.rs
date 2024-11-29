use std::time::{Duration, Instant};

use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, scalar_mul::BatchMulPreprocessing};
use ark_ff::{Field, Zero};
use ark_poly::{Polynomial, SparseMultilinearExtension};
use ark_poly_commit::{
    multilinear_pc::data_structures::{Commitment, CommitterKey, UniversalParams},
    Evaluations, PCCommitment,
};
pub use ark_relations::gr1cs::constraint_system::ConstraintSynthesizer;
use ark_relations::gr1cs::{
    index::Index, ConstraintSystem, Matrix, OptimizationGoal, SynthesisMode,
};
use ark_std::{
    cfg_into_iter,
    collections::BTreeMap,
    end_timer, format,
    marker::PhantomData,
    rand::RngCore,
    start_timer,
    string::{String, ToString},
    vec::{self, Vec},
};
use hp_arithmetic::DenseMultilinearExtension;

use crate::data_structures::{IndexInfo, ProverKey, VerifierKey};
use crate::{file_dbg, write_bench, Garuda};
use ark_poly_commit::multilinear_pc::MultilinearPC;
use ark_std::UniformRand;

impl<E> Garuda<E>
where
    E: Pairing,
{
    pub fn setup<R: RngCore, C: ConstraintSynthesizer<E::ScalarField>>(
        rng: &mut R,
        c: C,
    ) -> (ProverKey<E>, VerifierKey<E>)
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let index: Index<<E as Pairing>::ScalarField> = Self::extract_index(c);

        let t_max: usize = index.get_t_max();
        let v_total: usize = index.get_v_total();

        // println!("Creating SRS...");
        let mut setup_time: Duration = Duration::new(0, 0);
        let start: Instant = Instant::now();

        let (pst_srs, tau): (UniversalParams<E>, Vec<E::ScalarField>) =
            MultilinearPC::setup_inner(v_total, rng);

        let (pst_ck, pst_vk) = MultilinearPC::<E>::trim(&pst_srs, pst_srs.num_vars);

        let linking_challanges: Vec<E::ScalarField> =
            Self::create_consistency_challange(t_max, rng);

        let mut selector_pk: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        let mut selector_vk: Vec<Commitment<E>> = Vec::new();

        if index.c > 1 {
            selector_pk = Self::create_selector_polynomials(&index);
            selector_vk = Self::create_selector_commitments(&pst_ck, &selector_pk);
        }

        let linking_vk: Vec<E::G2> = linking_challanges
            .iter()
            .map(|alpha| pst_ck.h * (*alpha))
            .collect();

        let linking_srs =
            Self::create_linking_shifted_polynomials(&index, &pst_ck, tau, &linking_challanges);
        let (input_linking_check, witness_linking_check) = linking_srs.split_at(index.n);

        let linking_pk: Vec<E::G1Affine> = witness_linking_check.to_vec();
        let public_input_vk: Vec<E::G1Affine> = input_linking_check.to_vec();

        let vk: VerifierKey<E> = VerifierKey {
            index_info: IndexInfo {
                // num_variables: index.k,
                // num_instance_variables: index.n,
                v_total: index.get_v_total(),
                // t_max: index.get_t_max(),
                max_degree: index.get_max_degree(),
                num_predicates: index.c,
            },
            pst_vk,
            selector_vk,
            linking_vk,
            public_input_vk,
        };

        let pk: ProverKey<E> = ProverKey {
            index,
            pst_ck,
            linking_pk,
            selector_pk,
            vk: vk.clone(),
        };
        setup_time += start.elapsed();
        // std::println!("Setup time = {}", setup_time.as_millis());

        write_bench!("{} ", setup_time.as_millis());
        (pk, vk)
    }
    fn create_consistency_challange<R: RngCore>(t_max: usize, rng: &mut R) -> Vec<E::ScalarField>
    where
        E::ScalarField: Field,
    {
        (0..t_max).map(|_| E::ScalarField::rand(rng)).collect()
    }
    fn create_selector_polynomials(
        index: &Index<E::ScalarField>,
    ) -> Vec<DenseMultilinearExtension<E::ScalarField>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut selector_polynomials: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        let mut v_total: usize = index.get_v_total();
        let mut m_count = 0;
        for predicate in &index.predicates {
            let evaluations: Vec<E::ScalarField> = std::iter::repeat(E::ScalarField::zero())
                .take(m_count)
                .chain(std::iter::repeat(E::ScalarField::ONE).take(predicate.m))
                .chain(
                    std::iter::repeat(E::ScalarField::zero())
                        .take((2 as usize).pow(v_total as u32) - m_count - predicate.m),
                )
                .collect();
            let selector_poly =
                DenseMultilinearExtension::from_evaluations_vec(v_total, evaluations);
            selector_polynomials.push(selector_poly);
            m_count += predicate.m;
        }
        selector_polynomials
    }
    fn create_selector_commitments(
        pst_ck: &CommitterKey<E>,
        selector_polynomials: &Vec<DenseMultilinearExtension<E::ScalarField>>,
    ) -> Vec<Commitment<E>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut commitments: Vec<Commitment<E>> = Vec::new();
        for poly in selector_polynomials {
            let commitment: Commitment<E> = MultilinearPC::<E>::commit(pst_ck, poly);
            commitments.push(commitment);
        }
        commitments
    }

    pub fn create_linking_shifted_polynomials(
        index: &Index<E::ScalarField>,
        pst_ck: &CommitterKey<E>,
        tau: Vec<E::ScalarField>,
        linking_challanges: &Vec<E::ScalarField>,
    ) -> Vec<E::G1Affine>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let t_max: usize = index.get_t_max();
        let v_total: usize = index.get_v_total();

        let mut all_matrix_columns: Vec<BTreeMap<usize, E::ScalarField>> =
            vec![BTreeMap::new(); index.k];
        t_max;

        let mut num_of_previous_rows = 0;
        for (i, predicate) in index.predicates.iter().enumerate() {
            for (t, matrix_i_t) in predicate.matrices.iter().enumerate() {
                for (row_num, row) in matrix_i_t.iter().enumerate() {
                    for (value, col) in row {
                        all_matrix_columns[*col]
                            .entry(num_of_previous_rows + row_num)
                            .and_modify(|x| *x += value.clone() * linking_challanges[t])
                            .or_insert(value.clone() * linking_challanges[t]);
                    }
                }
            }
            num_of_previous_rows += predicate.m;
        }

        let mut column_challanges: Vec<E::ScalarField> = Vec::new();
        for j in 0..index.k {
            let column_evaluations: Vec<(usize, E::ScalarField)> =
                all_matrix_columns[j].clone().into_iter().collect();

            let column_poly: SparseMultilinearExtension<E::ScalarField> =
                SparseMultilinearExtension::from_evaluations(v_total, &column_evaluations);
            column_challanges.push(column_poly.evaluate(&tau));
        }
        let g1_table: BatchMulPreprocessing<E::G1> =
            BatchMulPreprocessing::new(pst_ck.g.into(), index.k);
        let a = g1_table.batch_mul(&column_challanges);
        a
    }

    fn add_vectors_in_place(a: &mut Vec<E::ScalarField>, b: &Vec<E::ScalarField>) {
        for (i, mut elem) in a.iter_mut().enumerate() {
            *elem += b[i];
        }
    }

    fn extract_index<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
    ) -> Index<E::ScalarField> {
        // Synthesize the circuit and extract the index struct
        let cs: ark_relations::gr1cs::ConstraintSystemRef<E::ScalarField> =
            ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit.generate_constraints(cs.clone()).unwrap();
        // std::dbg!(cs.num_constraints());
        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);
        cs.to_index().unwrap()
        // Now we have a handle to the index of the relation
    }
}
