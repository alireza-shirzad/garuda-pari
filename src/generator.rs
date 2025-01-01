use std::{
    collections::LinkedList,
    time::{Duration, Instant},
};

use ark_ec::{
    pairing::Pairing, scalar_mul::BatchMulPreprocessing, CurveGroup, ScalarMul, VariableBaseMSM,
};
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{MultilinearExtension, Polynomial, SparseMultilinearExtension};

use crate::{
    arithmetic::DenseMultilinearExtension,
    data_structures::{GroupParams, Index},
    timer::{self, Timer},
    utils::epc_unconstrained_commit,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, Label, OptimizationGoal, SynthesisMode,
};
use ark_std::{
    collections::BTreeMap,
    end_timer, format, log2,
    rand::RngCore,
    start_timer,
    string::{String, ToString},
    vec::Vec,
};

use crate::data_structures::{ProvingKey, VerifyingKey};
use crate::{write_bench, Garuda};
use ark_std::UniformRand;

impl<E> Garuda<E>
where
    E: Pairing,
{
    pub fn keygen<R: RngCore, C: ConstraintSynthesizer<E::ScalarField>>(
        c: C,
        rng: &mut R,
    ) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let timer_generator: Timer = Timer::new("SNARK::Generator");
        // Synthesize the circuit and create a constraint system, Then finally extract the informations needed to the index

        let constraint_system_ref = ConstraintSystem::new_ref();
        constraint_system_ref.set_optimization_goal(OptimizationGoal::Constraints);
        constraint_system_ref.set_mode(SynthesisMode::Setup);

        let timer_synthesis = Timer::new("SNARK::Generator::Circuit Synthesis");
        c.generate_constraints(constraint_system_ref.clone());
        timer_synthesis.stop();
        constraint_system_ref.finalize(true);

        let index = Index::new(&constraint_system_ref);
        let timer_inlining = Timer::new("SNARK::Generator::Inlining");
        constraint_system_ref.finalize(true);
        timer_inlining.stop();

        // Generate the trapdoors
        let timer_trapdoor = Timer::new("SNARK::Generator::Trapdoor Generation");
        let tau: Vec<E::ScalarField> = (0..index.log_num_constraints)
            .map(|_| E::ScalarField::rand(rng))
            .collect();
        let consistency_challanges: Vec<E::ScalarField> = (0..index.max_arity)
            .map(|_| E::ScalarField::rand(rng))
            .collect();
        timer_trapdoor.stop();

        // Generate the groups parameters
        let timer_powers_of_tau = Timer::new("SNARK::Generator::Generatingpowers of tau");
        let group_params: GroupParams<E> =
            Self::generate_group_params(&tau, index.log_num_constraints, rng);
        timer_powers_of_tau.stop();

        // Generate the selector polynomials, If there is only one predicate, then there is no need for selector polynomials, returns None
        let timer_selector = Timer::new("SNARK::Generator::Generating Selector PK and VK");
        let selector_pk_vk = Self::generate_selector_pk_vk(&index, &group_params);
        let (selector_pk, selector_vk) = match selector_pk_vk {
            Some((pk, vk)) => (pk, vk),
            None => (Vec::new(), Vec::new()),
        };
        timer_selector.stop();

        // Generate the consistency pk and vk
        let timer_consistency = Timer::new("SNARK::Generator::Generating Consistency PK and VK");
        let (consistency_pk, consistency_vk) = Self::generate_consistency_pk_vk(
            &index,
            &group_params,
            tau.clone(),
            &consistency_challanges,
        );
        timer_consistency.stop();

        // Generate the Garuda proving and verifying keys
        let timer_key_generation =
            Timer::new("SNARK::Generator::Generating Proving and Verifying keys");
        let vk: VerifyingKey<E> = VerifyingKey {
            log_num_constraints: index.log_num_constraints,
            instance_len: index.instance_len,
            predicate_max_deg: index.predicate_max_deg,
            num_predicates: index.num_predicates,
            g: group_params.g_affine,
            h: group_params.h_affine,
            h_mask_random: group_params.h_mask_random.clone(),
            selector_vk,
            consistency_vk,
            predicate_types: index.predicate_types.clone(),
        };

        let pk: ProvingKey<E> = ProvingKey {
            group_params,
            consistency_pk,
            selector_pk,
            verifying_key: vk.clone(),
        };

        timer_key_generation.stop();
        timer_generator.stop();

        (pk, vk)
    }

    fn create_selector_polynomials(
        num_vars: usize,
        predicate_num_constraints: &BTreeMap<Label, usize>,
    ) -> Vec<DenseMultilinearExtension<E::ScalarField>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut selector_polynomials: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        let mut m_count = 0;
        for m in predicate_num_constraints.values() {
            let evaluations: Vec<E::ScalarField> = std::iter::repeat(E::ScalarField::zero())
                .take(m_count)
                .chain(std::iter::repeat(E::ScalarField::ONE).take(*m))
                .chain(
                    std::iter::repeat(E::ScalarField::zero())
                        .take((2 as usize).pow(num_vars as u32) - m_count - m),
                )
                .collect();
            let selector_poly =
                DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);
            selector_polynomials.push(selector_poly);
            m_count += m;
        }
        selector_polynomials
    }
    fn create_selector_commitments(
        group_params: &GroupParams<E>,
        selector_polynomials: &Vec<DenseMultilinearExtension<E::ScalarField>>,
    ) -> Vec<E::G1Affine>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut commitments: Vec<E::G1Affine> = Vec::new();
        for poly in selector_polynomials {
            let commitment: E::G1Affine = epc_unconstrained_commit(&group_params, poly);
            commitments.push(commitment);
        }
        commitments
    }

    pub fn generate_consistency_pk_vk(
        index: &Index<E::ScalarField>,
        group_params: &GroupParams<E>,
        tau: Vec<E::ScalarField>,
        consistency_challanges: &Vec<E::ScalarField>,
    ) -> (Vec<E::G1Affine>, Vec<E::G2>)
    where
        E: Pairing,
        E::ScalarField: Field,
    {
                // TODO: Optimize this, do we need to do the random linear combinations on the evaluations? Can't we just do it on the final polynomial evaluation on tau?
        let consistency_vk = consistency_challanges
            .iter()
            .map(|alpha| group_params.h * (*alpha))
            .collect();

        let mut all_matrix_columns: Vec<BTreeMap<usize, E::ScalarField>> =
            vec![BTreeMap::new(); index.total_variables_len];

        let mut num_of_previous_rows = 0;
        for (i, (label, predicate_matrices)) in index.predicate_matrices.iter().enumerate() {
            for (t, matrix_i_t) in predicate_matrices.iter().enumerate() {
                for (row_num, row) in matrix_i_t.iter().enumerate() {
                    for (value, col) in row {
                        all_matrix_columns[*col]
                            .entry(num_of_previous_rows + row_num)
                            .and_modify(|x| *x += value.clone() * consistency_challanges[t])
                            .or_insert(value.clone() * consistency_challanges[t]);
                    }
                }
            }
            num_of_previous_rows += index.predicate_num_constraints[label];
        }

        let mut column_challanges: Vec<E::ScalarField> = Vec::new();
        for j in 0..index.total_variables_len {
            let column_evaluations: Vec<(usize, E::ScalarField)> =
                all_matrix_columns[j].clone().into_iter().collect();

            let column_poly: SparseMultilinearExtension<E::ScalarField> =
                SparseMultilinearExtension::from_evaluations(
                    index.log_num_constraints,
                    &column_evaluations,
                );
            column_challanges.push(column_poly.evaluate(&tau));
        }
        let g1_table: BatchMulPreprocessing<E::G1> =
            BatchMulPreprocessing::new(group_params.g, index.total_variables_len);
        let consistency_pk = g1_table.batch_mul(&column_challanges);
        //TODO: Fix this to_vec()
        (consistency_pk[index.instance_len..].to_vec(), consistency_vk)
    }

    fn add_vectors_in_place(a: &mut Vec<E::ScalarField>, b: &Vec<E::ScalarField>) {
        for (i, mut elem) in a.iter_mut().enumerate() {
            *elem += b[i];
        }
    }

    fn generate_selector_pk_vk(
        index: &Index<E::ScalarField>,
        group_params: &GroupParams<E>,
    ) -> Option<(
        Vec<DenseMultilinearExtension<E::ScalarField>>,
        Vec<E::G1Affine>,
    )> {
        if index.num_predicates < 1 {
            return None;
        }
        let selector_pk: Vec<DenseMultilinearExtension<E::ScalarField>> =
            Self::create_selector_polynomials(
                index.log_num_constraints,
                &index.predicate_num_constraints,
            );
        let selector_vk: Vec<E::G1Affine> =
            Self::create_selector_commitments(&group_params, &selector_pk);
        Some((selector_pk, selector_vk))
    }

    fn generate_group_params<R: RngCore>(
        tau: &[E::ScalarField],
        num_vars: usize,
        rng: &mut R,
    ) -> GroupParams<E> {
        assert!(num_vars > 0, "constant polynomial not supported");
        let (g, h) = (E::G1::rand(rng), E::G2::rand(rng));
        let mut powers_of_g = Vec::new();
        let mut eq: LinkedList<DenseMultilinearExtension<E::ScalarField>> =
            LinkedList::from_iter(Self::eq_extension(&tau).into_iter());
        let mut eq_arr = LinkedList::new();
        let mut base = eq.pop_back().unwrap().evaluations;

        for i in (0..num_vars).rev() {
            eq_arr.push_front(Self::remove_dummy_variable(&base, i));
            if i != 0 {
                let mul = eq.pop_back().unwrap().evaluations;
                base = base
                    .into_iter()
                    .zip(mul.into_iter())
                    .map(|(a, b)| a * &b)
                    .collect();
            }
        }

        let mut pp_powers = Vec::new();
        for i in 0..num_vars {
            let eq = eq_arr.pop_front().unwrap();
            let pp_k_powers = (0..(1 << (num_vars - i))).map(|x| eq[x]);
            pp_powers.extend(pp_k_powers);
        }

        let g_table = BatchMulPreprocessing::new(g, num_vars);
        let h_table = BatchMulPreprocessing::new(h, num_vars);
        let pp_g = g_table.batch_mul(&pp_powers);
        let mut start = 0;
        for i in 0..num_vars {
            let size = 1 << (num_vars - i);
            let pp_k_g = (&pp_g[start..(start + size)]).to_vec();
            powers_of_g.push(pp_k_g);
            start += size;
        }
        let h_mask = h_table.batch_mul(&tau);

        GroupParams::new(g, h, g.into_affine(), h.into_affine(), powers_of_g, h_mask)
    }

    /// fix first `pad` variables of `poly` represented in evaluation form to zero
    fn remove_dummy_variable<F: Field>(poly: &[F], pad: usize) -> Vec<F> {
        if pad == 0 {
            return poly.to_vec();
        }
        if !poly.len().is_power_of_two() {
            panic!("Size of polynomial should be power of two. ")
        }
        let nv = ark_std::log2(poly.len()) as usize - pad;
        let table: Vec<_> = (0..(1 << nv)).map(|x| poly[x << pad]).collect();
        table
    }

    /// generate eq(t,x), a product of multilinear polynomials with fixed t.
    /// eq(a,b) is takes extensions of a,b in {0,1}^num_vars such that if a and b in {0,1}^num_vars are equal
    /// then this polynomial evaluates to 1.
    fn eq_extension<F: Field>(t: &[F]) -> Vec<DenseMultilinearExtension<F>> {
        let dim = t.len();
        let mut result = Vec::new();
        for i in 0..dim {
            let mut poly = Vec::with_capacity(1 << dim);
            for x in 0..(1 << dim) {
                let xi = if x >> i & 1 == 1 { F::one() } else { F::zero() };
                let ti = t[i];
                let ti_xi = ti * xi;
                poly.push(ti_xi + ti_xi - xi - ti + F::one());
            }
            result.push(DenseMultilinearExtension::from_evaluations_vec(dim, poly));
        }

        result
    }
}
