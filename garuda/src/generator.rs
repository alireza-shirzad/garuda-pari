use ark_ec::pairing::Pairing;
use ark_ff::{Field, Zero};
use ark_poly::SparseMultilinearExtension;
use ark_poly_commit::{marlin_pst13_pc::MarlinPST13, PolynomialCommitment};
use rayon::iter::repeatn;
use std::rc::Rc;

use crate::{
    arithmetic::DenseMultilinearExtension as DenseMLE,
    data_structures::{Index, ProvingKey, SuccinctIndex, VerifyingKey},
    epc::{
        data_structures::{Generators, MLBatchedCommitment, MLCommitmentKey, MLPublicParameters},
        multilinear::MultilinearEPC,
        EPC,
    },
    utils::stack_matrices,
    Garuda,
};
use ark_relations::{
    gr1cs::{
        self,
        instance_outliner::{outline_r1cs, InstanceOutliner},
        transpose, ConstraintSynthesizer, ConstraintSystem, Label, Matrix, OptimizationGoal,
        SynthesisError, SynthesisMode, R1CS_PREDICATE_LABEL,
    },
    lc,
    utils::IndexMap,
};
use ark_std::{
    cfg_iter, end_timer,
    rand::{rngs::ThreadRng, RngCore},
    start_timer,
    vec::Vec,
    UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

impl<E: Pairing> Garuda<E> {
    pub fn keygen<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        zk: bool,
        mut rng: impl RngCore,
    ) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let timer_generator = start_timer!(|| "Generator");

        // Start up the constraint system and synthesize the circuit
        let timer_indexer = start_timer!(|| "Constraint System Startup");
        let mut index = Self::circuit_to_keygen_cs(circuit, zk).unwrap();
        end_timer!(timer_indexer);

        // Generate the public parameters for the multilinear EPC
        let timer_epc_startup = start_timer!(|| "EPC Startup");
        let generators = Generators {
            g: E::G1::rand(&mut rng),
            h: E::G2::rand(&mut rng),
        };
        let epc_pp = MLPublicParameters {
            num_var: index.log_num_constraints,
            num_constraints: index.max_arity,
            generators,
        };

        let timer_epc_equif_constrs_gen = start_timer!(|| "Generating Equifficient Constraints");
        let equifficient_constrinats: Vec<Vec<SparseMultilinearExtension<E::ScalarField>>> =
            Self::build_equifficient_constraints(&mut index);
        end_timer!(timer_epc_equif_constrs_gen);
        let timer_epc_keys = start_timer!(|| "Generating EPC Keys");
        let hiding_bound = match zk {
            true => Some(1),
            false => None,
        };
        let (epc_ck, epc_vk, _epc_tr) =
            MultilinearEPC::<E>::setup(&mut rng, &epc_pp, hiding_bound, &equifficient_constrinats);
        end_timer!(timer_epc_keys);
        end_timer!(timer_epc_startup);

        // Generate the selector polynomials, If there is only one predicate, then there is no need for selector polynomials, returns None
        let timer_selector = start_timer!(|| "Generating Selector PK and VK");
        let (sel_polys, sel_batched_comm) = Self::compute_sel_pk_vk(&index, &epc_ck);
        end_timer!(timer_selector);

        // Generate the Garuda proving and verifying keys
        let timer_key_generation = start_timer!(|| "Generating Proving and Verifying keys");

        let succinct_index = SuccinctIndex {
            log_num_constraints: index.log_num_constraints,
            predicate_max_deg: index.predicate_max_deg,
            max_arity: index.max_arity,
            num_predicates: index.num_predicates,
            instance_len: index.instance_len,
            predicate_types: index.predicate_types.clone(),
            r1cs_num_constraints: index.predicate_num_constraints[R1CS_PREDICATE_LABEL],
        };

        // If it's zk, generate the commitment keys for the sumcheck masking polynomials

        let (mask_ck, mask_vk) = if zk {
            let max_degree = succinct_index.predicate_max_deg
                + match succinct_index.num_predicates {
                    1 => 0,
                    _ => 1,
                };
            let num_vars = succinct_index.log_num_constraints;
            let masking_pp = MarlinPST13::setup(max_degree, Some(num_vars), &mut rng).unwrap();
            let masking_ck_vk =
                MarlinPST13::trim(&masking_pp, max_degree, max_degree, None).unwrap();
            (Some(masking_ck_vk.0), Some(masking_ck_vk.1))
        } else {
            (None, None)
        };

        let vk: VerifyingKey<E> = VerifyingKey {
            sel_batched_comm,
            epc_vk,
            succinct_index,
            mask_vk
        };

        let pk: ProvingKey<E> = ProvingKey {
            sel_polys,
            verifying_key: vk.clone(),
            epc_ck,
            mask_ck,
        };

        end_timer!(timer_key_generation);
        end_timer!(timer_generator);

        (pk, vk)
    }

    pub fn circuit_to_keygen_cs<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        zk: bool,
    ) -> Result<Index<E::ScalarField>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
        const ZK_BOUND: usize = 5;
        // Start up the constraint System and synthesize the circuit
        let timer_cs_startup = start_timer!(|| "Constraint System Startup");
        let cs: gr1cs::ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        cs.set_instance_outliner(InstanceOutliner {
            pred_label: R1CS_PREDICATE_LABEL.to_string(),
            func: Rc::new(outline_r1cs),
        });
        let timer_synthesize_circuit = start_timer!(|| "Synthesize Circuit");
        circuit.generate_constraints(cs.clone())?;
        end_timer!(timer_synthesize_circuit);

        if zk {
            let timer_zk = start_timer!(|| "ZK Setup");
            for i in 0..ZK_BOUND {
                cs.new_witness_variable(|| Ok(E::ScalarField::from(i as i32)))?;
                cs.enforce_r1cs_constraint(lc!(), lc!(), lc!())?;
            }
            end_timer!(timer_zk);
        }

        let timer_inlining = start_timer!(|| "Inlining constraints");
        cs.finalize();
        end_timer!(timer_inlining);

        end_timer!(timer_cs_startup);
        Ok(Index::new(&cs.into_inner().unwrap()))
    }

    fn create_sel_polynomials(
        num_vars: usize,
        predicate_num_constraints: &IndexMap<Label, usize>,
    ) -> Vec<DenseMLE<E::ScalarField>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let domain_size = 1 << num_vars; // 2^num_vars
        let mut offsets_and_counts = Vec::with_capacity(predicate_num_constraints.len());

        // First, calculate (offset, count) pairs sequentially
        let mut m_count = 0;
        for &count in predicate_num_constraints.values() {
            offsets_and_counts.push((m_count, count));
            m_count += count;
        }

        // Now build the polynomials in parallel
        let sel_polynomials: Vec<_> = (offsets_and_counts)
            .iter()
            .map(|(offset, count)| {
                let evaluations: Vec<_> = repeatn(E::ScalarField::zero(), *offset)
                    .chain(repeatn(E::ScalarField::ONE, *count))
                    .chain(repeatn(
                        E::ScalarField::zero(),
                        domain_size - offset - count,
                    ))
                    .collect();

                DenseMLE::from_evaluations_vec(num_vars, evaluations)
            })
            .collect();

        sel_polynomials
    }

    fn build_equifficient_constraints(
        index: &mut Index<E::ScalarField>,
    ) -> Vec<Vec<SparseMultilinearExtension<E::ScalarField>>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut equifficient_constraints: Vec<Vec<SparseMultilinearExtension<E::ScalarField>>> =
            Vec::new();
        let stacked_matrices: Vec<Matrix<E::ScalarField>> = stack_matrices(index);
        let transposed_stacked_matrices: Vec<Matrix<E::ScalarField>> = cfg_iter!(stacked_matrices)
            .map(|matrix| transpose(matrix, index.total_variables_len))
            .map(|matrix| matrix[index.instance_len..].to_vec())
            .collect();
        for matrix in transposed_stacked_matrices.into_iter() {
            let equifficient_constraint: Vec<_> = cfg_iter!(matrix)
                .map(|col| {
                    let evals: Vec<_> = cfg_iter!(col).map(|(value, row)| (*row, *value)).collect();
                    SparseMultilinearExtension::from_evaluations(index.log_num_constraints, &evals)
                })
                .collect();

            equifficient_constraints.push(equifficient_constraint);
        }
        equifficient_constraints
    }

    #[allow(clippy::type_complexity)]
    fn compute_sel_pk_vk(
        index: &Index<E::ScalarField>,
        epc_ck: &MLCommitmentKey<E>,
    ) -> (
        Option<Vec<DenseMLE<E::ScalarField>>>,
        Option<MLBatchedCommitment<E>>,
    ) {
        match index.num_predicates {
            1 => (None, None),
            _ => {
                let sel_polys = Self::create_sel_polynomials(
                    index.log_num_constraints,
                    &index.predicate_num_constraints,
                );
                let sel_comms = MultilinearEPC::batch_commit(
                    epc_ck,
                    &sel_polys,
                    &vec![None; sel_polys.len()],
                    &None::<&mut ThreadRng>,
                    &vec![None; sel_polys.len()],
                    None,
                );
                (Some(sel_polys), Some(sel_comms.0))
            }
        }
    }
}
