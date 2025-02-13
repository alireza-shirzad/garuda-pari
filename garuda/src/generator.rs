use std::rc::Rc;

use ark_ec::pairing::Pairing;
use ark_ff::{Field, Zero};
use ark_poly::SparseMultilinearExtension;

use crate::{
    arithmetic::DenseMultilinearExtension,
    data_structures::{Index, ProvingKey, SuccinctIndex, VerifyingKey},
    epc::{
        data_structures::{
            Generators, MLBatchedCommitment, MLCommitment, MLCommitmentKey, MLPublicParameters,
        },
        multilinear::MultilinearEPC,
        EPC,
    },
    utils::stack_matrices,
    Garuda,
};
use ark_relations::gr1cs::{
    self,
    instance_outliner::{outline_r1cs, InstanceOutliner},
    transpose, Constraint, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Label,
    Matrix, OptimizationGoal, SynthesisError, SynthesisMode, R1CS_PREDICATE_LABEL,
};
use ark_std::{
    collections::BTreeMap, end_timer, rand::RngCore, start_timer, vec::Vec, UniformRand,
};

impl<E, R> Garuda<E, R>
where
    E: Pairing,
    R: RngCore,
{
    pub fn keygen<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        rng: &mut R,
    ) -> (ProvingKey<E>, VerifyingKey<E>)
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let timer_generator = start_timer!(|| "Generator");
        let cs = Self::circuit_to_keygen_cs(circuit).unwrap();
        let timer_indexer = start_timer!(|| "Constraint System Startup");
        let index = Index::new(&cs);
        end_timer!(timer_indexer);

        // Generate the public parameters for the multilinear EPC
        let timer_epc_startup = start_timer!(|| "EPC Startup");
        let generators = Generators {
            g: E::G1::rand(rng),
            h: E::G2::rand(rng),
        };
        let epc_pp = MLPublicParameters {
            num_var: index.log_num_constraints,
            num_constraints: index.max_arity,
            generators,
        };

        let timer_epc_equif_constrs_gen = start_timer!(|| "Generating Equifficient Constraints");
        let equifficient_constrinats: Vec<Vec<SparseMultilinearExtension<E::ScalarField>>> =
            Self::build_equifficient_constraints(&index);
        end_timer!(timer_epc_equif_constrs_gen);
        start_timer!(|| "Generating EPC Keys");
        let (epc_ck, epc_vk, _epc_tr) =
            MultilinearEPC::<E, R>::setup(rng, &epc_pp, &equifficient_constrinats);
        end_timer!(timer_epc_startup);
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
        let vk: VerifyingKey<E> = VerifyingKey {
            sel_batched_comm,
            epc_vk,
            succinct_index,
        };

        let pk: ProvingKey<E> = ProvingKey {
            sel_polys,
            verifying_key: vk.clone(),
            epc_ck,
        };

        end_timer!(timer_key_generation);
        end_timer!(timer_generator);

        (pk, vk)
    }

    fn circuit_to_keygen_cs<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
    ) -> Result<ConstraintSystem<E::ScalarField>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
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

        let timer_inlining = start_timer!(|| "Inlining constraints");
        cs.finalize();

        end_timer!(timer_inlining);
        end_timer!(timer_cs_startup);
        Ok(cs.into_inner().unwrap())
    }

    fn create_sel_polynomials(
        num_vars: usize,
        predicate_num_constraints: &BTreeMap<Label, usize>,
    ) -> Vec<DenseMultilinearExtension<E::ScalarField>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut sel_polynomials: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        let mut m_count = 0;
        for m in predicate_num_constraints.values() {
            let evaluations: Vec<E::ScalarField> = std::iter::repeat(E::ScalarField::zero())
                .take(m_count)
                .chain(std::iter::repeat(E::ScalarField::ONE).take(*m))
                .chain(
                    std::iter::repeat(E::ScalarField::zero())
                        .take(2_usize.pow(num_vars as u32) - m_count - m),
                )
                .collect();
            let sel_poly = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);
            sel_polynomials.push(sel_poly);
            m_count += m;
        }

        sel_polynomials
    }

    fn build_equifficient_constraints(
        index: &Index<E::ScalarField>,
    ) -> Vec<Vec<SparseMultilinearExtension<E::ScalarField>>>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut equifficient_constraints: Vec<Vec<SparseMultilinearExtension<E::ScalarField>>> =
            Vec::new();
        let stacked_matrices: Vec<Matrix<E::ScalarField>> = stack_matrices(index);
        let transposed_stacked_matrices: Vec<Matrix<E::ScalarField>> = stacked_matrices
            .iter()
            .map(|matrix| transpose(matrix, index.total_variables_len))
            .map(|matrix| matrix[index.instance_len..].to_vec())
            .collect();
        for matrix in transposed_stacked_matrices {
            let mut equifficient_constraint: Vec<SparseMultilinearExtension<E::ScalarField>> =
                Vec::new();
            for col in matrix {
                let evals: Vec<(usize, E::ScalarField)> =
                    col.iter().map(|(value, row)| (*row, *value)).collect();
                let col_poly: SparseMultilinearExtension<E::ScalarField> =
                    SparseMultilinearExtension::from_evaluations(index.log_num_constraints, &evals);
                equifficient_constraint.push(col_poly);
            }
            equifficient_constraints.push(equifficient_constraint);
        }
        equifficient_constraints
    }

    #[allow(clippy::type_complexity)]
    fn compute_sel_pk_vk(
        index: &Index<E::ScalarField>,
        epc_ck: &MLCommitmentKey<E>,
    ) -> (
        Option<Vec<DenseMultilinearExtension<E::ScalarField>>>,
        Option<MLBatchedCommitment<E>>,
    ) {
        match index.num_predicates {
            1 => (None, None),
            _ => {
                let sel_polys = Self::create_sel_polynomials(
                    index.log_num_constraints,
                    &index.predicate_num_constraints,
                );
                let sel_comms: MLBatchedCommitment<E> =
                    MultilinearEPC::<E, R>::batch_commit(epc_ck, &sel_polys, None);
                (Some(sel_polys), Some(sel_comms))
            }
        }
    }
}
