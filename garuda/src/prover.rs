use std::rc::Rc;

use crate::{
    arithmetic::{DenseMultilinearExtension, VirtualPolynomial},
    data_structures::{Index, Proof, ProvingKey, VerifyingKey},
    epc::{
        data_structures::{MLBatchedCommitment, MLCommitment},
        multilinear::MultilinearEPC,
        EPC,
    },
    piop::{
        prelude::{IOPProof, ZeroCheck},
        PolyIOP,
    },
    utils::stack_matrices,
    Garuda,
};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, Zero};
use ark_poly::{
    multivariate::{SparsePolynomial, SparseTerm},
    Polynomial,
};
use ark_relations::gr1cs::{
    self,
    instance_outliner::{outline_r1cs, InstanceOutliner},
    mat_vec_mul,
    predicate::Predicate,
    ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
    R1CS_PREDICATE_LABEL,
};
use ark_std::{
    cfg_into_iter, cfg_iter, end_timer, rand::RngCore, start_timer, sync::Arc,
};
use shared_utils::transcript::IOPTranscript;

use rayon::iter::IntoParallelIterator;
#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
impl<E, R> Garuda<E, R>
where
    E: Pairing + Send + Sync,
    R: RngCore,
{
    pub fn prove<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        pk: &ProvingKey<E>,
    ) -> Result<Proof<E>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
        let timer_prove = start_timer!(|| "Prove");
        let cs = Self::circuit_to_prover_cs(circuit)?;
        // Extract the index (i), input (x), witness (w), and the full assignment z=(x||w) from the constraint system
        let timer_extract_i_x_w =
            start_timer!(|| "Extract NP index, intance, witness and extended witness");
        let x_assignment: &[E::ScalarField] = &cs.assignments.instance_assignment;
        let w_assignment: &[E::ScalarField] = &cs.assignments.witness_assignment;
        let z_assignment: Vec<E::ScalarField> = [x_assignment, w_assignment].concat();
        let index: Index<E::ScalarField> = Index::new(&cs);
        end_timer!(timer_extract_i_x_w);

        // initilizing the transcript
        let timer_init_transcript = start_timer!(|| "Initialize Transcript");
        let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
            IOPTranscript::<E::ScalarField>::new(Self::SNARK_NAME.as_bytes());
        let verifier_key: VerifyingKey<E> = pk.verifying_key.clone();
        let _ = transcript.append_serializable_element("vk".as_bytes(), &verifier_key);
        let _ =
            transcript.append_serializable_element("input".as_bytes(), &x_assignment[1..].to_vec());
        end_timer!(timer_init_transcript);

        // Generate the w polynomials, i.e. w_i = M_i * (0||w) and z polynomials, i.e. z_i = M_i * z
        // Line 3-a figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_generate_w_z_polys = start_timer!(|| "Generate Mw, Mz Polynomials");
        #[allow(clippy::type_complexity)]
        let (mw_polys, z_polys): (
            Vec<DenseMultilinearExtension<E::ScalarField>>,
            Vec<DenseMultilinearExtension<E::ScalarField>>,
        ) = Self::generate_w_z_polys(&index, &z_assignment);
        end_timer!(timer_generate_w_z_polys);
        // EPC-Commit to the witness polynomials, i.e. generate c_i = EPC.Comm(w_i)
        // Line 3-b figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_epc_commit = start_timer!(|| "EPC Commit");
        let w_batched_comm =
            MultilinearEPC::<E, R>::batch_commit(&pk.epc_ck, &mw_polys, Some(w_assignment));
        let _ = transcript
            .append_serializable_element("batched_commitments".as_bytes(), &w_batched_comm);
        end_timer!(timer_epc_commit);

        // Performing zero-check on the grand polynomial
        // Note that we use the z_polys here
        // Line 5 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_buid_grand_poly = start_timer!(|| "Build Grand Polynomial");
        let grand_poly: VirtualPolynomial<E::ScalarField> =
            Self::build_grand_poly(&z_polys, &pk.sel_polys, &index);
        end_timer!(timer_buid_grand_poly);

        let timer_zero_check = start_timer!(|| "Zero Check");
        let zero_check_proof: IOPProof<E::ScalarField> = <PolyIOP<E::ScalarField> as ZeroCheck<
            E::ScalarField,
        >>::prove(
            &grand_poly, &mut transcript
        )
        .unwrap();
        end_timer!(timer_zero_check);

        // Evaluate the selector and witness polynomials on the challenge point outputed by the zero-check
        // Line 7 of figure 7 of https://eprint.iacr.org/2024/1245.pdf

        let timer_eval_polys = start_timer!(|| "Evaluate Polynomials");
        let timer_eval_mw_polys = start_timer!(|| "Evaluate M.w Polynomials");
        let w_poly_evals: Vec<E::ScalarField> = cfg_iter!(mw_polys)
            .map(|witness| witness.evaluate(&zero_check_proof.point))
            .collect();
        end_timer!(timer_eval_mw_polys);

        let timer_eval_sel_polys = start_timer!(|| "Evaluate Selector Polynomials");
        let sel_poly_evals: Option<Vec<E::ScalarField>> = match index.num_predicates {
            1 => None,
            _ => pk.sel_polys.as_ref().map(|sel_polys| {
                cfg_iter!(sel_polys)
                    .map(|selector| selector.evaluate(&zero_check_proof.point))
                    .collect()
            }),
        };
        end_timer!(timer_eval_sel_polys);
        end_timer!(timer_eval_polys);

        // Construct the set of all polynomials the corresponding commitments to be opened
        // We will batch-open these commitments
        // Note that selector polynomials are only present when there are more than one predicate
        let comms_to_be_opened: Vec<MLCommitment<E>> =
            cfg_into_iter!(w_batched_comm.individual_comms.clone())
                .chain(match pk.verifying_key.sel_batched_comm.clone() {
                    Some(sel_comms) => sel_comms.individual_comms,
                    None => Vec::with_capacity(0),
                })
                .collect();

        let polys_to_be_opened: Vec<DenseMultilinearExtension<<E>::ScalarField>> =
            cfg_into_iter!(mw_polys.clone())
                .chain(pk.sel_polys.clone().unwrap_or(Vec::with_capacity(0)))
                .collect();

        // open the commitments
        // Line 8 and 9 of figure 7 of https://eprint.iacr.org/2024/1245.pdf

        let timer_open_comms = start_timer!(|| "Open Commitments");
        let opening_proof: Vec<E::G1Affine> = MultilinearEPC::<E, R>::batch_open(
            &pk.epc_ck,
            &polys_to_be_opened,
            &zero_check_proof.point,
            &MLBatchedCommitment {
                individual_comms: comms_to_be_opened,
                consistency_comm: w_batched_comm.consistency_comm,
            },
        );
        end_timer!(timer_open_comms);

        // Construct the proof
        // Line 10 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let result = Ok(Proof {
            w_batched_comm,
            zero_check_proof,
            sel_poly_evals,
            w_poly_evals,
            bathced_opening_proof: opening_proof,
        });

        end_timer!(timer_prove);

        result
    }

    fn circuit_to_prover_cs<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
    ) -> Result<ConstraintSystem<E::ScalarField>, SynthesisError>
    where
        E: Pairing,
        E::ScalarField: Field,
        E::ScalarField: std::convert::From<i32>,
    {
        // Start up the constraint System and synthesize the circuit
        let timer_cs_startup = start_timer!(|| "Building Constraint System");
        let cs: gr1cs::ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(gr1cs::SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: false,
        });
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

    #[allow(clippy::type_complexity)]
    fn generate_w_z_polys(
        index: &Index<E::ScalarField>,
        z_assignment: &[E::ScalarField],
    ) -> (
        Vec<DenseMultilinearExtension<E::ScalarField>>,
        Vec<DenseMultilinearExtension<E::ScalarField>>,
    )
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let stacked_matrices: Vec<Matrix<E::ScalarField>> = stack_matrices(index);

        cfg_iter!(stacked_matrices)
            .map(|matrix| {
                let mz: Vec<E::ScalarField> = mat_vec_mul(matrix, z_assignment);
                let mut w_assignment: Vec<E::ScalarField> =
                    vec![E::ScalarField::zero(); z_assignment.len()];
                w_assignment[index.instance_len..]
                    .copy_from_slice(&z_assignment[index.instance_len..]);
                let mw: Vec<E::ScalarField> = mat_vec_mul(matrix, &w_assignment);
                (
                    DenseMultilinearExtension::from_evaluations_vec(index.log_num_constraints, mw),
                    DenseMultilinearExtension::from_evaluations_vec(index.log_num_constraints, mz),
                )
            })
            .unzip()
    }

    // A helper function to build the grand polynomial
    // On witness polys, selector polys, and the predicate poly (inside the index), output the grand polynomial
    fn build_grand_poly(
        z_polys: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        sel_polys: &Option<Vec<DenseMultilinearExtension<E::ScalarField>>>,
        index: &Index<E::ScalarField>,
    ) -> VirtualPolynomial<E::ScalarField>
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let z_arcs: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = cfg_iter!(z_polys)
            .map(|item| Arc::new(item.clone()))
            .collect();
        let mut target_virtual_poly: VirtualPolynomial<E::ScalarField> =
            VirtualPolynomial::new(index.log_num_constraints);
        // If there is only one predicate, The virtual poly is just L(mle(M_1z), mle(M_2z), ..., mle(M_tz)) without any selector
        if index.num_predicates == 1 {
            let predicate_poly = match index.predicate_types.values().next().unwrap().clone() {
                Predicate::Polynomial(polynomial_predicate) => polynomial_predicate.polynomial,
                _ => unimplemented!("Only polynomial predicates are supported"),
            };
            Self::build_grand_poly_single_pred(predicate_poly, &z_arcs, &mut target_virtual_poly);
            return target_virtual_poly;
        }

        // If there are multiple predicates, The virtual poly is the grand poly in line 5 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let sel_arcs: Vec<Arc<DenseMultilinearExtension<E::ScalarField>>> = sel_polys
            .clone()
            .unwrap()
            .iter()
            .map(|item| Arc::new(item.clone()))
            .collect();

        for (c, (_, predicate_type)) in index.predicate_types.iter().enumerate() {
            let predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm> = match predicate_type
                .clone()
            {
                Predicate::Polynomial(polynomial_predicate) => polynomial_predicate.polynomial,
                _ => unimplemented!("Only polynomial predicates are supported"),
            };
            Self::build_grand_poly_multi_pred(
                predicate_poly,
                &sel_arcs[c],
                &z_arcs,
                &mut target_virtual_poly,
            );
        }
        target_virtual_poly
    }

    pub fn build_grand_poly_single_pred(
        predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm>,
        witness_poly_arcs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        virtual_poly: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        // 1.  Compute each (coeff, mle_list) pair in parallel (or serial).
        let contributions: Vec<(
            Vec<Arc<DenseMultilinearExtension<E::ScalarField>>>,
            E::ScalarField,
        )> = cfg_into_iter!(predicate_poly.terms) // parallel ↔ serial switch
            .map(|(coeff, term)| {
                // Re‑create the list of MLEs for this monomial.
                let mle_list: Vec<_> = term
                    .iter()
                    .flat_map(|(var, exponent)| {
                        std::iter::repeat_with(|| Arc::clone(&witness_poly_arcs[*var]))
                            .take(*exponent)
                    })
                    .collect();
                (mle_list, coeff)
            })
            .collect();

        // 2.  Feed the results into `virtual_poly` (sequential – cheap).
        for (mle_list, coeff) in contributions {
            let _ = virtual_poly.add_mle_list(mle_list, coeff);
        }
    }

    pub fn build_grand_poly_multi_pred(
        predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm>,
        selector_poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        witness_poly_arcs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        virtual_poly: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        // -------- phase 1: compute each (mle_list, coeff) in parallel --------
        let contributions: Vec<(
            Vec<Arc<DenseMultilinearExtension<E::ScalarField>>>,
            E::ScalarField,
        )> = cfg_into_iter!(predicate_poly.terms) // ⇢ `.into_par_iter()` when parallel
            .map(|(coeff, term)| {
                // Build the list of MLEs for this monomial.
                let mut mle_list = Vec::with_capacity(1 + term.len()); // 1 for selector
                mle_list.push(Arc::clone(selector_poly));

                term.iter().for_each(|(var, exponent)| {
                    mle_list.extend(
                        std::iter::repeat_with(|| Arc::clone(&witness_poly_arcs[*var]))
                            .take(*exponent),
                    );
                });

                (mle_list, coeff)
            })
            .collect();

        // -------- phase 2: mutate `virtual_poly` sequentially --------
        for (mle_list, coeff) in contributions {
            let _ = virtual_poly.add_mle_list(mle_list, coeff);
        }
    }
}
