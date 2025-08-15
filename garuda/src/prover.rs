use crate::zk::zk_zerocheck_prover_wrapper;
use crate::{
    arithmetic::{DenseMultilinearExtension as DenseMLE, VirtualPolynomial},
    data_structures::{Index, Proof, ProvingKey},
    epc::{data_structures::MLBatchedCommitment, multilinear::MultilinearEPC, EPC},
    piop::{prelude::ZeroCheck, PolyIOP},
    utils::{evaluate_batch, stack_matrices},
    Garuda,
};
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_poly::multivariate::{SparsePolynomial, SparseTerm};
use ark_relations::{
    gr1cs::{
        self,
        instance_outliner::{outline_r1cs, InstanceOutliner},
        predicate::Predicate,
        ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
        R1CS_PREDICATE_LABEL,
    },
    lc,
};
use ark_std::UniformRand;
use ark_std::{end_timer, rand::RngCore, rc::Rc, start_timer, sync::Arc};
use shared_utils::transcript::IOPTranscript;

impl<E: Pairing> Garuda<E> {
    pub fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &ProvingKey<E>,
        zk_rng: Option<&mut R>,
        circuit: C,
    ) -> Result<Proof<E>, SynthesisError> {
        let is_zk = &zk_rng.is_some();
        let timer_prove = start_timer!(|| "Prove");
        let (mut index, x_assignment, w_assignment) = Self::circuit_to_prover_cs(circuit, *is_zk)?;
        // Extract the index (i), input (x), witness (w), and the full assignment z=(x||w) from the constraint system
        let timer_extract_i_x_w =
            start_timer!(|| "Extract NP index, intance, witness and extended witness");
        let mut z_assignment = x_assignment.clone();
        z_assignment.extend_from_slice(&w_assignment);
        end_timer!(timer_extract_i_x_w);

        // initilizing the transcript
        let timer_init_transcript = start_timer!(|| "Initialize Transcript");
        let mut transcript = IOPTranscript::<E::ScalarField>::new(Self::SNARK_NAME.as_bytes());
        let verifier_key = &pk.verifying_key;
        transcript
            .append_serializable_element(b"vk", verifier_key)
            .unwrap();
        transcript
            .append_serializable_element(b"input", &x_assignment[1..])
            .unwrap();
        end_timer!(timer_init_transcript);

        // Generate the w polynomials, i.e. w_i = M_i * (0||w) and z polynomials, i.e. z_i = M_i * z
        // Line 3-a figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_generate_w_z_polys = start_timer!(|| "Generate Mw, Mz Polynomials");
        let (mut mw_polys, mz_polys) = Self::generate_w_z_polys(&mut index, &z_assignment);
        end_timer!(timer_generate_w_z_polys);
        //
        // EPC-Commit to the witness polynomials, i.e. generate c_i = EPC.Comm(w_i)
        // Line 3-b figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_epc_commit = start_timer!(|| "EPC Commit");
        let num_constraints = index.predicate_num_constraints.values().sum::<usize>();
        let mut rest_zeros = vec![Some(num_constraints); mw_polys.len()];
        let mut hiding_bound = vec![None; mw_polys.len()];
        if *is_zk {
            hiding_bound.push(Some(1));
            mw_polys.push(DenseMLE::from_evaluations_vec(
                mw_polys[0].num_vars,
                vec![E::ScalarField::zero(); mw_polys[0].evaluations.len()],
            ));
            rest_zeros.push(Some(0));
        }
        let w_batched_comm = MultilinearEPC::batch_commit(
            &pk.epc_ck,
            &mw_polys,
            &rest_zeros,
            &zk_rng,
            &hiding_bound,
            Some(&w_assignment),
        );
        transcript
            .append_serializable_element(b"batched_commitments", &w_batched_comm.0)
            .unwrap();
        end_timer!(timer_epc_commit);

        // Performing zero-check on the grand polynomial
        // Note that we use the z_polys here
        // Line 5 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let timer_buid_grand_poly = start_timer!(|| "Build Grand Polynomial");
        let grand_poly = Self::build_grand_poly(mz_polys, &pk.sel_polys, &index);
        end_timer!(timer_buid_grand_poly);

        // grand_poly.print_evals();
        let timer_zero_check = start_timer!(|| "Zero Check");
        let zero_check_proof =
            zk_zerocheck_prover_wrapper(&grand_poly, &mut transcript, zk_rng, pk.mask_ck.as_ref());
        end_timer!(timer_zero_check);

        // Evaluate the selector and witness polynomials on the challenge point outputed by the zero-check
        // Line 7 of figure 7 of https://eprint.iacr.org/2024/1245.pdf

        let timer_eval_polys = start_timer!(|| "Evaluate Polynomials");
        let timer_eval_mw_polys = start_timer!(|| "Evaluate M.w Polynomials");
        let w_poly_evals = evaluate_batch(&mw_polys, &zero_check_proof.iop_proof.point);
        end_timer!(timer_eval_mw_polys);

        let timer_eval_sel_polys = start_timer!(|| "Evaluate Selector Polynomials");
        let sel_poly_evals = match index.num_predicates {
            1 => None,
            _ => pk
                .sel_polys
                .as_ref()
                .map(|sel_polys| evaluate_batch(sel_polys, &zero_check_proof.iop_proof.point)),
        };
        end_timer!(timer_eval_sel_polys);
        end_timer!(timer_eval_polys);

        // Construct the set of all polynomials the corresponding commitments to be opened
        // We will batch-open these commitments
        // Note that selector polynomials are only present when there are more than one predicate
        let comms_to_be_opened = w_batched_comm
            .0
            .individual_comms
            .iter()
            .copied()
            .chain(
                pk.verifying_key
                    .sel_batched_comm
                    .iter()
                    .cloned()
                    .flat_map(|c| c.individual_comms),
            )
            .collect();

        let polys_to_be_opened: Vec<_> = mw_polys
            .into_iter()
            .chain(pk.sel_polys.iter().flatten().cloned())
            .collect();

        // open the commitments
        // Line 8 and 9 of figure 7 of https://eprint.iacr.org/2024/1245.pdf

        let timer_open_comms = start_timer!(|| "Open Commitments");
        let opening_proof = MultilinearEPC::batch_open(
            &pk.epc_ck,
            &polys_to_be_opened,
            &zero_check_proof.iop_proof.point,
            &MLBatchedCommitment {
                individual_comms: comms_to_be_opened,
                consistency_comm: w_batched_comm.0.consistency_comm,
            },
            &w_batched_comm.1,
        );
        end_timer!(timer_open_comms);

        // Construct the proof
        // Line 10 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let result = Ok(Proof {
            w_batched_comm: w_batched_comm.0,
            zero_check_proof,
            sel_poly_evals,
            w_poly_evals,
            batched_opening_proof: opening_proof,
        });

        end_timer!(timer_prove);

        result
    }

    pub fn circuit_to_prover_cs<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        zk: bool,
    ) -> Result<
        (
            Index<E::ScalarField>,
            Vec<E::ScalarField>,
            Vec<E::ScalarField>,
        ),
        SynthesisError,
    > {
        const ZK_BOUND: usize = 3;
        // Start up the constraint System and synthesize the circuit
        let timer_cs_startup = start_timer!(|| "Building Constraint System");
        let cs = ConstraintSystem::new_ref();
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
        //TODO: Fix this, The rng should be downstreamed from the prover
        if zk {
            let timer_zk = start_timer!(|| "ZK Setup");
            for _ in 0..ZK_BOUND {
                let a = E::ScalarField::from(100);
                let b = E::ScalarField::from(200);
                let c = a * b;
                let a_wit = cs.new_witness_variable(|| Ok(a))?;
                let b_wit = cs.new_witness_variable(|| Ok(b))?;
                let c_wit = cs.new_witness_variable(|| Ok(c))?;
                cs.enforce_r1cs_constraint(|| lc!() + a_wit, || lc!() + b_wit, || lc!() + c_wit)?;
            }
            end_timer!(timer_zk);
        }
        let timer_inlining = start_timer!(|| "Inlining constraints");
        cs.finalize();
        end_timer!(timer_inlining);
        end_timer!(timer_cs_startup);
        let cs = cs.into_inner().unwrap();
        let x_assignment = &cs.assignments.instance_assignment;
        let w_assignment = &cs.assignments.witness_assignment;
        Ok((
            Index::new(&cs),
            x_assignment.to_vec(),
            w_assignment.to_vec(),
        ))
    }

    #[allow(clippy::type_complexity)]
    fn generate_w_z_polys(
        index: &mut Index<E::ScalarField>,
        z_assignment: &[E::ScalarField],
    ) -> (Vec<DenseMLE<E::ScalarField>>, Vec<DenseMLE<E::ScalarField>>) {
        let stacked_matrices = stack_matrices(index);
        stacked_matrices
            .iter()
            .map(|matrix| {
                let (mz, mw) = crate::utils::mat_vec_mul(matrix, z_assignment, index.instance_len);
                (
                    DenseMLE::from_evaluations_vec(index.log_num_constraints, mw),
                    DenseMLE::from_evaluations_vec(index.log_num_constraints, mz),
                )
            })
            .unzip()
    }

    // A helper function to build the grand polynomial
    // On witness polys, selector polys, and the predicate poly (inside the index), output the grand polynomial
    fn build_grand_poly(
        z_polys: Vec<DenseMLE<E::ScalarField>>,
        sel_polys: &Option<Vec<DenseMLE<E::ScalarField>>>,
        index: &Index<E::ScalarField>,
    ) -> VirtualPolynomial<E::ScalarField> {
        let z_arcs = z_polys.into_iter().map(Arc::new).collect::<Vec<_>>();
        let mut target_virtual_poly = VirtualPolynomial::new(index.log_num_constraints);
        // If there is only one predicate, The virtual poly is just L(mle(M_1z), mle(M_2z), ..., mle(M_tz)) without any selector
        if index.num_predicates == 1 {
            let predicate_poly = match index.predicate_types.values().next() {
                Some(Predicate::Polynomial(p)) => p.polynomial.clone(),
                _ => unimplemented!("Only polynomial predicates are supported"),
            };
            Self::build_grand_poly_single_pred(predicate_poly, &z_arcs, &mut target_virtual_poly);
            return target_virtual_poly;
        }

        // If there are multiple predicates, The virtual poly is the grand poly in line 5 of figure 7 of https://eprint.iacr.org/2024/1245.pdf
        let selectors = sel_polys
            .clone()
            .unwrap()
            .iter()
            .map(|item| Arc::new(item.clone()))
            .collect::<Vec<_>>();

        for (c, (_, predicate_type)) in index.predicate_types.iter().enumerate() {
            let predicate_poly = match predicate_type {
                Predicate::Polynomial(p) => p.polynomial.clone(),
                _ => unimplemented!("Only polynomial predicates are supported"),
            };
            Self::build_grand_poly_multi_pred(
                predicate_poly,
                &selectors[c],
                &z_arcs,
                &mut target_virtual_poly,
            );
        }
        target_virtual_poly
    }

    pub fn build_grand_poly_single_pred(
        predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm>,
        witness_poly_arcs: &[Arc<DenseMLE<E::ScalarField>>],
        virtual_poly: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        // 1.  Compute each (coeff, mle_list) pair.
        let contributions = (predicate_poly.terms).into_iter().map(|(coeff, term)| {
            // Re‑create the list of MLEs for this monomial.
            let mle_list = term
                .into_iter()
                .flat_map(|(var, exponent)| {
                    std::iter::repeat_n(Arc::clone(&witness_poly_arcs[*var]), *exponent)
                })
                .collect::<Vec<_>>();
            (mle_list, coeff)
        });

        // 2.  Feed the results into `virtual_poly` (sequential – cheap).
        for (mle_list, coeff) in contributions {
            virtual_poly.add_mle_list(mle_list, coeff).unwrap();
        }
    }

    pub fn build_grand_poly_multi_pred(
        predicate_poly: SparsePolynomial<E::ScalarField, SparseTerm>,
        selector_poly: &Arc<DenseMLE<E::ScalarField>>,
        witness_poly_arcs: &[Arc<DenseMLE<E::ScalarField>>],
        virtual_poly: &mut VirtualPolynomial<E::ScalarField>,
    ) {
        // -------- phase 1: compute each (mle_list, coeff) in parallel --------
        let contributions = predicate_poly
            .terms // ⇢ `.into_par_iter()` when parallel
            .into_iter()
            .map(|(coeff, term)| {
                // Build the list of MLEs for this monomial.
                let mut mle_list = Vec::with_capacity(1 + term.len()); // 1 for selector
                mle_list.push(Arc::clone(selector_poly));

                term.iter().for_each(|(var, exponent)| {
                    mle_list.extend(std::iter::repeat_n(
                        Arc::clone(&witness_poly_arcs[*var]),
                        *exponent,
                    ));
                });

                (mle_list, coeff)
            });

        // -------- phase 2: mutate `virtual_poly` sequentially --------
        for (mle_list, coeff) in contributions {
            let _ = virtual_poly.add_mle_list(mle_list, coeff);
        }
    }
}
