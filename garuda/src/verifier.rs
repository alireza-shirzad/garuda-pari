use crate::zk::{zk_zerocheck_verifier_wrapper, DummySponge};
use crate::{
    arithmetic::VPAuxInfo,
    data_structures::{Proof, VerifyingKey},
    epc::{data_structures::MLBatchedCommitment, multilinear::MultilinearEPC, EPC},
    Garuda,
};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, Zero};
use ark_poly::{Polynomial, SparseMultilinearExtension};
use ark_relations::gr1cs::predicate::{polynomial_constraint::PolynomialPredicate, Predicate};
use ark_std::{end_timer, marker::PhantomData, start_timer};
use shared_utils::transcript::IOPTranscript;
impl<E: Pairing> Garuda<E> {
    pub fn verify(proof: &Proof<E>, vk: &VerifyingKey<E>, public_input: &[E::ScalarField]) -> bool
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let timer_verify = start_timer!(|| "Verify");
        assert_eq!(public_input.len(), vk.succinct_index.instance_len - 1);

        // Prepare the transcript
        let timer_transcript_init = start_timer!(|| "Transcript initializtion");
        let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
            IOPTranscript::<E::ScalarField>::new(Self::SNARK_NAME.as_bytes());
        let _ = transcript.append_serializable_element(b"vk", vk);
        let _ = transcript.append_serializable_element(b"input", public_input);
        let _ =
            transcript.append_serializable_element(b"batched_commitments", &proof.w_batched_comm);

        end_timer!(timer_transcript_init);

        // Compute the x polynomials
        // Line 4 of figure 7 in https://eprint.iacr.org/2024/1245.pdf
        // This process is only succinct if the constraint system is 'instance outlined'
        let timer_x_poly = start_timer!(|| "Compute x polynomial");
        let mut px_evaluations = Vec::with_capacity(vk.succinct_index.instance_len);
        let r1cs_orig_num_cnstrs =
            vk.succinct_index.r1cs_num_constraints - vk.succinct_index.instance_len;
        px_evaluations.push((r1cs_orig_num_cnstrs, E::ScalarField::ONE));
        for i in 1..vk.succinct_index.instance_len {
            px_evaluations.push((r1cs_orig_num_cnstrs + i, public_input[i - 1]));
        }
        let px = SparseMultilinearExtension::from_evaluations(
            vk.succinct_index.log_num_constraints,
            &px_evaluations,
        );
        end_timer!(timer_x_poly);

        // Performing the zerocheck
        // Line 3 of figure 7 in https://eprint.iacr.org/2024/1245.pdf
        let timer_zerocheck = start_timer!(|| "Zero Check");
        let zero_check_auxiliary_info = VPAuxInfo {
            max_degree: vk.succinct_index.predicate_max_deg
                + match vk.succinct_index.num_predicates {
                    1 => 0,
                    _ => 1,
                },
            num_variables: vk.succinct_index.log_num_constraints,
            phantom: PhantomData,
        };

        let zero_check_subclaim = zk_zerocheck_verifier_wrapper::<E, DummySponge>(
            &vk.mask_vk,
            &proof.zero_check_proof,
            &zero_check_auxiliary_info,
            &mut transcript,
        );
        end_timer!(timer_zerocheck);

        // Performing the last step of the zerocheck
        // It checks whether the evaluation of the grand polynomial on a random point is equal to the expected evaluation
        let timer_zerocheck = start_timer!(|| "Grand Poly Evaluation");
        if !Self::zerocheck_final_eval_check(
            &zero_check_subclaim.point,
            &zero_check_subclaim.expected_evaluation,
            &px,
            proof,
            vk,
        ) {
            // panic!("Final Evaluation check in zerocheck failed");
        }
        end_timer!(timer_zerocheck);

        // batch Verification of the EPC evaluation proofs
        // The batch contains the evaluation proofs of the w polynomials and possibly the selector polynomials
        // If there is only one predicate, then there is no selector polynomial

        let timer_epc_batch_ver = start_timer!(|| "EPC Verification");
        let batched_comm = MLBatchedCommitment {
            individual_comms: proof
                .w_batched_comm
                .individual_comms
                .clone()
                .into_iter()
                .chain(match vk.clone().sel_batched_comm {
                    Some(sel_batched_comm) => sel_batched_comm.individual_comms,
                    None => Vec::new(),
                })
                .collect(),
            consistency_comm: proof.w_batched_comm.consistency_comm,
        };

        let evals_to_be_checked: Vec<E::ScalarField> = proof
            .w_poly_evals
            .clone()
            .into_iter()
            .chain(proof.clone().sel_poly_evals.unwrap_or_default())
            .collect();

        if !MultilinearEPC::batch_verify(
            &vk.epc_vk,
            &batched_comm,
            &zero_check_subclaim.point,
            &evals_to_be_checked,
            &(proof.batched_opening_proof.clone()),
            vk.succinct_index.max_arity,
        ) {
            panic!("Batch verification failed");
        }
        end_timer!(timer_epc_batch_ver);

        end_timer!(timer_verify);
        true
    }

    fn zerocheck_final_eval_check(
        random_eval_point: &[E::ScalarField],
        exptected_eval: &E::ScalarField,
        px: &SparseMultilinearExtension<E::ScalarField>,
        proof: &Proof<E>,
        vk: &VerifyingKey<E>,
    ) -> bool {
        let mut z_poly_evals = proof.w_poly_evals.clone();
        z_poly_evals[2] += px.evaluate(&random_eval_point.to_vec());
        // By construction on the prover side, we know that the first stacked predicate is the R1CS predicate
        let predicate_polys: Vec<&PolynomialPredicate<E::ScalarField>> = vk
            .succinct_index
            .predicate_types
            .values()
            .map(|pred| match pred {
                Predicate::Polynomial(poly_predicate) => poly_predicate,
                _ => panic!("Invalid predicate type"),
            })
            .collect();
        let eval = match vk.succinct_index.num_predicates {
            1 => {
                assert_eq!(predicate_polys.len(), 1);
                assert!(proof.sel_poly_evals.is_none());
                predicate_polys[0].eval(&z_poly_evals)
            }
            _ => {
                assert!(predicate_polys.len() > 1);
                assert_eq!(
                    predicate_polys.len(),
                    proof.sel_poly_evals.as_ref().unwrap().len()
                );
                predicate_polys
                    .iter()
                    .zip(proof.sel_poly_evals.as_ref().unwrap())
                    .fold(E::ScalarField::zero(), |acc, (poly, sel_eval)| {
                        acc + *sel_eval * poly.eval(&z_poly_evals)
                    })
            }
        };

        eval == *exptected_eval
    }
}
