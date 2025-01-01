use core::time;
use std::collections::BTreeMap;

use crate::arithmetic::{DenseMultilinearExtension, VPAuxInfo, VirtualPolynomial};
use crate::data_structures::VerifyingKey;
use crate::piop::prelude::{IOPProof, ZeroCheck};
use crate::piop::PolyIOP;
use crate::timer::{self, Timer};
use crate::transcript::IOPTranscript;
use crate::utils::epc_batch_check;
use crate::{data_structures::Proof, Garuda};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::VariableBaseMSM;
use ark_ff::{BigInt, Field, PrimeField, UniformRand, Zero};
use ark_poly::SparseMultilinearExtension;
use ark_poly::{MultilinearExtension, Polynomial};
use ark_relations::gr1cs::predicate::PredicateType;
use ark_relations::gr1cs::{
    predicate, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL,
};
use ark_relations::utils::matrix::Matrix;
use ark_std::iterable::Iterable;
use ark_std::marker::PhantomData;
use ark_std::ops::Add;
use ark_std::rand::RngCore;
use ark_std::sync::Arc;
impl<E> Garuda<E>
where
    E: Pairing,
{
    pub fn verify(proof: Proof<E>, vk: VerifyingKey<E>, public_input: &[E::ScalarField]) -> bool
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        assert_eq!(public_input.len(), vk.instance_len - 1);
        let timer_verify: Timer = Timer::new("SNARK::Verify");

        // Prepare the transcript
        let timer_transcript_init: Timer = Timer::new("SNARK::Verify::Transcript initializtion");
        let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
            IOPTranscript::<E::ScalarField>::new(b"Garuda-2024");
        transcript.append_serializable_element("vk".as_bytes(), &vk);
        transcript.append_serializable_element("input".as_bytes(), &public_input.to_vec());
        transcript.append_serializable_element(
            "individual_commitments".as_bytes(),
            &proof.individual_comms,
        );
        transcript.append_serializable_element(
            "consistency_commitments".as_bytes(),
            &proof.consistency_comm,
        );

        timer_transcript_init.stop();

        // Compute the x polynomials
        // Line 4 of figure 7 in https://eprint.iacr.org/2024/1245.pdf
        // This process is only succinct if the constraint system is 'instance outlined'
        let timer_x_poly: Timer = Timer::new("SNARK::Verify::Compute x polynomial");
        let mut px_evaluations: Vec<(usize, E::ScalarField)> = Vec::with_capacity(vk.instance_len);
        px_evaluations.push((0, E::ScalarField::ONE));
        for i in 1..vk.instance_len {
            px_evaluations.push((i, public_input[i - 1]));
        }
        let px =
            SparseMultilinearExtension::from_evaluations(vk.log_num_constraints, &px_evaluations);
        timer_x_poly.stop();

        // Check if the equifficient property of the commitments are satisfied
        // Line 6 of figure 7 in https://eprint.iacr.org/2024/1245.pdf
        let timer_consistency_check: Timer = Timer::new("SNARK::Verify::Consistency check");
        Self::perform_consistency_check(&vk, proof.consistency_comm, &proof.individual_comms);
        timer_consistency_check.stop();

        // Performing the zerocheck
        // Line 3 of figure 7 in https://eprint.iacr.org/2024/1245.pdf
        let zero_check_auxiliary_info = VPAuxInfo {
            max_degree: vk.predicate_max_deg
                + match vk.num_predicates {
                    1 => 0,
                    _ => 1,
                },
            num_variables: vk.log_num_constraints,
            phantom: PhantomData,
        };

        let zero_check_subclaim = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::verify(
            &proof.zero_check_proof,
            &zero_check_auxiliary_info,
            &mut transcript,
        )
        .unwrap();

        //TODO: Clone
        let mut z_poly_evals = proof.w_poly_evals.clone();
        z_poly_evals[0] += px.evaluate(&zero_check_subclaim.point);
        // By construction on the prover side, we know that the first stacked predicate is the R1CS predicate
        let mut provided_grand_eval = E::ScalarField::zero();
        let mut i = 0;
        for (_, pred) in vk.predicate_types {
            match pred {
                PredicateType::Polynomial(poly) => {
                    provided_grand_eval += proof.sel_poly_evals[i] * poly.eval(&z_poly_evals);
                }
                _ => panic!("Invalid predicate type"),
            }
            i += 1;
        }

        assert_eq!(provided_grand_eval, zero_check_subclaim.expected_evaluation);

        let comms_to_be_checked: Vec<E::G1Affine> = proof
            .individual_comms
            .clone()
            .into_iter()
            .chain(vk.selector_vk.clone())
            .collect();

        let evals_to_be_checked: Vec<E::ScalarField> = proof
            .w_poly_evals
            .clone()
            .into_iter()
            .chain(proof.sel_poly_evals.clone())
            .collect();

        Self::perform_opening_check(
            &comms_to_be_checked,
            &zero_check_subclaim.point,
            &evals_to_be_checked,
            (&vk.g, &vk.h),
            &proof.opening_proof,
            &vk.h_mask_random,
            vk.log_num_constraints,
        );

        timer_verify.stop();
        true
    }

    fn perform_consistency_check(
        vk: &VerifyingKey<E>,
        consistency_proof: E::G1,
        commitments: &Vec<E::G1Affine>,
    ) {
        assert_eq!(vk.consistency_vk.len(), commitments.len());
        let left: PairingOutput<E> = E::pairing(consistency_proof, vk.h);
        let pairing_lefts: Vec<E::G1Prepared> =
            commitments.iter().map(E::G1Prepared::from).collect();
        let pairing_rights: Vec<E::G2Prepared> =
            vk.consistency_vk.iter().map(E::G2Prepared::from).collect();
        let right: PairingOutput<E> = E::multi_pairing(pairing_lefts, pairing_rights);
        if left != right {
            panic!("consistency check failed");
        }
    }

    fn perform_opening_check(
        all_comms: &Vec<E::G1Affine>,
        point: &Vec<E::ScalarField>,
        all_evals: &Vec<E::ScalarField>,
        (g, h): (&E::G1Affine, &E::G2Affine),
        pst_proof: &Vec<E::G1Affine>,
        h_mask_random: &Vec<E::G2Affine>,
        nv: usize,
    ) {
        assert!(all_comms.len() == all_evals.len());
        if !epc_batch_check::<E>((g, h),h_mask_random, all_comms, point, all_evals, pst_proof, nv) {
            panic!("Batch check failed");
        };
    }
}
