use crate::data_structures::{IndexInfo, ProverKey, VerifierKey};
use crate::{data_structures::Proof, Garuda};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::VariableBaseMSM;
use ark_ff::{BigInt, Field, PrimeField, UniformRand, Zero};
use ark_poly::evaluations;
use ark_poly_commit::multilinear_pc::data_structures::VerifierKey as PST_Vk;
use ark_poly_commit::multilinear_pc::data_structures::{
    Commitment, CommitterKey, Proof as PST_proof,
};
use ark_poly_commit::multilinear_pc::MultilinearPC;
use ark_relations::gr1cs::polynomial::Polynomial;
use ark_relations::gr1cs::predicate::LocalPredicateType;
use ark_relations::gr1cs::{predicate, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_relations::utils::variable::Matrix;
use ark_std::iterable::Iterable;
use ark_std::marker::PhantomData;
use ark_std::ops::Add;
use ark_std::rand::RngCore;
use ark_std::sync::Arc;
use hp_arithmetic::{DenseMultilinearExtension, VPAuxInfo, VirtualPolynomial};
use hp_subroutines::{IOPProof, PolyIOP, ZeroCheck};
use hp_transcript::IOPTranscript;

impl<E> Garuda<E>
where
    E: Pairing,
{
    pub fn verify<R: RngCore>(
        rng: &mut R,
        proof: Proof<E>,
        vk: VerifierKey<E>,
        public_input: &[E::ScalarField],
    ) -> bool
    where
        E: Pairing,
        E::ScalarField: Field,
    {
        let mut transcript: IOPTranscript<<E as Pairing>::ScalarField> =
            IOPTranscript::<E::ScalarField>::new(b"Garuda-2024");
        transcript.append_serializable_element("vk".as_bytes(), &vk);
        transcript.append_serializable_element("input".as_bytes(), &public_input[1..].to_vec());
        transcript.append_serializable_element("commitments".as_bytes(), &proof.commitments);
        transcript.append_serializable_element("linking_proof".as_bytes(), &proof.linking_proof);

        Self::perform_linking_check(&vk, proof.linking_proof, &proof.commitments, public_input);

        let zero_check_auxiliary_info = VPAuxInfo {
            max_degree: vk.index_info.max_degree
                + match vk.index_info.num_predicates {
                    1 => 0,
                    _ => 1,
                },
            num_variables: vk.index_info.v_total,
            phantom: PhantomData,
        };

        let zero_check_subclaim = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::verify(
            &proof.zero_check_proof,
            &zero_check_auxiliary_info,
            &mut transcript,
        )
        .unwrap();

        let mut all_commitments = proof.commitments.clone();
        let mut all_openings = proof.witness_poly_openings.clone();

        all_commitments.extend(vk.selector_vk.clone());
        all_openings.extend(proof.selector_poly_openings.clone());
        Self::perform_opening_check(
            &all_commitments,
            &zero_check_subclaim.point,
            &all_openings,
            &vk.pst_vk,
            &proof.opening_proof,
        );
        true
    }

    fn perform_linking_check(
        vk: &VerifierKey<E>,
        linking_proof: E::G1,
        commitments: &Vec<Commitment<E>>,
        input_assignment: &[E::ScalarField],
    ) {
        assert_eq!(vk.linking_vk.len(), commitments.len());
        assert_eq!(vk.public_input_vk.len(), input_assignment.len());
        let public_input_linking = E::G1::msm(&vk.public_input_vk, input_assignment).unwrap();
        let left: PairingOutput<E> = E::pairing(linking_proof + public_input_linking, vk.pst_vk.h);
        let pairing_lefts: Vec<E::G1Prepared> = commitments
            .into_iter()
            .map(|x| E::G1Prepared::from(x.g_product))
            .collect();
        let pairing_rights: Vec<E::G2Prepared> = vk
            .linking_vk
            .iter()
            .map(|x| E::G2Prepared::from(x))
            .collect();
        let right: PairingOutput<E> = E::multi_pairing(pairing_lefts, pairing_rights);
        if (left != right) {
            panic!("Linking check failed");
        }
    }

    fn perform_opening_check(
        commitments: &Vec<Commitment<E>>,
        point: &Vec<E::ScalarField>,
        evaluations: &Vec<E::ScalarField>,
        pst_vk: &PST_Vk<E>,
        pst_proof: &PST_proof<E>,
    ) {
        assert!(commitments.len() == evaluations.len());
        if (MultilinearPC::<E>::batch_check(&pst_vk, commitments, &point, evaluations, pst_proof)
            == false)
        {
            panic!("Batch check failed");
        };
    }
}
