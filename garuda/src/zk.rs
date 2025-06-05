use core::panic;

use crate::arithmetic::eq_eval;
use crate::arithmetic::{VPAuxInfo, VirtualPolynomial};
use crate::data_structures::ZKIOPProof;
use crate::piop::prelude::{IOPProof, SumCheck, SumCheckSubClaim, ZeroCheckSubClaim};
use crate::piop::PolyIOP;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::multivariate::SparsePolynomial;
use ark_poly::multivariate::SparseTerm;
use ark_poly::multivariate::Term;
use ark_poly::DenseMVPolynomial;
use ark_poly::Polynomial;
use ark_poly_commit::marlin_pc::Commitment as MaskCommitment;
use ark_poly_commit::marlin_pst13_pc::CommitterKey as ScMaskCk;
use ark_poly_commit::marlin_pst13_pc::MarlinPST13;
use ark_poly_commit::marlin_pst13_pc::Proof as MaskOpeningProof;
use ark_poly_commit::marlin_pst13_pc::VerifierKey as MaskVerifierKey;
use ark_poly_commit::PolynomialCommitment;
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use ark_std::Zero;
use ark_std::{end_timer, start_timer, test_rng};
use rayon::vec;
use shared_utils::transcript::IOPTranscript;
/// Generate 'num_variables' univariate mask polynomials with degree 'deg'.
/// The mask multivariate polynomial formed by univariate polynomials sums 0 on hypercube.
pub(crate) fn generate_mask_polynomial<F: PrimeField>(
    mask_rng: &mut impl RngCore,
    num_variables: usize,
    deg: usize,
    sum_to_zero: bool,
) -> SparsePolynomial<F, SparseTerm> {
    let mut mask_polynomials: Vec<Vec<F>> = Vec::new();
    let mut sum_g = F::zero();
    for _ in 0..num_variables {
        let mut mask_poly = Vec::<F>::with_capacity(deg + 1);
        mask_poly.push(F::rand(mask_rng));
        sum_g += mask_poly[0] + mask_poly[0];
        for i in 1..deg + 1 {
            mask_poly.push(F::rand(mask_rng));
            sum_g += mask_poly[i];
        }
        mask_polynomials.push(mask_poly);
    }
    if sum_to_zero {
        mask_polynomials[0][0] -= sum_g / F::from(2u8);
    }
    let mut terms: Vec<(F, SparseTerm)> = Vec::new();
    for (var, variables_coef) in mask_polynomials.iter().enumerate() {
        variables_coef
            .iter()
            .enumerate()
            .for_each(|(degree, coef)| terms.push((*coef, SparseTerm::new(vec![(var, degree)]))));
    }

    SparsePolynomial::from_coefficients_vec(num_variables, terms)
}

pub fn zk_zerocheck_prover_wrapper<E: Pairing, R: RngCore>(
    poly: &VirtualPolynomial<E::ScalarField>,
    transcript: &mut IOPTranscript<E::ScalarField>,
    mask_rng_key: Option<&mut R>,
    mask_key: Option<&ScMaskCk<E, SparsePolynomial<E::ScalarField, SparseTerm>>>,
) -> ZKIOPProof<E> {
    let start = start_timer!(|| "zero check prove");
    let length = poly.aux_info.num_variables;
    let r = transcript
        .get_and_append_challenge_vectors(b"0check r", length)
        .unwrap();
    let f_hat = poly.build_f_hat(r.as_ref()).unwrap();

    let res = zk_sumcheck_prover_wrapper(&f_hat, transcript, mask_rng_key, mask_key);
    end_timer!(start);
    res
}
pub fn zk_sumcheck_prover_wrapper<E: Pairing, R: RngCore>(
    poly: &VirtualPolynomial<E::ScalarField>,
    transcript: &mut IOPTranscript<E::ScalarField>,
    mask_rng_key: Option<&mut R>,
    mask_key: Option<&ScMaskCk<E, SparsePolynomial<E::ScalarField, SparseTerm>>>,
) -> ZKIOPProof<E> {
    match (mask_rng_key, mask_key) {
        (Some(mask_rng), Some(mask_key)) => {
            let aux_info = poly.aux_info.clone();
            let mask_poly = generate_mask_polynomial(
                mask_rng,
                aux_info.num_variables,
                aux_info.max_degree,
                true,
            );
            let vec_mask_poly = vec![LabeledPolynomial::new(
                String::from("mask_poly_for_sumcheck"),
                mask_poly.clone(),
                Some(aux_info.max_degree),
                None,
            )];
            let (mask_commit, mask_randomness) = MarlinPST13::<
                E,
                SparsePolynomial<E::ScalarField, SparseTerm>,
            >::commit(
                mask_key, &vec_mask_poly, Some(mask_rng)
            )
            .unwrap();
            let g_commit = mask_commit[0].commitment();
            let challenge = transcript
                .get_and_append_challenge(b"mask_commitment")
                .unwrap();
            let mask = Some((mask_poly.clone(), challenge));

            let proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(
                poly, mask, transcript,
            )
            .unwrap();
            let point = proof.point.clone();
            let mut sponge = DummySponge::new(&());
            let opening = MarlinPST13::<E, SparsePolynomial<E::ScalarField, SparseTerm>>::open(
                mask_key,
                &vec_mask_poly,
                &mask_commit,
                &point,
                &mut sponge,
                &mask_randomness,
                None,
            );
            ZKIOPProof {
                iop_proof: proof,
                mask_com: Some(*g_commit),
                mask_opening: Some(opening.unwrap()),
                mask_evaluation: Some(mask_poly.evaluate(&point)),
            }
        }
        (None, None) => {
            let proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(
                poly, None, transcript,
            )
            .unwrap();
            ZKIOPProof {
                iop_proof: proof,
                mask_com: None,
                mask_opening: None,
                mask_evaluation: None,
            }
        }
        _ => {
            panic!("Both mask_rng_key and mask_key must be provided or both must be None");
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
pub struct DummySponge;

impl CryptographicSponge for DummySponge {
    type Config = ();

    fn new(params: &Self::Config) -> Self {
        Self
    }

    fn absorb(&mut self, input: &impl ark_crypto_primitives::sponge::Absorb) {}

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        vec![0; num_bytes]
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        vec![false; num_bits]
    }
}

pub fn zk_sumcheck_verifier_wrapper<E: Pairing, S: CryptographicSponge>(
    mask_vk: &Option<MaskVerifierKey<E>>,
    proof: &ZKIOPProof<E>,
    claimed_sum: E::ScalarField,
    aux_info: &VPAuxInfo<E::ScalarField>,
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> SumCheckSubClaim<E::ScalarField> {
    let challenge = match (
        mask_vk,
        &proof.mask_com,
        &proof.mask_opening,
        &proof.mask_evaluation,
    ) {
        (Some(_), Some(_), Some(_), Some(_)) => transcript
            .get_and_append_challenge(b"mask_commitment")
            .unwrap(),
        (None, None, None, None) => E::ScalarField::zero(),
        _ => panic!("Mask verification data is inconsistent"),
    };

    let mut subclaim = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::verify(
        claimed_sum,
        &proof.iop_proof,
        aux_info,
        transcript,
    )
    .unwrap();

    match (
        mask_vk,
        &proof.mask_com,
        &proof.mask_opening,
        &proof.mask_evaluation,
    ) {
        (Some(mask_vk), Some(mask_com), Some(mask_opening), Some(mask_evaluation)) => {
            let label_com = vec![LabeledCommitment::new(
                String::from("mask_poly_for_sumcheck"),
                *mask_com,
                None,
            )];
            let mut sponge = DummySponge::new(&());
            let flag = MarlinPST13::<_, SparsePolynomial<E::ScalarField, SparseTerm>>::check(
                mask_vk,
                &label_com,
                &subclaim.point,
                vec![*mask_evaluation],
                mask_opening,
                &mut sponge,
                None,
            )
            .unwrap();
            if !flag {
                panic!("Mask verification failed");
            }
        }
        (None, None, None, None) => {}
        _ => panic!("Mask verification data is inconsistent"),
    }
    subclaim
}

pub fn zk_zerocheck_verifier_wrapper<E: Pairing, S: CryptographicSponge>(
    mask_vk: &Option<MaskVerifierKey<E>>,
    proof: &ZKIOPProof<E>,
    fx_aux_info: &VPAuxInfo<E::ScalarField>,
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> ZeroCheckSubClaim<E::ScalarField> {
    let start = start_timer!(|| "zero check verify");

    // check that the sum is zero
    if proof.iop_proof.proofs[0].evaluations[0] + proof.iop_proof.proofs[0].evaluations[1]
        != E::ScalarField::zero()
    {
        panic!(
            "zero check: sum {} is not zero",
            proof.iop_proof.proofs[0].evaluations[0] + proof.iop_proof.proofs[0].evaluations[1]
        );
    }

    // generate `r` and pass it to the caller for correctness check
    let length = fx_aux_info.num_variables;
    let r = transcript
        .get_and_append_challenge_vectors(b"0check r", length)
        .unwrap();

    // hat_fx's max degree is increased by eq(x, r).degree() which is 1
    let mut hat_fx_aux_info = fx_aux_info.clone();
    hat_fx_aux_info.max_degree += 1;
    let sum_subclaim = zk_sumcheck_verifier_wrapper::<E, DummySponge>(
        mask_vk,
        proof,
        E::ScalarField::zero(),
        &hat_fx_aux_info,
        transcript,
    );

    // expected_eval = sumcheck.expect_eval/eq(v, r)
    // where v = sum_check_sub_claim.point
    let eq_x_r_eval = eq_eval(&sum_subclaim.point, &r).unwrap();
    let expected_evaluation = sum_subclaim.expected_evaluation / eq_x_r_eval;

    end_timer!(start);
    ZeroCheckSubClaim {
        point: sum_subclaim.point,
        expected_evaluation,
        init_challenge: r,
    }
}
