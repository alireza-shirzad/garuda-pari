pub const INPUT_BENCHMARK: &str = "input";
pub const RESCUE_APPLICATION_NAME: &str = "rescue";

pub mod bellpepper_adapter;

use ark_crypto_primitives::sponge::rescue::constraints::RESCUE_PREDICATE;
use ark_crypto_primitives::{
    crh::{
        rescue::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    },
    sponge::rescue::RescueConfig,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{ConstraintSynthesizer, SynthesisError};
use garuda::ConstraintSystemRef;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};
use rand::Rng;
pub const RESCUE_ROUNDS: usize = 12;
pub const WIDTH: usize = 9;

/// This is our demo circuit for proving knowledge of the
/// preimage of a Rescue hash invocation.
#[derive(Clone)]
pub struct RescueDemo<F: PrimeField> {
    pub input: Option<Vec<F>>,
    pub image: Option<F>,
    pub num_instances: usize,
    pub config: RescueConfig<F>,
    pub num_invocations: usize,
    pub should_use_custom_predicate: bool,
}

pub fn create_test_rescue_parameter<F: PrimeField + ark_ff::PrimeField>(
    rng: &mut impl Rng,
) -> RescueConfig<F> {
    let mut mds = vec![vec![]; 4];
    for mds_row in mds.iter_mut() {
        for _ in 0..4 {
            mds_row.push(F::rand(rng));
        }
    }

    let mut ark = vec![vec![]; 25];
    for row in ark.iter_mut() {
        for _ in 0..4 {
            row.push(F::rand(rng));
        }
    }
    // Compute alpha^{-1} mod (p - 1) for the active field so parameters stay valid across curves.
    let alpha_inv = compute_alpha_inv::<F>(5);
    RescueConfig::<F>::new(RESCUE_ROUNDS, 5, alpha_inv, mds, ark, 3, 1)
}

/// Compute the modular inverse of `alpha` modulo `p - 1`, where `p` is the field modulus.
fn compute_alpha_inv<F: PrimeField>(alpha: u64) -> BigUint {
    // modulus minus one for the field as a BigUint
    let modulus_minus_one =
        BigUint::from_bytes_le(&F::MODULUS.to_bytes_le()) - BigUint::from(1u32);
    let alpha = BigUint::from(alpha);

    // Extended Euclidean algorithm to find the inverse of `alpha` mod (p - 1)
    let mut t = BigInt::zero(); // Bezout coefficient for modulus_minus_one
    let mut new_t = BigInt::one(); // Bezout coefficient for alpha
    let mut r = BigInt::from(modulus_minus_one.clone()); // remainder for modulus_minus_one
    let mut new_r = BigInt::from(alpha); // remainder for alpha

    while new_r != BigInt::zero() {
        let quotient = &r / &new_r;
        (t, new_t) = (new_t.clone(), &t - &quotient * &new_t);
        (r, new_r) = (new_r.clone(), &r - &quotient * &new_r);
    }

    // If gcd(alpha, p-1) != 1 there is no inverse; this should not happen for valid parameters.
    assert_eq!(r, BigInt::one(), "alpha and p-1 are not coprime");

    if t < BigInt::zero() {
        t += BigInt::from(modulus_minus_one);
    }

    t.to_biguint().expect("inverse should be positive")
}

impl<F: PrimeField + ark_ff::PrimeField + ark_crypto_primitives::sponge::Absorb>
    ConstraintSynthesizer<F> for RescueDemo<F>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        if self.should_use_custom_predicate
        {
            use ark_relations::gr1cs::predicate::PredicateConstraintSystem;
            let pow_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
                2,
                vec![(F::from(1i8), vec![(0, 5)]), (F::from(-1i8), vec![(1, 1)])],
            );
            cs.register_predicate(RESCUE_PREDICATE, pow_pred).unwrap();
        }
        let params_g =
            CRHParametersVar::<F>::new_witness(cs.clone(), || Ok(self.config.clone())).unwrap();
        let mut input_g = Vec::new();

        for elem in self
            .input
            .clone()
            .ok_or(SynthesisError::AssignmentMissing)
            .unwrap()
        {
            input_g.push(FpVar::new_witness(cs.clone(), || Ok(elem)).unwrap());
        }

        let mut crh_a_g: Option<FpVar<F>> =
            Some(CRHGadget::<F>::evaluate(&params_g, &input_g).unwrap());

        for _ in 0..(self.num_invocations - 1) {
            crh_a_g =
                Some(CRHGadget::<F>::evaluate(&params_g, &vec![crh_a_g.unwrap(); WIDTH]).unwrap());
        }

        for _ in 0..self.num_instances - 1 {
            let image_instance: FpVar<F> = FpVar::new_input(cs.clone(), || {
                Ok(self.image.ok_or(SynthesisError::AssignmentMissing).unwrap())
            })
            .unwrap();

            if let Some(crh_a_g) = crh_a_g.clone() {
                let _ = crh_a_g.enforce_equal(&image_instance);
            }
        }

        Ok(())
    }
}
