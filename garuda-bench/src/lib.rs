pub mod bellpepper_adapter;

use ark_crypto_primitives::{
    crh::{
        rescue::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    },
    sponge::rescue::RescueConfig,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{ConstraintSynthesizer, SynthesisError};
use garuda::ConstraintSystemRef;
use num_bigint::BigUint;
use rand::Rng;
use std::str::FromStr;

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
}

pub fn create_test_rescue_parameter<F: PrimeField + ark_ff::PrimeField>(
    rng: &mut impl Rng,
) -> RescueConfig<F> {
    let mut mds = vec![vec![]; 4];
    for i in 0..4 {
        for _ in 0..4 {
            mds[i].push(F::rand(rng));
        }
    }

    let mut ark = vec![vec![]; 25];
    for i in 0..(2 * RESCUE_ROUNDS + 1) {
        for _ in 0..4 {
            ark[i].push(F::rand(rng));
        }
    }
    let alpha_inv: BigUint = BigUint::from_str(
        "20974350070050476191779096203274386335076221000211055129041463479975432473805",
    )
    .unwrap();
    RescueConfig::<F>::new(RESCUE_ROUNDS, 5, alpha_inv, mds, ark, 3, 1, 1)
}

impl<F: PrimeField + ark_ff::PrimeField + ark_crypto_primitives::sponge::Absorb>
    ConstraintSynthesizer<F> for RescueDemo<F>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        #[cfg(feature = "gr1cs")]
        {
            use ark_relations::gr1cs::predicate::PredicateConstraintSystem;
            let pow_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
                2,
                vec![(F::from(1i8), vec![(0, 5)]), (F::from(-1i8), vec![(1, 1)])],
            );
            cs.register_predicate("XXX", pow_pred).unwrap();
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
