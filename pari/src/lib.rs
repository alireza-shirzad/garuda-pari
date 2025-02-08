#![feature(associated_type_defaults)]
#![allow(unreachable_patterns)]

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::{
    gr1cs::{
        predicate::PredicateConstraintSystem, ConstraintSynthesizer, ConstraintSystem,
        LinearCombination, SynthesisError, Variable,
    },
    lc, ns,
};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};

pub use ark_relations::gr1cs::ConstraintSystemRef;
use ark_std::marker::PhantomData;

pub mod data_structures;
mod generator;
mod prover;
mod verifier;

/// The SNARK of [[Pari]](https://eprint.iacr.org/2024/1245.pdf).
pub struct Pari<E: Pairing, R: RngCore> {
    _p: PhantomData<E>,
    _r: PhantomData<R>,
}

impl<E: Pairing, R: RngCore> Pari<E, R> {
    pub const SNARK_NAME: &'static str = "Pari";
}
#[cfg(test)]
mod temp_tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_poly::GeneralEvaluationDomain;
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
    use ark_std::{
        rand::{rngs::StdRng, Rng, RngCore, SeedableRng},
        test_rng,
    };

    use crate::{
        data_structures::{Proof, ProvingKey, VerifyingKey},
        MySillyCircuit, Pari,
    };

    #[test]
    fn temp() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let a_val = Fr::rand(&mut rng);
        let b_val = Fr::rand(&mut rng);
        let circuit = MySillyCircuit {
            a: Some(a_val),
            b: Some(b_val),
        };
        let (pk, vk): (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) =
            Pari::<Bls12_381, StdRng>::keygen(circuit.clone(), &mut rng);
        let proof: Proof<Bls12_381> =
            Pari::<Bls12_381, StdRng>::prove(circuit.clone(), &pk).unwrap();
        let input_assignment = [a_val * b_val];
        assert!(Pari::<Bls12_381, StdRng>::verify(
            &proof,
            &vk,
            &input_assignment
        ));
    }
}

#[derive(Clone)]
struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a *= &b;
            Ok(a)
        })?;

        cs.enforce_r1cs_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_r1cs_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_r1cs_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_r1cs_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_r1cs_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_r1cs_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}
