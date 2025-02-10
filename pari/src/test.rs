#[cfg(test)]
use ark_bls12_381::{Bls12_381, Fr as Bls12_381_Fr};
use ark_bn254::{Bn254, Fr as Bn254_Fr};
use ark_ec::pairing::Pairing;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::gr1cs::{ConstraintSystemRef, OptimizationGoal};
use ark_relations::{
    gr1cs::{
        predicate::PredicateConstraintSystem, ConstraintSynthesizer, ConstraintSystem,
        LinearCombination, SynthesisError, Variable,
    },
    lc, ns,
};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use ark_std::{rand::Rng, test_rng};

use crate::{
    data_structures::{Proof, ProvingKey, VerifyingKey},
    Pari,
};
use ark_std::ops::Neg;
#[test]
fn run_test() {
    let _ = test_circuit::<Bn254>();
}

fn test_circuit<E: Pairing>()
where
    E::G1Affine: Neg<Output = E::G1Affine>,
    E: Pairing,
    E::ScalarField: Field,
    E::ScalarField: std::convert::From<i32>,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let a_val = E::ScalarField::rand(&mut rng);
    let b_val = E::ScalarField::rand(&mut rng);
    let circuit = Circuit1 {
        a: Some(a_val),
        b: Some(b_val),
    };
    let (pk, vk): (ProvingKey<E>, VerifyingKey<E>) =
        Pari::<E, StdRng>::keygen(circuit.clone(), &mut rng);
    let proof: Proof<E> = Pari::<E, StdRng>::prove(circuit.clone(), &pk).unwrap();
    let input_assignment = [a_val * b_val];
    assert!(Pari::<E, StdRng>::verify(&proof, &vk, &input_assignment));
}

#[derive(Clone)]
struct Circuit1<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for Circuit1<ConstraintF> {
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
