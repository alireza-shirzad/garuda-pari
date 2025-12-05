use std::time::Instant;

use ark_bn254::Fr as ArkFr;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ff::BigInteger;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use bellpepper_core_04::{
    num::AllocatedNum, ConstraintSystem as BellpepperCS, LinearCombination, SynthesisError,
};
use ff::PrimeField;
use spartan2::{
    provider::T256HyraxEngine,
    spartan::SpartanSNARK,
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait, Engine},
};

type E = T256HyraxEngine;
type S2Scalar = <E as Engine>::Scalar;

#[derive(Clone)]
struct ArkToBellpepperCircuit {
    a: Matrix<S2Scalar>,
    b: Matrix<S2Scalar>,
    c: Matrix<S2Scalar>,
    public_inputs: Vec<S2Scalar>,
    witness: Vec<S2Scalar>,
}

type Matrix<F> = Vec<Vec<(F, usize)>>;

impl SpartanCircuit<E> for ArkToBellpepperCircuit {
    fn public_values(&self) -> Result<Vec<S2Scalar>, SynthesisError> {
        Ok(self.public_inputs.clone())
    }

    fn shared<CS: BellpepperCS<S2Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<S2Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: BellpepperCS<S2Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<S2Scalar>],
    ) -> Result<Vec<AllocatedNum<S2Scalar>>, SynthesisError> {
        // Allocate public inputs and witnesses to mirror the arkworks assignment ordering.
        let mut vars: Vec<Option<AllocatedNum<S2Scalar>>> =
            vec![None; 1 + self.public_inputs.len() + self.witness.len()];

        for (i, value) in self.public_inputs.iter().enumerate() {
            let num = AllocatedNum::alloc_input(cs.namespace(|| format!("input_{i}")), || Ok(*value))?;
            vars[1 + i] = Some(num);
        }
        for (i, value) in self.witness.iter().enumerate() {
            let num = AllocatedNum::alloc(cs.namespace(|| format!("witness_{i}")), || Ok(*value))?;
            vars[1 + self.public_inputs.len() + i] = Some(num);
        }

        let vars: Vec<AllocatedNum<S2Scalar>> = vars
            .into_iter()
            .enumerate()
            .map(|(idx, v)| v.unwrap_or_else(|| panic!("missing variable at index {idx}")))
            .collect();

        let mut make_lc = |row: &[(S2Scalar, usize)]| -> LinearCombination<S2Scalar> {
            let mut lc = LinearCombination::zero();
            for (coeff, idx) in row {
                if *idx == 0 {
                    lc = lc + (*coeff, CS::one());
                } else {
                    let var = vars.get(*idx).expect("variable index out of bounds");
                    lc = lc + (*coeff, var.get_variable());
                }
            }
            lc
        };

        for (i, (a_row, (b_row, c_row))) in self
            .a
            .iter()
            .zip(self.b.iter().zip(self.c.iter()))
            .enumerate()
        {
            cs.enforce(
                || format!("constraint_{i}"),
                |_| make_lc(a_row),
                |_| make_lc(b_row),
                |_| make_lc(c_row),
            );
        }

        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: BellpepperCS<S2Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<S2Scalar>],
        _challenges: &[AllocatedNum<S2Scalar>],
        _challenges_values: Option<&[S2Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn main() {
    // Load Circom artifacts and build the arkworks constraint system (bn254 field).
    let cfg = CircomConfig::<ArkFr>::new("./circuits/aptos/main.wasm", "./circuits/aptos/main.r1cs")
        .expect("circom config");
    let mut builder = CircomBuilder::new(cfg);
    builder
        .load_input_json("./circuits/aptos/input.json")
        .expect("load input");
    let circom = builder.build().expect("build circom");

    let cs = ConstraintSystem::<ArkFr>::new_ref();
    circom
        .clone()
        .generate_constraints(cs.clone())
        .expect("generate constraints");
    cs.finalize();

    // Extract assignments and matrices.
    let instance_assignment = cs.instance_assignment().expect("instance assignment");
    let witness_assignment = cs.witness_assignment().expect("witness assignment");
    let matrices = cs.to_matrices().expect("matrices");
    let (_, mats) = matrices.into_iter().next().expect("no predicate matrices");
    assert!(
        mats.len() >= 3,
        "expected A/B/C matrices, found {}",
        mats.len()
    );

    // Convert arkworks field elements into Spartan2's scalar field (t256).
    let public_inputs: Vec<S2Scalar> = instance_assignment[1..]
        .iter()
        .map(|x| convert_field(*x))
        .collect();
    let witness: Vec<S2Scalar> = witness_assignment.iter().copied().map(convert_field).collect();
    let a = convert_matrix(&mats[0]);
    let b = convert_matrix(&mats[1]);
    let c = convert_matrix(&mats[2]);

    let circuit = ArkToBellpepperCircuit {
        a,
        b,
        c,
        public_inputs,
        witness,
    };

    // Setup
    let start = Instant::now();
    let (pk, vk) = SpartanSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    println!("Setup took: {:?}", start.elapsed());

    // Prepare
    let start = Instant::now();
    let prep = SpartanSNARK::<E>::prep_prove(&pk, circuit.clone(), true).expect("prep_prove failed");
    println!("Prep-prove took: {:?}", start.elapsed());

    // Prove
    let start = Instant::now();
    let proof = SpartanSNARK::<E>::prove(&pk, circuit.clone(), &prep, true).expect("prove failed");
    println!("Prove took: {:?}", start.elapsed());

    // Verify
    let start = Instant::now();
    proof.verify(&vk).expect("verify failed");
    println!("Verify took: {:?}", start.elapsed());
}

fn convert_field<F: ark_ff::PrimeField>(elem: F) -> S2Scalar {
    use num_bigint::BigUint;
    let bytes = elem.into_bigint().to_bytes_be();
    let n = BigUint::from_bytes_be(&bytes).to_str_radix(10);
    S2Scalar::from_str_vartime(&n).expect("field conversion")
}

fn convert_matrix<F: ark_ff::PrimeField>(matrix: &Matrix<F>) -> Matrix<S2Scalar> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|(coeff, idx)| (convert_field(*coeff), *idx))
                .collect()
        })
        .collect()
}
