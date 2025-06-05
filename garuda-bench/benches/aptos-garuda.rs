use std::time::Instant;

use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::test_rng;
use garuda::Garuda;
use rand::{RngCore, SeedableRng};

#[tokio::main]
async fn main() {
    type E = Bn254;
    type Fr = <E as ark_ec::pairing::Pairing>::ScalarField;

    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Fr>::new("./circuits/aptos/main.wasm", "./circuits/aptos/main.r1cs")
        .unwrap();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let mut builder = CircomBuilder::new(cfg);
    builder
        .load_input_json("./circuits/aptos/input.json")
        .unwrap();
    let circom = builder.build().unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    circom.clone().generate_constraints(cs.clone()).unwrap();
    let start = Instant::now();
    let (pk, vk) = Garuda::<E>::keygen(circom.clone(), true, &mut rng);
    let duration = start.elapsed();
    println!("Keygen took: {:?}", duration);
    let circom = circom.clone();
    let instance = circom.get_public_inputs().unwrap();
    let start = Instant::now();
    let proof = Garuda::prove(&pk, Some(&mut rng), circom).unwrap();
    let duration = start.elapsed();
    println!("Prover took: {:?}", duration);
    let start = Instant::now();
    assert!(Garuda::verify(&proof, &vk, &instance));
    let duration = start.elapsed();
    println!("Verifier took: {:?}", duration);
}
