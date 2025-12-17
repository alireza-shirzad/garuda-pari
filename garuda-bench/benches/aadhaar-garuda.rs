use std::{
    fs::{create_dir_all, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};

use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::test_rng;
use garuda::Garuda;
use rand::{RngCore, SeedableRng};

const CSV_HEADER: &str = "benchmark,phase,duration_ms,proof_size_bytes,verified";

fn append_csv_row(path: &Path, row: &str) {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).unwrap();
    }
    let file_exists = path.exists();
    let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
    if !file_exists {
        writeln!(file, "{CSV_HEADER}").unwrap();
    }
    writeln!(file, "{row}").unwrap();
}

fn main() {
    type E = Bn254;
    type Fr = <E as ark_ec::pairing::Pairing>::ScalarField;
    let csv_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join("aadhaar-garuda.csv");

    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Fr>::new(
        "./circuits/aadhaar/aadhaar-verifier.wasm",
        "./circuits/aadhaar/aadhaar-verifier.r1cs",
    )
    .unwrap();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let mut builder = CircomBuilder::new(cfg);
    builder
        .load_input_json("./circuits/aadhaar/input.json")
        .unwrap();
    let circom = builder.build().unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    circom.clone().generate_constraints(cs.clone()).unwrap();
    let start = Instant::now();
    let (pk, vk) = Garuda::<E>::keygen(circom.clone(), true, &mut rng);
    let duration = start.elapsed();
    append_csv_row(
        &csv_path,
        &format!("aadhaar-garuda,keygen,{:.3},,", duration.as_secs_f64() * 1000.0),
    );
    let circom = circom.clone();
    let instance = circom.get_public_inputs().unwrap();
    let start = Instant::now();
    let proof = Garuda::prove(&pk, Some(&mut rng), circom).unwrap();
    let duration = start.elapsed();
    append_csv_row(
        &csv_path,
        &format!("aadhaar-garuda,prover,{:.3},,", duration.as_secs_f64() * 1000.0),
    );
    let start = Instant::now();
    let verified = Garuda::verify(&proof, &vk, &instance);
    assert!(verified);
    let duration = start.elapsed();
    append_csv_row(
        &csv_path,
        &format!(
            "aadhaar-garuda,verifier,{:.3},,{}",
            duration.as_secs_f64() * 1000.0,
            verified
        ),
    );
}
