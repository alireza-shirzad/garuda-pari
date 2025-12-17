use std::{collections::HashMap, fs::File, io::BufReader, path::Path, time::Instant};

use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::test_rng;
use garuda_bench::append_csv_row;
use garuda_bench::prover_prep;
use num_bigint::BigInt;
use rand::{RngCore, SeedableRng};

use serde::Deserialize;

const CSV_HEADER: &str = "benchmark,phase,duration_ms,proof_size_bytes,verified";

fn main() {
    type E = Bn254;
    type Fr = <E as ark_ec::pairing::Pairing>::ScalarField;
    let csv_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join("aadhaar-groth16.csv");
    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Fr>::new(
        "./circuits/aadhaar/aadhaar-verifier.wasm",
        "./circuits/aadhaar/aadhaar-verifier.r1cs",
    )
    .unwrap();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let mut builder = CircomBuilder::new(cfg);
    builder.inputs = load_bigint_map("./circuits/aadhaar/input.json").unwrap();
    let circom = builder.build().unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    circom.clone().generate_constraints(cs.clone()).unwrap();
    ////////////////// KeyGen ////////////////
    let start = Instant::now();
    let (pk, vk) = Groth16::<E>::setup(circom.clone(), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&vk);
    let duration = start.elapsed();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aadhaar-groth16,keygen,{:.3},,",
            duration.as_secs_f64() * 1000.0
        ),
    );

    ////////////////// Prove ////////////////

    let circom = circom.clone();
    let instance = circom.get_public_inputs().unwrap();
    let start = Instant::now();
    prover_prep::<E, _>(circom.clone());
    let prover_prep_duration = start.elapsed();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aadhaar-groth16,prover_prep,{:.3},,",
            prover_prep_duration.as_secs_f64() * 1000.0
        ),
    );
    let start = Instant::now();
    // let proof = Groth16::<E>::create_proof_with_reduction_no_zk(circom, &pk).unwrap();
    let proof = Groth16::<E>::prove(&pk, circom, &mut rng).unwrap();
    let duration = start.elapsed();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aadhaar-groth16,prover,{:.3},,",
            duration.as_secs_f64() * 1000.0
        ),
    );
    let prover_corrected = duration
        .checked_sub(prover_prep_duration)
        .unwrap_or_default();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aadhaar-groth16,prover_corrected,{:.3},,",
            prover_corrected.as_secs_f64() * 1000.0
        ),
    );

    ////////////////// Verify ////////////////
    let start = Instant::now();
    let verified = Groth16::<E>::verify_with_processed_vk(&pvk, &instance, &proof).unwrap();
    assert!(verified);
    let duration = start.elapsed();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aadhaar-groth16,verifier,{:.3},,{}",
            duration.as_secs_f64() * 1000.0,
            verified
        ),
    );
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BigIntOrVec {
    Single(String),
    Vec(Vec<String>),
}

pub fn load_bigint_map<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, Vec<BigInt>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let raw: HashMap<String, BigIntOrVec> = serde_json::from_reader(reader)?;

    let parsed = raw
        .into_iter()
        .map(|(k, v)| {
            let vec = match v {
                BigIntOrVec::Single(s) => vec![s.parse::<BigInt>()?],
                BigIntOrVec::Vec(vs) => vs
                    .into_iter()
                    .map(|s| s.parse::<BigInt>())
                    .collect::<Result<_, _>>()?,
            };
            Ok((k, vec))
        })
        .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()?;

    Ok(parsed)
}
