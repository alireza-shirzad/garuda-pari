use std::{
    path::Path,
    time::Instant,
};

use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ec::pairing::Pairing;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use garuda_bench::{append_csv_row, arkwork_r1cs_adapter};
use libspartan::{SNARKGens, SNARK};
use merlin::Transcript;
use rand::{RngCore, SeedableRng};

const CSV_HEADER: &str = "benchmark,phase,duration_ms,proof_size_bytes,verified";

fn main() {
    type E = Bn254;
    type G = <E as Pairing>::G1;
    type Fr = <E as Pairing>::ScalarField;
    let csv_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join("aptos-spartan.csv");

    // Load the WASM and R1CS for witness and proof generation.
    let cfg = CircomConfig::<Fr>::new("./circuits/aptos/main.wasm", "./circuits/aptos/main.r1cs")
        .expect("circom config");
    let rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let mut builder = CircomBuilder::new(cfg);
    builder
        .load_input_json("./circuits/aptos/input.json")
        .expect("load input");
    let circom = builder.build().expect("build circom");

    // Build a constraint system and adapt it to libspartan's R1CS format.
    let cs = ConstraintSystem::<Fr>::new_ref();
    circom
        .clone()
        .generate_constraints(cs.clone())
        .expect("generate constraints");
    cs.finalize();
    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(false, cs, rng.clone());

    // Key generation (encode the instance).
    let start = Instant::now();
    let gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
    let (comm, decomm) = SNARK::encode(&inst, &gens);
    let keygen_time = start.elapsed();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aptos-spartan,keygen,{:.3},,",
            keygen_time.as_secs_f64() * 1000.0
        ),
    );

    // Proving.
    let start = Instant::now();
    let mut prover_transcript = Transcript::new(b"aptos-spartan");
    let proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        vars.clone(),
        &inputs,
        &gens,
        &mut prover_transcript,
    );
    let proof_size = proof.compressed_size();
    let prover_time = start.elapsed();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aptos-spartan,prover,{:.3},{},",
            prover_time.as_secs_f64() * 1000.0,
            proof_size
        ),
    );

    // Verifying.
    let start = Instant::now();
    let mut verifier_transcript = Transcript::new(b"aptos-spartan");
    let ok = proof
        .verify(&comm, &inputs, &mut verifier_transcript, &gens)
        .is_ok();
    let verifier_time = start.elapsed();
    append_csv_row(
        CSV_HEADER,
        &csv_path,
        &format!(
            "aptos-spartan,verifier,{:.3},,{}",
            verifier_time.as_secs_f64() * 1000.0,
            ok
        ),
    );
}