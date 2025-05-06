use std::{collections::HashMap, fs::File, io::BufReader, path::Path, time::Instant};

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::test_rng;
use garuda::Garuda;
use num_bigint::BigInt;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rayon::ThreadPoolBuilder;
use serde::Deserialize;
// Keygen took: 19.18047725s
// Prover took: 58.543421709s
// Verifier took: 5.030917ms
#[tokio::main]
async fn main() {
    type E = Bn254;
    type Fr = <E as ark_ec::pairing::Pairing>::ScalarField;

    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Fr>::new("./circuits/aptos/main.wasm", "./circuits/aptos/main.r1cs")
        .unwrap();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let mut builder = CircomBuilder::new(cfg);
    builder.load_input_json("./circuits/aptos/input.json").unwrap();
    let circom = builder.build().unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    circom.clone().generate_constraints(cs.clone()).unwrap();
    let start = Instant::now();
    let (pk, vk) = Garuda::<E, StdRng>::keygen(circom.clone(), &mut rng);
    let duration = start.elapsed();
    println!("Keygen took: {:?}", duration);
    let start = Instant::now();
    let proof = Garuda::<E, StdRng>::prove(circom.clone(), &pk).unwrap();
    let duration = start.elapsed();
    println!("Prover took: {:?}", duration);
    let instance = circom.get_public_inputs().unwrap();
    let start = Instant::now();
    assert!(Garuda::<E, StdRng>::verify(&proof, &vk, &instance));
    let duration = start.elapsed();
    println!("Verifier took: {:?}", duration);
}
// #[derive(Debug, Deserialize)]
// #[serde(untagged)]
// enum BigIntOrVec {
//     Single(String),
//     Vec(Vec<String>),
// }

// pub fn load_bigint_map<P: AsRef<Path>>(
//     path: P,
// ) -> Result<HashMap<String, Vec<BigInt>>, Box<dyn std::error::Error>> {
//     let file = File::open(path)?;
//     let reader = BufReader::new(file);

//     let raw: HashMap<String, BigIntOrVec> = serde_json::from_reader(reader)?;

//     let parsed = raw
//         .into_iter()
//         .map(|(k, v)| {
//             let vec = match v {
//                 BigIntOrVec::Single(s) => vec![s.parse::<BigInt>()?],
//                 BigIntOrVec::Vec(vs) => vs
//                     .into_iter()
//                     .map(|s| s.parse::<BigInt>())
//                     .collect::<Result<_, _>>()?,
//             };
//             Ok((k, vec))
//         })
//         .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()?;

//     Ok(parsed)
// }
