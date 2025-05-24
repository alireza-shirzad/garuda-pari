use std::time::Instant;

use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::test_rng;
use garuda::Garuda;
use rand::{RngCore, SeedableRng};

// Keygen took: 19.18047725s
// Prover took: 58.543421709s
// Verifier took: 5.030917ms
#[tokio::main]
async fn main() {
    type E = Bn254;
    type Fr = <E as ark_ec::pairing::Pairing>::ScalarField;

    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Fr>::new("./circuits/aadhaar/aadhaar-verifier.wasm", "./circuits/aadhaar/aadhaar-verifier.r1cs")
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
    let (pk, vk) = Garuda::<E>::keygen(circom.clone(), &mut rng);
    let duration = start.elapsed();
    println!("Keygen took: {:?}", duration);
    let circom = circom.clone();
    let instance = circom.get_public_inputs().unwrap();
    let start = Instant::now();
    let proof = Garuda::prove(&pk, circom).unwrap();
    let duration = start.elapsed();
    println!("Prover took: {:?}", duration);
    let start = Instant::now();
    assert!(Garuda::verify(&proof, &vk, &instance));
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
