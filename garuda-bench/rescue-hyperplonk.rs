use ark_bls12_381_v4::{Bls12_381, Fr as Bls12_381_Fr};
use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::rescue::constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::rescue::RescueConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs;
use ark_relations::gr1cs::R1CS_PREDICATE_LABEL;
use ark_relations::gr1cs::instance_outliner::InstanceOutliner;
use ark_relations::gr1cs::instance_outliner::outline_r1cs;
use ark_relations::gr1cs::predicate::PredicateConstraintSystem;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize_v4::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::collections::BTreeMap;
use ark_std::log2;
use ark_std::rand::rngs::StdRng;
use ark_std::rc::Rc;
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng,
};
use core::num;
use hp_hyperplonk::HyperPlonkSNARK;
use hp_hyperplonk::prelude::CustomizedGates;
use hp_hyperplonk::prelude::MockCircuit;
use hp_subroutines::MultilinearKzgPCS;
use hp_subroutines::MultilinearUniversalParams;
use hp_subroutines::PolyIOP;
use hp_subroutines::PolynomialCommitmentScheme;
use num_bigint::BigUint;
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::env;
use std::fmt::format;
use std::fs::File;
use std::mem::size_of_val;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};

macro_rules! bench {
    ($bench_name:ident, $num_invocations:expr, $num_keygen_iterations:expr, $num_prover_iterations:expr, $num_verifier_iterations:expr, $num_thread:expr, $bench_pairing_engine:ty, $bench_field:ty,$pcs_srs:expr,$jf_gate:expr) => {{
        let mut prover_time = Duration::new(0, 0);
        let mut keygen_time = Duration::new(0, 0);
        let mut verifier_time = Duration::new(0, 0);
        let nv = log2(num_constr_from_num_invoc($num_invocations)) as usize;
        let circuit = MockCircuit::<$bench_field>::new(1 << nv, $jf_gate);
        assert!(circuit.is_satisfied());
        let index = circuit.index.clone();
        let (mut pk, mut vk) = <PolyIOP<$bench_field> as HyperPlonkSNARK<
            $bench_pairing_engine,
            MultilinearKzgPCS<$bench_pairing_engine>,
        >>::preprocess(&index, $pcs_srs)
        .unwrap();

        for _ in 0..$num_keygen_iterations {
            // let setup_circuit = circuit.clone();
            let start = ark_std::time::Instant::now();
            (pk, vk) = <PolyIOP<$bench_field> as HyperPlonkSNARK<
                $bench_pairing_engine,
                MultilinearKzgPCS<$bench_pairing_engine>,
            >>::preprocess(&index, $pcs_srs)
            .unwrap();
            keygen_time += start.elapsed();
        }

        let pk_size = size_of_val(&pk);
        let vk_size = size_of_val(&vk);
        // let prover_circuit = circuit.clone();
        let mut proof = <PolyIOP<$bench_field> as HyperPlonkSNARK<
            $bench_pairing_engine,
            MultilinearKzgPCS<$bench_pairing_engine>,
        >>::prove(&pk, &circuit.public_inputs, &circuit.witnesses)
        .unwrap();
        for _ in 0..$num_keygen_iterations {
            let start = ark_std::time::Instant::now();
            proof = <PolyIOP<$bench_field> as HyperPlonkSNARK<
                $bench_pairing_engine,
                MultilinearKzgPCS<$bench_pairing_engine>,
            >>::prove(&pk, &circuit.public_inputs, &circuit.witnesses)
            .unwrap();
            prover_time += start.elapsed();
        }
        let proof_size = size_of_val(&proof);
        let start = ark_std::time::Instant::now();
        for _ in 0..$num_verifier_iterations {
            let verify = <PolyIOP<$bench_field> as HyperPlonkSNARK<
                Bls12_381,
                MultilinearKzgPCS<Bls12_381>,
            >>::verify(&vk, &circuit.public_inputs, &proof)
            .unwrap();
            assert!(verify);
        }
        verifier_time += start.elapsed();

        let bench_result = BenchResult {
            curve: type_name::<$bench_pairing_engine>().to_string(),
            num_constraints: 1 << nv,
            predicate_constraints: BTreeMap::new(),
            num_invocations: $num_invocations,
            num_thread: $num_thread,
            num_keygen_iterations: $num_keygen_iterations,
            num_prover_iterations: $num_prover_iterations,
            num_verifier_iterations: $num_verifier_iterations,
            pk_size,
            vk_size,
            proof_size,
            prover_time: (prover_time / $num_prover_iterations),
            verifier_time: (verifier_time / $num_verifier_iterations),
            keygen_time: (keygen_time / $num_keygen_iterations),
        };
        bench_result
    }};
}

fn num_constr_from_num_invoc(num_invocations: usize) -> usize {
    num_invocations * 284
}

fn main() {
    let num_thread = env::var("NUM_THREAD")
        .unwrap_or_else(|_| "default".to_string())
        .parse::<usize>()
        .unwrap();

    ThreadPoolBuilder::new()
        .num_threads(num_thread)
        .build_global()
        .unwrap();

    const MAX_LOG_VAR: usize = 25;
    let srs_file_path: String = format!("srs_{}.bin", MAX_LOG_VAR);
    let mut rng = test_rng();
    let jf_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
    let pcs_srs: MultilinearUniversalParams<Bls12_381> = if Path::new(&srs_file_path).exists() {
        dbg!("File exists");
        // The file exists; read and print its contents
        let mut file = File::open(&srs_file_path).unwrap();
        let mut reader = std::io::BufReader::new(file);
        MultilinearUniversalParams::<Bls12_381>::deserialize_uncompressed_unchecked(reader).unwrap()
    } else {
        dbg!("File does not exist");
        // The file does not exist; create it and write some content
        let mut file = File::create(&srs_file_path).unwrap();
        let mut writer = std::io::BufWriter::new(file);
        let pcs_srs =
            MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, MAX_LOG_VAR).unwrap();
        pcs_srs.serialize_uncompressed(writer).unwrap();
        pcs_srs
    };
    let _ = bench!(
        bench,
        72,
        1,
        2,
        100,
        num_thread,
        Bls12_381,
        Bls12_381_Fr,
        &pcs_srs,
        &jf_gate
    )
    .save_to_csv("hyperplonk.csv", false);
    bench!(
        bench,
        144,
        1,
        2,
        100,
        num_thread,
        Bls12_381,
        Bls12_381_Fr,
        &pcs_srs,
        &jf_gate
    )
    .save_to_csv("hyperplonk.csv", true);
    bench!(
        bench,
        288,
        1,
        2,
        100,
        num_thread,
        Bls12_381,
        Bls12_381_Fr,
        &pcs_srs,
        &jf_gate
    )
    .save_to_csv("hyperplonk.csv", true);
    bench!(
        bench,
        577,
        1,
        2,
        100,
        num_thread,
        Bls12_381,
        Bls12_381_Fr,
        &pcs_srs,
        &jf_gate
    )
    .save_to_csv("hyperplonk.csv", true);
    bench!(
        bench,
        1154,
        1,
        2,
        100,
        num_thread,
        Bls12_381,
        Bls12_381_Fr,
        &pcs_srs,
        &jf_gate
    )
    .save_to_csv("hyperplonk.csv", true);
    bench!(
        bench,
        2309,
        1,
        2,
        100,
        num_thread,
        Bls12_381,
        Bls12_381_Fr,
        &pcs_srs,
        &jf_gate
    )
    .save_to_csv("hyperplonk.csv", true);
    // // bench!(bench, 4619, 1, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    // // bench!(bench, 9238, 1, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    // // bench!(
    // //     bench,
    // //     18477,
    // //     1,
    // //     num_thread,
    // //     Bls12_381,
    // //     BlsFr12_381_Fr
    // // )
    // // .save_to_csv(true);
}
