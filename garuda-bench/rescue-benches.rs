use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::rescue::gr1cs_constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::GR1CSVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::predicate::PredicateConstraintSystem;
use ark_std::rand::rngs::StdRng;
use ark_test_curves::bls12_381::{Bls12_381, Fr as BlsFr12_381_Fr};
use garuda::{Garuda, write_bench};
use garuda_bench::BenchResult;

use num_bigint::BigUint;
use rayon::ThreadPoolBuilder;

use ark_crypto_primitives::sponge::rescue::RescueConfig;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::{gr1cs, ns};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng,
};
use std::env;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};
const RESCUE_ROUNDS: usize = 12;

/// This is our demo circuit for proving knowledge of the
/// preimage of a Rescue hash invocation.
#[derive(Clone)]
struct RescueDemo<F: PrimeField> {
    input: Option<Vec<F>>,
    image: Option<F>,
    config: RescueConfig<F>,
    num_invocations: usize,
}

pub fn create_test_rescue_parameter<F: PrimeField + ark_ff::PrimeField>(
    rng: &mut impl Rng,
) -> RescueConfig<F> {
    let mut mds = vec![vec![]; 4];
    for i in 0..4 {
        for _ in 0..4 {
            mds[i].push(F::rand(rng));
        }
    }

    let mut ark = vec![vec![]; 25];
    for i in 0..(2 * RESCUE_ROUNDS + 1) {
        for _ in 0..4 {
            ark[i].push(F::rand(rng));
        }
    }
    let alpha_inv: BigUint = BigUint::from_str(
        "20974350070050476191779096203274386335076221000211055129041463479975432473805",
    )
    .unwrap();
    let params = RescueConfig::<F>::new(RESCUE_ROUNDS, 5, alpha_inv, mds, ark, 3, 1);
    params
}

impl<F: PrimeField + ark_ff::PrimeField + ark_crypto_primitives::sponge::Absorb>
    ConstraintSynthesizer<F> for RescueDemo<F>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let params_g =
            CRHParametersVar::<F>::new_witness(cs.clone(), || Ok(self.config.clone())).unwrap();
        let _ = cs.clone().register_predicate(
            "XXX",
            PredicateConstraintSystem::new_polynomial_predicate(2, vec![
                (F::from(1i8), vec![(0, 5)]),
                (F::from(-1i8), vec![(1, 1)]),
            ]),
        );

        let mut input_g = Vec::new();

        for elem in self
            .input
            .clone()
            .ok_or(SynthesisError::AssignmentMissing)
            .unwrap()
        {
            input_g.push(FpVar::new_witness(cs.clone(), || Ok(elem)).unwrap());
        }

        let mut crh_a_g: Option<FpVar<F>> =
            Some(CRHGadget::<F>::evaluate(&params_g, &input_g).unwrap());

        for _ in 0..(self.num_invocations - 1) {
            crh_a_g =
                Some(CRHGadget::<F>::evaluate(&params_g, &vec![crh_a_g.unwrap(); 9]).unwrap());
        }

        let image_instance: FpVar<F> = FpVar::new_input(cs.clone(), || {
            Ok(self.image.ok_or(SynthesisError::AssignmentMissing).unwrap())
        })
        .unwrap();

        if let Some(crh_a_g) = crh_a_g {
            let _ = crh_a_g.enforce_equal(&image_instance);
        }

        Ok(())
    }
}

fn benchmark(num_invocations: usize) {
    println!(
        "Benchmarking Garuda for number of Rescue Invocation = {}",
        num_invocations
    );
    write_bench!("{} ", num_invocations);
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let config = create_test_rescue_parameter(&mut rng);

    // Generate a random preimage and compute the image
    let mut input = Vec::new();
    for _ in 0..9 {
        input.push(BlsFr12_381_Fr::rand(&mut rng));
    }
    let mut expected_image = CRH::<BlsFr12_381_Fr>::evaluate(&config, input.clone()).unwrap();

    for i in 0..(num_invocations - 1) {
        let output = vec![expected_image; 9];
        expected_image = CRH::<BlsFr12_381_Fr>::evaluate(&config, output.clone()).unwrap();
    }

    let c = RescueDemo::<BlsFr12_381_Fr> {
        input: Some(input.clone()),
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
    };

    ///////////////////////////////////////////////////////////////////////////////////
    // Create parameters for our circuit

    let (pk, vk) = { Garuda::<Bls12_381, StdRng>::keygen(c.clone(), &mut rng) };

    write_bench!("{} ", pk.serialized_size(ark_serialize::Compress::Yes));
    write_bench!("{} ", vk.serialized_size(ark_serialize::Compress::Yes));
    // Create and write to the file

    ///////////////////////////////////////////////
    // Creating the proof

    // Create a groth16 proof with our parameters.
    let proof = Garuda::<Bls12_381, StdRng>::prove(c, pk).unwrap();

    write_bench!("{} ", proof.serialized_size(ark_serialize::Compress::Yes));

    ///////////////////////////////////////////////
    // Verifying the proof

    let mut total_verifying: Duration = Duration::new(0, 0);
    let start = Instant::now();

    assert!(Garuda::<Bls12_381, StdRng>::verify(proof, vk, &[
        expected_image
    ],));

    // proof.write(&mut proof_vec).unwrap();

    // let proof = Proof::read(&proof_vec[..]).unwrap();
    // Check the proof

    total_verifying += start.elapsed();
    write_bench!("{}\n", total_verifying.as_micros());
}

macro_rules! garuda_bench {
    ($bench_name:ident, $num_invocations:expr, $num_iterations:expr, $num_thread:expr, $bench_pairing_engine:ty, $bench_field:ty) => {{
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let config = create_test_rescue_parameter(&mut rng);
        let mut input = Vec::new();
        for _ in 0..9 {
            input.push(BlsFr12_381_Fr::rand(&mut rng));
        }
        let mut expected_image = CRH::<BlsFr12_381_Fr>::evaluate(&config, input.clone()).unwrap();

        for _i in 0..($num_invocations - 1) {
            let output = vec![expected_image; 9];
            expected_image = CRH::<BlsFr12_381_Fr>::evaluate(&config, output.clone()).unwrap();
        }

        let mut prover_time = Duration::new(0, 0);
        let mut setup_time = Duration::new(0, 0);
        let mut verifier_time = Duration::new(0, 0);
        let mut pk_size: usize = 0;
        let mut vk_size: usize = 0;
        let mut proof_size: usize = 0;
        let circuit = RescueDemo::<$bench_field> {
            input: Some(input.clone()),
            image: Some(expected_image),
            config: config.clone(),
            num_invocations: $num_invocations,
        };
        for _ in 0..$num_iterations {
            let start = ark_std::time::Instant::now();
            let setup_circuit = circuit.clone();
            let (pk, vk) = Garuda::<$bench_pairing_engine, StdRng>::keygen(setup_circuit, &mut rng);
            setup_time += start.elapsed();
            pk_size = pk.serialized_size(ark_serialize::Compress::Yes);
            vk_size = vk.serialized_size(ark_serialize::Compress::Yes);
            let start = ark_std::time::Instant::now();
            let prover_circuit = circuit.clone();
            let proof = Garuda::<Bls12_381, StdRng>::prove(prover_circuit, pk).unwrap();
            prover_time += start.elapsed();
            proof_size = proof.serialized_size(ark_serialize::Compress::Yes);
            let start = ark_std::time::Instant::now();
            assert!(Garuda::<Bls12_381, StdRng>::verify(proof, vk, &[
                expected_image
            ],));
            verifier_time += start.elapsed();
        }
        let cs: gr1cs::ConstraintSystemRef<$bench_field> = gr1cs::ConstraintSystem::new_ref();
        cs.outline_instances();
        let _ = circuit.clone().generate_constraints(cs.clone());
        cs.finalize();

        let bench_result = BenchResult {
            curve: "Bls12_381".to_string(),
            num_constraints: cs.num_constraints(),
            predicate_constraints: cs.get_all_predicates_num_constraints(),
            num_invocations: $num_invocations,
            num_thread: $num_thread,
            num_iterations: $num_iterations,
            pk_size,
            vk_size,
            proof_size,
            prover_time: (prover_time / $num_iterations),
            verifier_time: (verifier_time / $num_iterations),
            setup_time: (setup_time / $num_iterations),
        };
        bench_result
    }};
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

    garuda_bench!(garuda_bench, 72, 5, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(false);
    garuda_bench!(garuda_bench, 144, 5, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    garuda_bench!(garuda_bench, 288, 5, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    garuda_bench!(garuda_bench, 577, 5, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    garuda_bench!(garuda_bench, 1154, 1, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    garuda_bench!(garuda_bench, 2309, 1, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    garuda_bench!(garuda_bench, 4619, 1, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    garuda_bench!(garuda_bench, 9238, 1, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
    garuda_bench!(garuda_bench, 18477, 1, num_thread, Bls12_381, BlsFr12_381_Fr).save_to_csv(true);
}
