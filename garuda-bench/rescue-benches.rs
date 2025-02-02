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
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use garuda::{Garuda, write_bench};

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
    N: usize,
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
                (F::from(-1i8) , vec![(1, 1)]),
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

        for _ in 0..(self.N - 1) {
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
        if cs.is_in_setup_mode() {
            write_bench!("{} ", cs.num_constraints());
        }

        Ok(())
    }
}

fn benchmark(N: usize) {
    println!(
        "Benchmarking Garuda for number of Rescue Invocation = {}",
        N
    );
    write_bench!("{} ", N);
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let config = create_test_rescue_parameter(&mut rng);

    // Generate a random preimage and compute the image
    let mut input = Vec::new();
    for _ in 0..9 {
        input.push(Fr::rand(&mut rng));
    }
    let mut expected_image = CRH::<Fr>::evaluate(&config, input.clone()).unwrap();

    for i in 0..(N - 1) {
        let output = vec![expected_image; 9];
        expected_image = CRH::<Fr>::evaluate(&config, output.clone()).unwrap();
    }

    let c = RescueDemo::<Fr> {
        input: Some(input.clone()),
        image: Some(expected_image),
        config: config.clone(),
        N,
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
fn main() {
    let path = Path::new("garuda_bench.txt");
    let num_thread = env::var("NUM_THREAD")
        .unwrap_or_else(|_| "default".to_string())
        .parse::<usize>()
        .unwrap();
    let mut file = File::create(&path).unwrap();
    println!(
        "----------------------Garuda Benchmarking with {} threads, result stored in garuda_bench.txt ----------------------",
        num_thread
    );
    ThreadPoolBuilder::new()
        .num_threads(num_thread)
        .build_global()
        .unwrap();
    write_bench!(
        "# Invokations Constraints Setup-Time(ms) PK-Size(b) VK-Size(b) Prover-Time(ms) Proof-Size(b) Verifier-Time(us)\n",
    );
    let num_invokations = vec![72, 144, 288, 577, 1154, 2309, 4619, 9238, 18477];
    for N in num_invokations.iter() {
        benchmark(*N);
    }
    // benchmark(100);
    println!("Hello");
}
