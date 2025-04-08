use ark_bls12_381::{Bls12_381, Fr as Bls12_381_Fr};
use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::rescue::constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::rescue::RescueConfig;
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
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
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::rand::rngs::StdRng;
use ark_std::rc::Rc;
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng,
};
use garuda::Garuda;
use num_bigint::BigUint;
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::env;
use std::fs::File;
use std::ops::Neg;
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
    num_instances: usize,
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
    let params = RescueConfig::<F>::new(RESCUE_ROUNDS, 5, alpha_inv, mds, ark, 3, 1, 1);
    params
}

impl<F: PrimeField + ark_ff::PrimeField + ark_crypto_primitives::sponge::Absorb>
    ConstraintSynthesizer<F> for RescueDemo<F>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let params_g =
            CRHParametersVar::<F>::new_witness(cs.clone(), || Ok(self.config.clone())).unwrap();
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

        for _ in 0..self.num_instances - 1 {
            let image_instance: FpVar<F> = FpVar::new_input(cs.clone(), || {
                Ok(self.image.ok_or(SynthesisError::AssignmentMissing).unwrap())
            })
            .unwrap();

            if let Some(crh_a_g) = crh_a_g.clone() {
                let _ = crh_a_g.enforce_equal(&image_instance);
            }
        }

        Ok(())
    }
}

fn bench<E: Pairing>(
    _bench_name: &str,
    num_invocations: usize,
    input_size: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
) -> BenchResult
where
    E::ScalarField: PrimeField + Absorb,
    E::G1Affine: Neg<Output = E::G1Affine>,
    <E::G1Affine as AffineRepr>::BaseField: PrimeField,
    num_bigint::BigUint: From<<E::ScalarField as PrimeField>::BigInt>,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let config = create_test_rescue_parameter(&mut rng);
    let mut input = Vec::new();
    for _ in 0..9 {
        input.push(<E::ScalarField>::rand(&mut rng));
    }
    let mut expected_image = CRH::<E::ScalarField>::evaluate(&config, input.clone()).unwrap();

    for _i in 0..(num_invocations - 1) {
        let output = vec![expected_image; 9];
        expected_image = CRH::<E::ScalarField>::evaluate(&config, output.clone()).unwrap();
    }
    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let mut pk_size: usize = 0;
    let mut vk_size: usize = 0;
    let mut proof_size: usize = 0;
    let circuit = RescueDemo::<E::ScalarField> {
        input: Some(input.clone()),
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
        num_instances: input_size,
    };
    let setup_circuit = circuit.clone();
    let (mut pk, mut vk) = Garuda::<E, StdRng>::keygen(setup_circuit, &mut rng);
    for _ in 0..num_keygen_iterations {
        let setup_circuit = circuit.clone();
        let start = ark_std::time::Instant::now();
        (pk, vk) = Garuda::<E, StdRng>::keygen(setup_circuit, &mut rng);
        keygen_time += start.elapsed();
    }
    pk_size = pk.serialized_size(ark_serialize::Compress::Yes);
    vk_size = vk.serialized_size(ark_serialize::Compress::Yes);
    let prover_circuit = circuit.clone();
    let mut proof = Garuda::<E, StdRng>::prove(prover_circuit, &pk).unwrap();
    for _ in 0..num_prover_iterations {
        let prover_circuit = circuit.clone();
        let start = ark_std::time::Instant::now();
        proof = Garuda::<E, StdRng>::prove(prover_circuit, &pk).unwrap();
        prover_time += start.elapsed();
    }
    proof_size = proof.serialized_size(ark_serialize::Compress::Yes);
    let start = ark_std::time::Instant::now();
    for _ in 0..num_verifier_iterations {
        assert!(Garuda::<E, StdRng>::verify(
            &proof,
            &vk,
            &vec![expected_image; input_size - 1]
        ));
    }
    verifier_time += start.elapsed();
    let cs: gr1cs::ConstraintSystemRef<E::ScalarField> = gr1cs::ConstraintSystem::new_ref();
    cs.set_instance_outliner(InstanceOutliner {
        pred_label: R1CS_PREDICATE_LABEL.to_string(),
        func: Rc::new(outline_r1cs),
    });
    let _ = circuit.clone().generate_constraints(cs.clone());
    cs.finalize();

    let bench_result = BenchResult {
        curve: type_name::<E>().to_string(),
        num_constraints: cs.num_constraints(),
        predicate_constraints: cs.get_all_predicates_num_constraints(),
        num_invocations,
        input_size,
        num_thread,
        num_keygen_iterations: num_keygen_iterations as usize,
        num_prover_iterations: num_prover_iterations as usize,
        num_verifier_iterations: num_verifier_iterations as usize,
        pk_size,
        vk_size,
        proof_size,
        prover_time: (prover_time / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
    };
    bench_result
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

    // bench_smart_contract();

    // /////////// Benchmark Pari for different input sizes ///////////
    // let num_inputs: Vec<usize> = (0..12).map(|i| 2_usize.pow(i)).collect();
    // for i in 0..num_inputs.len() {
    //     let _ = bench::<Bls12_381>("bench", 1, num_inputs[i], 1, 1, 100, num_thread)
    //         .save_to_csv("garuda-gr1cs.csv", true);
    // }

    /////////// Benchmark Pari for different circuit sizes ///////////
    const MAX_LOG2_NUM_INVOCATIONS: usize = 30;
    // let num_invocations: Vec<usize> = (0..MAX_LOG2_NUM_INVOCATIONS)
    //     .map(|i| 2_usize.pow(i as u32))
    //     .collect();
    let num_invocations = vec![64];
    for i in 0..num_invocations.len() {
        let _ = bench::<Bls12_381>("bench", num_invocations[i], 20, 1, 1, 100, num_thread)
            .save_to_csv("garuda-gr1cs.csv", true);
    }
}
