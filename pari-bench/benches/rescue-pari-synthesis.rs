use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::sponge::rescue::RescueConfig;
use ark_crypto_primitives::{crh::rescue::CRH, sponge::Absorb};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_relations::gr1cs::instance_outliner::InstanceOutliner;
use ark_relations::gr1cs::instance_outliner::{outline_r1cs, outline_sr1cs};
use ark_relations::gr1cs::predicate::polynomial_constraint::SR1CS_PREDICATE_LABEL;
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::R1CS_PREDICATE_LABEL;
use ark_relations::gr1cs::{self, ConstraintSystem, OptimizationGoal};
use ark_relations::sr1cs::Sr1csAdapter;
use ark_serialize::CanonicalSerialize;
use ark_std::rc::Rc;
use ark_std::UniformRand;
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use pari::Pari;
use pari_bench::RescueDemo;
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::env;
use std::time::Duration;
use std::{any::type_name, ops::Neg};
fn bench<E: Pairing>(
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
    let config = RescueConfig::<E::ScalarField>::test_conf();

    let mut rescue_input = Vec::new();
    for _ in 0..9 {
        rescue_input.push(E::ScalarField::rand(&mut rng));
    }
    let mut expected_image =
        CRH::<E::ScalarField>::evaluate(&config, rescue_input.clone()).unwrap();

    for _i in 0..(num_invocations - 1) {
        let output = vec![expected_image; 9];
        expected_image = CRH::evaluate(&config, output.clone()).unwrap();
    }

    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let circuit = RescueDemo {
        input: Some(rescue_input.clone()),
        num_instances: input_size,
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
    };
    let setup_circuit = circuit.clone();
    let (mut pk, mut vk) = Pari::<E>::keygen(setup_circuit, &mut rng);
    let pk_size = pk.serialized_size(ark_serialize::Compress::Yes);
    let vk_size = vk.serialized_size(ark_serialize::Compress::Yes);
    let prover_circuit = circuit.clone();
    let start = ark_std::time::Instant::now();
    let cs: gr1cs::ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    prover_circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let sr1cs_cs =
        Sr1csAdapter::r1cs_to_sr1cs_with_assignment(&mut cs.into_inner().unwrap()).unwrap();

    let mut sr1cs_inner = sr1cs_cs.into_inner().unwrap();
    let _ = sr1cs_inner.perform_instance_outlining(InstanceOutliner {
        pred_label: SR1CS_PREDICATE_LABEL.to_string(),
        func: Rc::new(outline_sr1cs),
    });
    prover_time += start.elapsed();
    let cs = gr1cs::ConstraintSystem::new_ref();
    cs.set_instance_outliner(InstanceOutliner {
        pred_label: R1CS_PREDICATE_LABEL.to_string(),
        func: Rc::new(outline_r1cs),
    });
    let _ = circuit.clone().generate_constraints(cs.clone());
    cs.finalize();

    BenchResult {
        curve: type_name::<E>().to_string(),
        num_constraints: cs.num_constraints(),
        predicate_constraints: cs.get_all_predicates_num_constraints(),
        num_invocations,
        num_thread,
        input_size: cs.num_instance_variables(),
        num_keygen_iterations: num_keygen_iterations as usize,
        num_prover_iterations: num_prover_iterations as usize,
        num_verifier_iterations: num_verifier_iterations as usize,
        pk_size,
        vk_size,
        proof_size: 0,
        prover_time,
        verifier_time,
        keygen_time,
    }
}

#[cfg(not(feature = "sol"))]
fn main() {
    let num_thread = env::var("NUM_THREAD")
        .unwrap_or_else(|_| "default".to_string())
        .parse::<usize>()
        .unwrap();

    ThreadPoolBuilder::new()
        .num_threads(num_thread)
        .build_global()
        .unwrap();

    /////////// Benchmark Pari for different circuit sizes ///////////
    const MAX_LOG2_NUM_INVOCATIONS: usize = 30;
    let num_invocations: Vec<usize> = (0..MAX_LOG2_NUM_INVOCATIONS)
        .map(|i| 2_usize.pow(i as u32))
        .collect();
    for invocation in &num_invocations {
        let _ = bench::<Bls12_381>(*invocation, 20, 1, 1, 0, num_thread)
            .save_to_csv("pari-synthesis.csv");
    }
}
