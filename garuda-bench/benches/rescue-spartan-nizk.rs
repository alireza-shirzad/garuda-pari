use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::sponge::Absorb;
use ark_curve25519::EdwardsProjective;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_relations::gr1cs::ConstraintSystem;
use ark_relations::gr1cs::OptimizationGoal;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use garuda_bench::RESCUE_APPLICATION_NAME;
use garuda_bench::{create_test_rescue_parameter, RescueDemo, WIDTH};
use libspartan::{NIZKGens, NIZK};
use merlin::Transcript;
use shared_utils::BenchResult;
use std::any::type_name;
use std::ops::Neg;
use std::time::Duration;

#[cfg(feature = "gr1cs")]
fn bench<G: CurveGroup>(
    num_invocations: usize,
    input_size: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    _zk: bool,
    should_use_custom_predicate: bool,
) -> BenchResult
where
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Neg<Output = G::Affine>,
    num_bigint::BigUint: From<<G::ScalarField as PrimeField>::BigInt>,
{
    use garuda_bench::arkwork_r1cs_adapter;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let config = create_test_rescue_parameter(&mut rng);
    let mut input = Vec::new();
    for _ in 0..WIDTH {
        input.push(<G::ScalarField>::rand(&mut rng));
    }
    let mut expected_image = CRH::<G::ScalarField>::evaluate(&config, input.clone()).unwrap();

    for _i in 0..(num_invocations - 1) {
        let output = vec![expected_image; WIDTH];
        expected_image = CRH::<G::ScalarField>::evaluate(&config, output.clone()).unwrap();
    }

    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let pk_size: usize = 0;
    let vk_size: usize = 0;
    let circuit = RescueDemo::<G::ScalarField> {
        input: Some(input.clone()),
        num_instances: input_size,
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
        should_use_custom_predicate,
    };
    let circuit = circuit.clone();
    let cs: ConstraintSystemRef<G::ScalarField> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let (num_cons, num_vars, num_inputs, num_nonzero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(should_use_custom_predicate, cs, rng);

    let mut gens = NIZKGens::<G>::new(num_cons, num_vars, num_inputs);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = NIZKGens::<G>::new(num_cons, num_vars, num_inputs);
        keygen_time += start.elapsed();
    }

    let mut prover_transcript = Transcript::new(b"benchmark");
    let mut proof = NIZK::prove(&inst, vars.clone(), &inputs, &gens, &mut prover_transcript);
    let proof_size = proof.serialized_size(ark_serialize::Compress::Yes);
    for _ in 0..num_prover_iterations {
        let vars = vars.clone();
        let start = ark_std::time::Instant::now();
        prover_transcript = Transcript::new(b"benchmark");
        proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut prover_transcript);
        prover_time += start.elapsed();
    }

    let start = ark_std::time::Instant::now();
    for _ in 0..1 {
        let mut verifier_transcript = Transcript::new(b"benchmark");
        let _ = proof
            .verify(&inst, &inputs, &mut verifier_transcript, &gens)
            .is_ok();
    }
    verifier_time += start.elapsed();

    let cs: ConstraintSystemRef<G::ScalarField> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();

    BenchResult {
        curve: type_name::<G>().to_string(),
        num_constraints: num_cons,
        predicate_constraints: cs.get_all_predicates_num_constraints(),
        num_invocations,
        input_size,
        num_nonzero_entries,
        num_thread,
        num_keygen_iterations: num_keygen_iterations as usize,
        num_prover_iterations: num_prover_iterations as usize,
        num_verifier_iterations: num_verifier_iterations as usize,
        pk_size,
        vk_size,
        proof_size,
        prover_time: (prover_time / num_prover_iterations),
        prover_prep_time: Duration::new(0, 0),
        prover_corrected_time: ((prover_time) / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
        keygen_prep_time: Duration::new(0, 0),
        keygen_corrected_time: ((keygen_time) / num_keygen_iterations),
    }
}

const MAX_LOG2_NUM_INVOCATIONS: usize = 15;
const ZK: bool = false;

fn main() {

    let args: Vec<String> = std::env::args().collect();
    let use_gr1cs = args.iter().any(|arg| arg == "--gr1cs");
    let zk_string = if ZK { "-zk" } else { "" };

    let num_invocations: Vec<usize> = (1..MAX_LOG2_NUM_INVOCATIONS)
        .map(|i| 2_usize.pow(i as u32))
        .collect();
    let num_thread = 1;
    for &num_invocation in &num_invocations {
        let variant = if use_gr1cs { "gr1cs" } else { "r1cs" };
        let filename = format!(
            "{RESCUE_APPLICATION_NAME}-spartan-{variant}-nizk-{}-{}t.csv",
            zk_string, num_thread
        );
        let _ = bench::<EdwardsProjective>(num_invocation, 20, 1, 1, 1, num_thread, ZK, use_gr1cs)
            .save_to_csv(&filename);
    }
}
