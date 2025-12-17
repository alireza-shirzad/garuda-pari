use ark_curve25519::{EdwardsProjective, Fr as CurveFr};
use ark_ff::{Field, PrimeField};
use ark_relations::gr1cs::{
    predicate::PredicateConstraintSystem, ConstraintSynthesizer, ConstraintSystemRef,
    SynthesisError, Variable, R1CS_PREDICATE_LABEL,
};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal};
use ark_relations::lc;
use ark_relations::utils::IndexMap;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{
    rand::RngCore,
    rand::{rngs::StdRng, Rng, SeedableRng},
    test_rng,
};
use garuda_bench::{arkwork_r1cs_adapter, RandomCircuit};
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use shared_utils::BenchResult;
use std::any::type_name;
use std::time::Duration;

const DEG5_LABEL: &str = "deg5-mul";

fn bench_spartan(
    num_constraints: usize,
    nonzero_per_constraint: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    _zk: bool,
) -> Option<BenchResult> {
    type Fr = CurveFr;
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = RandomCircuit::<Fr>::new(num_constraints, nonzero_per_constraint, true);
    let circuit = circuit.clone();
    let cs: ConstraintSystemRef<Fr> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let (num_cons, num_vars, num_inputs, max_non_zero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(true, cs, rng);

    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let pk_size: usize = 0;
    let vk_size: usize = 0;

    let mut gens =
        SNARKGens::<EdwardsProjective>::new(num_cons, num_vars, num_inputs, max_non_zero_entries);
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<EdwardsProjective>::new(
            num_cons,
            num_vars,
            num_inputs,
            max_non_zero_entries,
        );
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }

    let mut prover_transcript = Transcript::new(b"random-spartan-ccs");
    let mut proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        vars.clone(),
        &inputs,
        &gens,
        &mut prover_transcript,
    );
    let proof_size = proof.compressed_size();
    for _ in 0..num_prover_iterations {
        let vars = vars.clone();
        let start = ark_std::time::Instant::now();
        prover_transcript = Transcript::new(b"random-spartan-ccs");
        proof = SNARK::prove(
            &inst,
            &comm,
            &decomm,
            vars,
            &inputs,
            &gens,
            &mut prover_transcript,
        );
        prover_time += start.elapsed();
    }

    let start = ark_std::time::Instant::now();
    let mut verified = true;
    for _ in 0..num_verifier_iterations {
        let mut verifier_transcript = Transcript::new(b"random-spartan-ccs");
        if proof
            .verify(&comm, &inputs, &mut verifier_transcript, &gens)
            .is_err()
        {
            verified = false;
            break;
        }
    }
    verifier_time += start.elapsed();
    Some(BenchResult {
        curve: type_name::<EdwardsProjective>().to_string(),
        num_constraints: num_cons,
        predicate_constraints: IndexMap::default(),
        num_invocations: num_constraints,
        input_size: num_inputs,
        num_nonzero_entries: max_non_zero_entries,
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
    })
}

const MIN_LOG2_CONSTRAINTS: usize = 20;
const MAX_LOG2_CONSTRAINTS: usize = 30;
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 1;
const ZK: bool = false;

fn main() {
    let zk_string = if ZK { "-zk" } else { "" };

    for log_num_constraints in MIN_LOG2_CONSTRAINTS..=MAX_LOG2_CONSTRAINTS {
        let filename = format!("random-spartan-ccs{}-{}t.csv", zk_string, 1);
        let Some(result) = bench_spartan(
            2usize.pow(log_num_constraints as u32),
            3,
            NUM_KEYGEN_ITERATIONS,
            NUM_PROVER_ITERATIONS,
            NUM_VERIFIER_ITERATIONS,
            1,
            ZK,
        ) else {
            continue;
        };
        let _ = result.save_to_csv(&filename);
    }
}
