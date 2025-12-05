use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::sponge::Absorb;
use ark_curve25519::EdwardsProjective;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_relations::gr1cs::ConstraintSystem;
use ark_relations::gr1cs::OptimizationGoal;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng,
};
use garuda_bench::RESCUE_APPLICATION_NAME;
use garuda_bench::{create_test_rescue_parameter, RescueDemo, WIDTH};
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use rand::rngs::StdRng;
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::cmp::max;
use std::ops::Neg;
use std::time::Duration;
#[cfg(feature = "r1cs")]
fn bench<G: CurveGroup>(
    num_invocations: usize,
    input_size: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    _zk: bool,
) -> BenchResult
where
    G::ScalarField: PrimeField + Absorb,
    G::Affine: Neg<Output = G::Affine>,
    num_bigint::BigUint: From<<G::ScalarField as PrimeField>::BigInt>,
{
    dbg!(num_invocations);
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
    };
    let circuit = circuit.clone();
    let cs: ConstraintSystemRef<G::ScalarField> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(cs, rng);
    let mut gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }
    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"benchmark");
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
        prover_transcript = Transcript::new(b"benchmark");
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
    // let start = ark_std::time::Instant::now();
    // for _ in 0..num_verifier_iterations {
    //     let mut verifier_transcript = Transcript::new(b"benchmark");
    //     let _ = proof
    //         .verify(&comm, &inputs, &mut verifier_transcript, &gens)
    //         .is_ok();
    // }
    // verifier_time += start.elapsed();

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
const MAX_LOG2_INPUT_SIZE: usize = 20;
const ZK: bool = false;

#[cfg(feature = "parallel")]
fn main() {
    //////////// Benchamrk the Verifier ////////////////
    let zk_string = if ZK { "-zk" } else { "" };
    //////////// Benchamrk the prover ////////////////

    let num_invocations: Vec<usize> = (1..MAX_LOG2_NUM_INVOCATIONS)
        .map(|i| 2_usize.pow(i as u32))
        .collect();

    for &num_thread in &[4] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(num_thread)
            .build()
            .expect("Failed to build thread pool");
        pool.install(|| {
            for &num_invocation in &num_invocations {
                let filename = format!(
                    "{RESCUE_APPLICATION_NAME}-spartan-r1cs{}-{}t.csv",
                    zk_string, num_thread
                );
                let _ = bench::<EdwardsProjective>(num_invocation, 20, 1, 1, 100, num_thread, ZK)
                    .save_to_csv(&filename);
            }
        });
    }
}

#[cfg(not(feature = "parallel"))]
fn main() {
    //////////// Benchmark the Verifier ////////////////
    let zk_string = if ZK { "-zk" } else { "" };
    // use garuda_bench::INPUT_BENCHMARK;
    // let input_sizes: Vec<usize> = (1..MAX_LOG2_INPUT_SIZE)
    //     .map(|i| 2_usize.pow(i as u32))
    //     .collect();

    // for &input_size in &input_sizes {
    //     let filename = format!(
    //         "{RESCUE_APPLICATION_NAME}-spartan-r1cs{}-{}t-{INPUT_BENCHMARK}.csv",
    //         zk_string, 1
    //     );
    //     let _ = bench::<EdwardsProjective>(2, input_size, 1, 1, 100, 1, ZK).save_to_csv(&filename);
    // }

    //////////// Benchmark the Prover ////////////////

    let num_invocations: Vec<usize> = (1..MAX_LOG2_NUM_INVOCATIONS)
        .map(|i| 2_usize.pow(i as u32))
        .collect();
    let num_thread = 1;
    for &num_invocation in &num_invocations {
        const GARUDA_VARIANT: &str = {
            #[cfg(all(feature = "gr1cs", not(feature = "r1cs")))]
            {
                "garuda-gr1cs"
            }

            #[cfg(all(feature = "r1cs", not(feature = "gr1cs")))]
            {
                "garuda-r1cs"
            }

            #[cfg(not(any(
                all(feature = "gr1cs", not(feature = "r1cs")),
                all(feature = "r1cs", not(feature = "gr1cs"))
            )))]
            {
                compile_error!("Enable exactly one of the features \"gr1cs\" or \"r1cs\".")
            }
        };

        let filename = format!(
            "{RESCUE_APPLICATION_NAME}-{GARUDA_VARIANT}-{}-{}t.csv",
            zk_string, num_thread
        );
        let _ = bench::<EdwardsProjective>(num_invocation, 20, 1, 1, 100, num_thread, ZK)
            .save_to_csv(&filename);
    }
}

fn arkwork_r1cs_adapter<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    mut rng: StdRng,
) -> (
    usize,
    usize,
    usize,
    usize,
    Instance<F>,
    VarsAssignment<F>,
    InputsAssignment<F>,
) {
    dbg!(&cs.num_constraints());
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_predicates(), 1);
    let num_cons = cs.num_constraints();
    let num_inputs = cs.num_instance_variables() - 1;
    let num_vars = cs.num_witness_variables();

    let instance_assignment = cs.instance_assignment().unwrap();
    let witness_assignment = cs.witness_assignment().unwrap();
    let ark_matrices = cs.to_matrices().unwrap();
    let mut num_gr1cs_nonzero_entries = 0;
    for (_, matrices) in ark_matrices.iter() {
        for matrix in matrices.iter() {
            for row in matrix.iter() {
                num_gr1cs_nonzero_entries += row.len();
            }
        }
    }
    num_gr1cs_nonzero_entries = prev_power_of_two(num_gr1cs_nonzero_entries);

    let num_a_nonzeros = rng.gen_range(0..=num_gr1cs_nonzero_entries);
    let num_b_nonzeros = rng.gen_range(0..=(num_gr1cs_nonzero_entries - num_a_nonzeros));
    let num_c_nonzeros = num_gr1cs_nonzero_entries - num_a_nonzeros - num_b_nonzeros;

    let mut a: Vec<(usize, usize, F)> = Vec::with_capacity(num_a_nonzeros);
    let mut b: Vec<(usize, usize, F)> = Vec::with_capacity(num_b_nonzeros);
    let mut c: Vec<(usize, usize, F)> = Vec::with_capacity(num_c_nonzeros);
    for _ in 0..num_a_nonzeros {
        let row = rng.gen_range(0..num_cons);
        let col = rng.gen_range(0..num_vars + num_inputs + 1);
        let value = F::rand(&mut rng);
        a.push((row, col, value));
    }
    for _ in 0..num_b_nonzeros {
        let row = rng.gen_range(0..num_cons);
        let col = rng.gen_range(0..num_vars + num_inputs + 1);
        let value = F::rand(&mut rng);
        b.push((row, col, value));
    }
    for _ in 0..num_c_nonzeros {
        let row = rng.gen_range(0..num_cons);
        let col = rng.gen_range(0..num_vars + num_inputs + 1);
        let value = F::rand(&mut rng);
        c.push((row, col, value));
    }
    let inst = Instance::new(num_cons, num_vars, num_inputs, &a, &b, &c).unwrap();
    let assignment_vars = VarsAssignment::new(&witness_assignment).unwrap();
    let assignment_inputs = InputsAssignment::new(&instance_assignment[1..]).unwrap();
    let num_non_zero_entries = max(a.len(), max(b.len(), c.len()));
    (
        num_cons,
        num_vars,
        num_inputs,
        num_non_zero_entries,
        inst,
        assignment_vars,
        assignment_inputs,
    )
}
fn prev_power_of_two(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        1 << (usize::BITS - n.leading_zeros() - 1)
    }
}
