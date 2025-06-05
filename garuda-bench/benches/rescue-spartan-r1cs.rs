// use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::{rescue::CRH, CRHScheme};
use ark_relations::gr1cs::ConstraintSynthesizer as arkConstraintSynthesizer;
use ark_relations::gr1cs::ConstraintSystem as arkConstraintSystem;
use ark_std::cfg_iter;
use ark_std::test_rng;
use ark_std::UniformRand;
use garuda::ConstraintSystemRef;
use garuda_bench::bellpepper_adapter::{ark_to_nova_field, FCircuit};
use garuda_bench::{create_test_rescue_parameter, RescueDemo, WIDTH};
use rand::{RngCore, SeedableRng};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use shared_utils::BenchResult;

fn run_bench(
    num_invocations: usize,
    input_size: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
) -> BenchResult {
    use spartan2::SNARK;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let config = create_test_rescue_parameter(&mut rng);
    let mut input = Vec::new();
    for _ in 0..WIDTH {
        input.push(<ark_pallas::Fq>::rand(&mut rng));
    }
    let mut expected_image = CRH::<ark_pallas::Fq>::evaluate(&config, input.clone()).unwrap();

    for _i in 0..(num_invocations - 1) {
        let output = vec![expected_image; WIDTH];
        expected_image = CRH::<ark_pallas::Fq>::evaluate(&config, output.clone()).unwrap();
    }

    let circuit = RescueDemo::<ark_pallas::Fq> {
        input: Some(input.clone()),
        num_instances: input_size,
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
    };

    let circuit = circuit.clone();
    let cs: ConstraintSystemRef<ark_pallas::Fq> = arkConstraintSystem::new_ref();
    assert!(cs.is_satisfied().unwrap());
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    let f_circuit: FCircuit<bls12_381::Scalar> = FCircuit::new(cs);
    type G = bls12_381::G1Affine;
    type EE = spartan2::provider::ipa_pc::EvaluationEngine<G>;
    type S = spartan2::spartan::snark::RelaxedR1CSSNARK<G, EE>;
    let (pk, vk) = SNARK::<G, S, FCircuit<bls12_381::Scalar>>::setup(f_circuit.clone()).unwrap();
    let snark = SNARK::prove(&pk, f_circuit).unwrap();
    let input_assignments: Vec<bls12_381::Scalar> =cfg_iter!(vec![expected_image; input_size - 1])
        .map(ark_to_nova_field)
        .collect();
    snark.verify(&vk, &input_assignments).unwrap();

    todo!();
    // let (pk, vk) = (None, None);
    // for _ in 0..num_keygen_iterations {
    //     let start = ark_std::time::Instant::now();
    //     let (ipk, ivk) = SNARK::<G, S, LessThanCircuitSafe<_>>::setup(circuit.clone()).unwrap();
    //     let (pk, vk) = (Some(ipk), Some(ivk));
    //     keygen_time += start.elapsed();
    // }
    // let proof = None;
    // for _ in 0..num_prover_iterations {
    //     let vars = vars.clone();
    //     let start = ark_std::time::Instant::now();
    //     let proof = Some(SNARK::prove(&pk, circuit).unwrap());
    //     prover_time += start.elapsed();
    // }
    // let proof_size = proof.compressed_size();
    // let start = ark_std::time::Instant::now();
    // for _ in 0..num_verifier_iterations {
    //     proof.verify(&vk, &[])
    // }
    // verifier_time += start.elapsed();

    // let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    // cs.set_optimization_goal(OptimizationGoal::Constraints);
    // circuit.generate_constraints(cs.clone()).unwrap();
    // cs.finalize();

    // BenchResult {
    //     curve: type_name::<E::G1>().to_string(),
    //     num_constraints: num_cons,
    //     predicate_constraints: cs.get_all_predicates_num_constraints(),
    //     num_invocations,
    //     input_size,
    //     num_thread,
    //     num_keygen_iterations: num_keygen_iterations as usize,
    //     num_prover_iterations: num_prover_iterations as usize,
    //     num_verifier_iterations: num_verifier_iterations as usize,
    //     pk_size,
    //     vk_size,
    //     proof_size,
    //     prover_time: (prover_time / num_prover_iterations),
    //     prover_prep_time: Duration::new(0, 0),
    //     prover_corrected_time: (prover_time / num_prover_iterations),
    //     verifier_time: (verifier_time / num_verifier_iterations),
    //     keygen_time: (keygen_time / num_keygen_iterations),
    //     keygen_prep_time: Duration::new(0, 0),
    //     keygen_corrected_time: (keygen_time / num_keygen_iterations),
    // }
}

fn main() {
    let num_thread = 1;
    /////////// Benchmark Pari for different circuit sizes ///////////
    // const MAX_LOG2_NUM_INVOCATIONS: usize = 30;
    // let num_invocations: Vec<usize> = (0..MAX_LOG2_NUM_INVOCATIONS)
    //     .map(|i| 2_usize.pow(i as u32))
    //     .collect();
    // for num_invocation in &num_invocations {
    //     let _ = run_bench::<Bls12_381>(*num_invocation, 20, 1, 1, 100, num_thread)
    //         .save_to_csv("spartan-r1cs.csv");
    // }
    let _ = run_bench(2, 20, 1, 1, 100, num_thread).save_to_csv("spartan-r1cs.csv");
}
