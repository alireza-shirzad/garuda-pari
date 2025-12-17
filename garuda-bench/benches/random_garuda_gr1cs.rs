use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField};
use ark_relations::gr1cs::{
    predicate::PredicateConstraintSystem, ConstraintSynthesizer, ConstraintSystem,
    ConstraintSystemRef, SynthesisError, Variable, R1CS_PREDICATE_LABEL,
};
use ark_relations::lc;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{
    rand::RngCore,
    rand::{rngs::StdRng, Rng, SeedableRng},
    test_rng,
};
use garuda::Garuda;
use garuda_bench::RandomCircuit;
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::ops::Neg;
use std::panic::{self, AssertUnwindSafe};
use std::time::Duration;

const DEG5_LABEL: &str = "deg5-mul";

fn bench<E: Pairing>(
    num_constraints: usize,
    nonzero_per_matrix: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    zk: bool,
) -> Option<BenchResult>
where
    E::ScalarField: PrimeField + UniformRand,
    E::G1Affine: Neg<Output = E::G1Affine>,
    <E::G1Affine as AffineRepr>::BaseField: PrimeField,
{
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = RandomCircuit::<E::ScalarField>::new(num_constraints, nonzero_per_matrix, true);
    let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap(), "GR1CS not satisfied");

    let mut prover_time = Duration::new(0, 0);
    let mut prover_prep_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut keygen_prep_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let (mut pk, mut vk) = (None, None);

    for _ in 0..num_keygen_iterations {
        let setup_circuit = circuit.clone();

        let start = ark_std::time::Instant::now();
        let _cs = Garuda::<E>::circuit_to_keygen_cs(setup_circuit.clone(), zk).unwrap();
        keygen_prep_time += start.elapsed();
        let start = ark_std::time::Instant::now();
        let (ipk, ivk) = Garuda::<E>::keygen(setup_circuit, zk, &mut rng);
        pk = Some(ipk);
        vk = Some(ivk);
        keygen_time += start.elapsed();
    }

    let pk_size = pk
        .as_ref()
        .unwrap()
        .serialized_size(ark_serialize::Compress::Yes);
    let vk_size = vk
        .as_ref()
        .unwrap()
        .serialized_size(ark_serialize::Compress::Yes);

    let mut proof = None;
    for _ in 0..num_prover_iterations {
        let zk_rng = if zk { Some(&mut rng) } else { None };
        let prover_circuit = circuit.clone();

        let start = ark_std::time::Instant::now();
        let cs = Garuda::<E>::circuit_to_prover_cs(prover_circuit.clone(), zk).unwrap();
        prover_prep_time += start.elapsed();
        let start = ark_std::time::Instant::now();
        proof = pk
            .as_ref()
            .map(|pk| Garuda::prove(pk, zk_rng, prover_circuit).unwrap());
        prover_time += start.elapsed();
    }

    let proof_size = proof
        .as_ref()
        .unwrap()
        .serialized_size(ark_serialize::Compress::Yes);

    let start = ark_std::time::Instant::now();
    let mut all_verified = true;
    for _ in 0..num_verifier_iterations {
        let verified = panic::catch_unwind(AssertUnwindSafe(|| {
            Garuda::verify(proof.as_ref().unwrap(), vk.as_ref().unwrap(), &[])
        }))
        .map(|ok| ok)
        .unwrap_or(false);
        if !verified {
            all_verified = false;
            break;
        }
    }
    verifier_time += start.elapsed();
    if !all_verified {
        eprintln!(
            "Verification failed; skipping entry (constraints={}, nonzero_per_matrix={})",
            num_constraints, nonzero_per_matrix
        );
        return None;
    }

    let prover_corrected = prover_time
        .checked_sub(prover_prep_time)
        .unwrap_or_else(|| Duration::new(0, 0));
    let keygen_corrected = keygen_time
        .checked_sub(keygen_prep_time)
        .unwrap_or_else(|| Duration::new(0, 0));

    BenchResult {
        curve: type_name::<E>().to_string(),
        num_invocations: num_constraints,
        input_size: cs.num_instance_variables(),
        num_nonzero_entries: nonzero_per_matrix,
        num_constraints: cs.num_constraints(),
        predicate_constraints: cs.get_all_predicates_num_constraints(),
        num_thread,
        num_keygen_iterations: num_keygen_iterations as usize,
        num_prover_iterations: num_prover_iterations as usize,
        num_verifier_iterations: num_verifier_iterations as usize,
        pk_size,
        vk_size,
        proof_size,
        prover_time: (prover_time / num_prover_iterations),
        prover_prep_time: (prover_prep_time / num_prover_iterations),
        prover_corrected_time: (prover_corrected / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
        keygen_prep_time: (keygen_prep_time / num_keygen_iterations),
        keygen_corrected_time: (keygen_corrected / num_keygen_iterations),
    }
    .into()
}

const MIN_LOG2_CONSTRAINTS: usize = 10;
const MAX_LOG2_CONSTRAINTS: usize = 20;
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 1;
const ZK: bool = false;

fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let bench_num_constraints = (MIN_LOG2_CONSTRAINTS..=MAX_LOG2_CONSTRAINTS)
        .map(|i| 1 << i)
        .collect::<Vec<usize>>();
    for num_constraints in bench_num_constraints {
        let filename = format!("random-garuda-gr1cs{}-{}t.csv", zk_string, 1);
        let Some(result) = bench::<Bls12_381>(
            num_constraints,
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
