use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_relations::gr1cs;
use ark_relations::gr1cs::instance_outliner::outline_r1cs;
use ark_relations::gr1cs::instance_outliner::InstanceOutliner;
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_relations::gr1cs::R1CS_PREDICATE_LABEL;
use ark_serialize::CanonicalSerialize;
use ark_std::rc::Rc;
use ark_std::UniformRand;
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use garuda::Garuda;
use garuda_bench::{create_test_rescue_parameter, RescueDemo};
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::ops::Neg;
use std::time::Duration;

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
    let mut prover_prep_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut keygen_prep_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let circuit = RescueDemo::<E::ScalarField> {
        input: Some(input.clone()),
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
        num_instances: input_size,
    };
    let (mut pk, mut vk) = (None, None);
    for _ in 0..num_keygen_iterations {
        let setup_circuit = circuit.clone();

        let start = ark_std::time::Instant::now();
        let _cs = Garuda::<E>::circuit_to_keygen_cs(circuit.clone()).unwrap();
        keygen_prep_time += start.elapsed();
        let start = ark_std::time::Instant::now();
        let (ipk, ivk) = Garuda::<E>::keygen(setup_circuit, &mut rng);
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
        let prover_circuit = circuit.clone();

        let start = ark_std::time::Instant::now();

        let _cs = Garuda::<E>::circuit_to_prover_cs(circuit.clone()).unwrap();
        prover_prep_time += start.elapsed();
        let start = ark_std::time::Instant::now();
        proof = pk
            .as_ref()
            .map(|pk| Garuda::prove(pk, prover_circuit).unwrap());
        prover_time += start.elapsed();
    }
    let proof_size = proof.serialized_size(ark_serialize::Compress::Yes);
    let start = ark_std::time::Instant::now();
    for _ in 0..num_verifier_iterations {
        assert!(Garuda::verify(
            proof.as_ref().unwrap(),
            vk.as_ref().unwrap(),
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

    BenchResult {
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
        prover_prep_time: (prover_prep_time / num_prover_iterations),
        prover_corrected_time: ((prover_time - prover_prep_time) / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
        keygen_prep_time: (keygen_prep_time / num_keygen_iterations),
        keygen_corrected_time: ((keygen_time - keygen_prep_time) / num_keygen_iterations),
    }
}

fn main() {
    const MAX_LOG2_NUM_INVOCATIONS: usize = 30;
    let num_invocations: Vec<usize> = (4..6).map(|i| 2_usize.pow(i as u32)).collect();

    for &num_thread in &[1, 4] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(num_thread)
            .build()
            .expect("Failed to build thread pool");

        pool.install(|| {
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

                    // Fire a helpful error if the build is mis‑configured.
                    #[cfg(not(any(
                        all(feature = "gr1cs", not(feature = "r1cs")),
                        all(feature = "r1cs", not(feature = "gr1cs"))
                    )))]
                    {
                        compile_error!("Enable exactly one of the features \"gr1cs\" or \"r1cs\".")
                    }
                };

                let filename = format!("{GARUDA_VARIANT}-{}t.csv", num_thread);
                let _ = bench::<Bls12_381>("bench", num_invocation, 20, 1, 1, 100, num_thread)
                    .save_to_csv(&filename);
            }
        });
    }
}
