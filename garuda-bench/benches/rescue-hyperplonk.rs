use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_relations::utils::HashBuilder;
use ark_relations::utils::IndexMap;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::any::type_name;
use ark_std::fs::File;
use ark_std::log2;
use ark_std::ops::Neg;
use ark_std::path::Path;
use ark_std::test_rng;
use ark_std::time::Duration;
use hp_hyperplonk::prelude::CustomizedGates;
use hp_hyperplonk::prelude::MockCircuit;
use hp_hyperplonk::HyperPlonkSNARK;
use hp_subroutines::MultilinearKzgPCS;
use hp_subroutines::MultilinearUniversalParams;
use hp_subroutines::PolyIOP;
use hp_subroutines::PolynomialCommitmentScheme;

use shared_utils::BenchResult;

fn bench<E: Pairing>(
    num_invocations: usize,
    input_size: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    jf_gate: &CustomizedGates,
    pcs_srs: &MultilinearUniversalParams<E>,
) -> BenchResult
where
    E::G1Affine: Neg<Output = E::G1Affine>,
{
    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let nv = log2(num_constr_from_num_invoc(num_invocations)) as usize;
    let circuit = MockCircuit::<E::ScalarField>::new(1 << nv, jf_gate);
    assert!(circuit.is_satisfied());
    let index = circuit.index.clone();
    let (mut pk, mut vk) =
        <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::preprocess(
            &index, pcs_srs,
        )
        .unwrap();

    for _ in 0..num_keygen_iterations {
        // let setup_circuit = circuit.clone();
        let start = ark_std::time::Instant::now();
        (pk, vk) =
            <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::preprocess(
                &index, pcs_srs,
            )
            .unwrap();
        keygen_time += start.elapsed();
    }

    let mut proof = <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::prove(
        &pk,
        &circuit.public_inputs,
        &circuit.witnesses,
    )
    .unwrap();
    let proof_size = proof.serialized_size(ark_serialize::Compress::Yes);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        proof = <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::prove(
            &pk,
            &circuit.public_inputs,
            &circuit.witnesses,
        )
        .unwrap();
        prover_time += start.elapsed();
    }
    let start = ark_std::time::Instant::now();
    for _ in 0..num_verifier_iterations {
        let verify = <PolyIOP<E::ScalarField> as HyperPlonkSNARK<E, MultilinearKzgPCS<E>>>::verify(
            &vk,
            &circuit.public_inputs,
            &proof,
        )
        .unwrap();
        assert!(verify);
    }
    verifier_time += start.elapsed();

    BenchResult {
        curve: type_name::<E>().to_string(),
        num_constraints: 1 << nv,
        predicate_constraints: IndexMap::with_hasher(HashBuilder::default()),
        num_invocations,
        input_size,
        num_nonzero_entries: 0,
        num_thread,
        num_keygen_iterations: num_keygen_iterations as usize,
        num_prover_iterations: num_prover_iterations as usize,
        num_verifier_iterations: num_verifier_iterations as usize,
        pk_size: 0,
        vk_size: 0,
        proof_size,
        prover_time: (prover_time / num_prover_iterations),
        prover_prep_time: Duration::new(0, 0),
        prover_corrected_time: (prover_time / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
        keygen_prep_time: Duration::new(0, 0),
        keygen_corrected_time: (keygen_time / num_keygen_iterations),
    }
}

fn num_constr_from_num_invoc(num_invocations: usize) -> usize {
    num_invocations * 284
}

fn main() {
    const MAX_LOG_VAR: usize = 25;
    let jf_gate = CustomizedGates::jellyfish_turbo_plonk_gate();
    let srs_file_path: String = format!("srs_{}.bin", MAX_LOG_VAR);
    let mut rng = test_rng();
    let pcs_srs: MultilinearUniversalParams<Bls12_381> = if Path::new(&srs_file_path).exists() {
        println!("File exists");
        // The file exists; read and print its contents
        let file = File::open(&srs_file_path).unwrap();
        let reader = std::io::BufReader::new(file);
        MultilinearUniversalParams::<Bls12_381>::deserialize_uncompressed_unchecked(reader).unwrap()
    } else {
        println!("File does not exist");
        // The file does not exist; create it and write some content
        let file = File::create(&srs_file_path).unwrap();
        let writer = std::io::BufWriter::new(file);
        let pcs_srs =
            MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, MAX_LOG_VAR).unwrap();
        pcs_srs.serialize_uncompressed(writer).unwrap();
        pcs_srs
    };
    /////////// Benchmark Pari for different circuit sizes ///////////
    const MAX_LOG2_NUM_INVOCATIONS: usize = 30;
    let num_invocations: Vec<usize> = (0..MAX_LOG2_NUM_INVOCATIONS)
        .map(|i| 2_usize.pow(i as u32))
        .collect();

    {
        let num_thread: usize = 1;
        for num_invocation in &num_invocations {
            let _ =
                bench::<Bls12_381>(*num_invocation, 20, 1, 1, 1, num_thread, &jf_gate, &pcs_srs)
                    .save_to_csv("hyperplonk.csv");
        }
    }
}
