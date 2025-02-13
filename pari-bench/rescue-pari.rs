// use ark_bls12_381::{Bls12_381, Fr as BlsFr12_381_Fr};
use ark_bn254::{Bn254, Fr as Bn254_Fr};
use ark_crypto_primitives::crh::rescue::CRH;
use ark_crypto_primitives::crh::rescue::constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::sponge::rescue::RescueConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs;
use ark_relations::gr1cs::R1CS_PREDICATE_LABEL;
use ark_relations::gr1cs::instance_outliner::InstanceOutliner;
use ark_relations::gr1cs::instance_outliner::outline_r1cs;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::rand::rngs::StdRng;
use ark_std::rc::Rc;
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng,
};
use pari::Pari;
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::env;
use std::time::Duration;

#[derive(Clone)]
struct RescueDemo<F: PrimeField> {
    rescue_input: Option<Vec<F>>,
    num_isntances: usize,
    rescue_image: Option<F>,
    config: RescueConfig<F>,
    num_invocations: usize,
}

impl<F: PrimeField + ark_ff::PrimeField + ark_crypto_primitives::sponge::Absorb>
    ConstraintSynthesizer<F> for RescueDemo<F>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let params_g =
            CRHParametersVar::<F>::new_witness(cs.clone(), || Ok(self.config.clone())).unwrap();

        let mut input_g = Vec::new();

        for elem in self
            .rescue_input
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
        for i in 0..self.num_isntances - 1 {
            let image_instance: FpVar<F> = FpVar::new_input(cs.clone(), || {
                Ok(self
                    .rescue_image
                    .ok_or(SynthesisError::AssignmentMissing)
                    .unwrap())
            })
            .unwrap();

            if let Some(crh_a_g) = crh_a_g.clone() {
                let _ = crh_a_g.enforce_equal(&image_instance);
            }
        }

        Ok(())
    }
}

macro_rules! bench {
    ($bench_name:ident, $num_invocations:expr,$input_size:expr, $num_keygen_iterations:expr, $num_prover_iterations:expr, $num_verifier_iterations:expr, $num_thread:expr, $bench_pairing_engine:ty, $bench_field:ty) => {{
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let config = RescueConfig::<$bench_field>::test_conf();

        let mut rescue_input = Vec::new();
        for _ in 0..9 {
            rescue_input.push(<$bench_field>::rand(&mut rng));
        }
        let mut expected_image =
            CRH::<$bench_field>::evaluate(&config, rescue_input.clone()).unwrap();

        for _i in 0..($num_invocations - 1) {
            let output = vec![expected_image; 9];
            expected_image = CRH::<$bench_field>::evaluate(&config, output.clone()).unwrap();
        }

        let mut prover_time = Duration::new(0, 0);
        let mut keygen_time = Duration::new(0, 0);
        let mut verifier_time = Duration::new(0, 0);
        let circuit = RescueDemo::<$bench_field> {
            rescue_input: Some(rescue_input.clone()),
            num_isntances: $input_size,
            rescue_image: Some(expected_image),
            config: config.clone(),
            num_invocations: $num_invocations,
        };
        let setup_circuit = circuit.clone();
        let (mut pk, mut vk) =
            Pari::<$bench_pairing_engine, StdRng>::keygen(setup_circuit, &mut rng);
        for _ in 0..$num_keygen_iterations {
            let setup_circuit = circuit.clone();
            let start = ark_std::time::Instant::now();
            (pk, vk) = Pari::<$bench_pairing_engine, StdRng>::keygen(setup_circuit, &mut rng);
            keygen_time += start.elapsed();
        }
        let pk_size = pk.serialized_size(ark_serialize::Compress::Yes);
        let vk_size = vk.serialized_size(ark_serialize::Compress::Yes);
        let prover_circuit = circuit.clone();
        let mut proof = Pari::<$bench_pairing_engine, StdRng>::prove(prover_circuit, &pk).unwrap();
        for _ in 0..$num_keygen_iterations {
            let prover_circuit = circuit.clone();
            let start = ark_std::time::Instant::now();
            proof = Pari::<$bench_pairing_engine, StdRng>::prove(prover_circuit, &pk).unwrap();
            prover_time += start.elapsed();
        }
        let proof_size = proof.serialized_size(ark_serialize::Compress::Yes);
        let start = ark_std::time::Instant::now();
        for _ in 0..$num_verifier_iterations {
            assert!(Pari::<$bench_pairing_engine, StdRng>::verify(
                &proof,
                &vk,
                &vec![expected_image; $input_size-1],
            ));
        }
        verifier_time += start.elapsed();
        let cs: gr1cs::ConstraintSystemRef<$bench_field> = gr1cs::ConstraintSystem::new_ref();
        cs.set_instance_outliner(InstanceOutliner {
            pred_label: R1CS_PREDICATE_LABEL.to_string(),
            func: Rc::new(outline_r1cs),
        });
        let _ = circuit.clone().generate_constraints(cs.clone());
        cs.finalize();

        let bench_result = BenchResult {
            curve: type_name::<$bench_pairing_engine>().to_string(),
            num_constraints: cs.num_constraints(),
            predicate_constraints: cs.get_all_predicates_num_constraints(),
            num_invocations: $num_invocations,
            num_thread: $num_thread,
            input_size: $input_size,
            num_keygen_iterations: $num_keygen_iterations,
            num_prover_iterations: $num_prover_iterations,
            num_verifier_iterations: $num_verifier_iterations,
            pk_size,
            vk_size,
            proof_size,
            prover_time: (prover_time / $num_prover_iterations),
            verifier_time: (verifier_time / $num_verifier_iterations),
            keygen_time: (keygen_time / $num_keygen_iterations),
        };
        bench_result
    }};
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

    let _ =
        bench!(bench, 72, 4, 1, 1, 1, num_thread, Bn254, Bn254_Fr).save_to_csv("pari.csv", false);
    // let _ = bench!(bench, 144, 1, 5, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    //     .save_to_csv("pari.csv", true);
    // let _ = bench!(bench, 288, 1, 2, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    //     .save_to_csv("pari.csv", true);
    // let _ = bench!(bench, 577, 1, 1, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    //     .save_to_csv("pari.csv", true);
    // let _ = bench!(bench, 1154, 1, 1, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    //     .save_to_csv("pari.csv", false);
    // let _ = bench!(bench, 2309, 1, 1, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    //     .save_to_csv("pari.csv", true);
    // let _ = bench!(bench, 4619, 1, 1, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    //     .save_to_csv("pari.csv", true);
    // let _ = bench!(bench, 9238, 1, 1, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    //     .save_to_csv("pari.csv", true);
    // let _ = bench!(bench, 18477, 1, 1, 1, num_thread, Bls12_381, BlsFr12_381_Fr)
    // .save_to_csv("pari.csv", true);
}

