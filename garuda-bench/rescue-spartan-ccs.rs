use ark_bls12_381::Bls12_381;
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
use ark_relations::gr1cs::ConstraintSystem;
use ark_relations::gr1cs::OptimizationGoal;
use ark_relations::gr1cs::R1CS_PREDICATE_LABEL;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::UniformRand;
use ark_std::{
    rand::{Rng, RngCore, SeedableRng},
    test_rng,
};
use libspartan::{InputsAssignment, Instance, SNARK, SNARKGens, VarsAssignment};
use merlin::Transcript;
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::env;
use std::ops::Neg;
use std::str::FromStr;
use std::time::Duration;
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
        num_instances: input_size,
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
    };
    let circuit = circuit.clone();
    let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(cs, rng);
    let mut gens = SNARKGens::<E::G1>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<E::G1>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }
    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let mut proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        vars.clone(),
        &inputs,
        &gens,
        &mut prover_transcript,
    );
    for _ in 0..num_prover_iterations {
        let vars = vars.clone();
        let start = ark_std::time::Instant::now();
        prover_transcript = Transcript::new(b"snark_example");
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
    for _ in 0..num_verifier_iterations {
        let mut verifier_transcript = Transcript::new(b"snark_example");
        assert!(
            proof
                .verify(&comm, &inputs, &mut verifier_transcript, &gens)
                .is_ok()
        );
    }
    verifier_time += start.elapsed();

    let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();

    BenchResult {
        curve: type_name::<E::G1>().to_string(),
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
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
    }
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

    /////////// Benchmark Pari for different circuit sizes ///////////
    const MAX_LOG2_NUM_INVOCATIONS: usize = 30;
    let num_invocations: Vec<usize> = (0..MAX_LOG2_NUM_INVOCATIONS)
        .map(|i| 2_usize.pow(i as u32))
        .collect();
    for i in 0..num_invocations.len() {
        let _ = bench::<Bls12_381>("bench", num_invocations[i], 20, 1, 1, 100, num_thread)
            .save_to_csv("spartan-ccs.csv", true);
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
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_predicates(), 1);
    let ark_matrices: Vec<Vec<Vec<(F, usize)>>> = cs.to_spartan_matrices().unwrap()["XXX"].clone();
    assert_eq!(ark_matrices.len(), 3);
    let instance_assignment = cs.instance_assignment().unwrap();
    let witness_assignment = cs.witness_assignment().unwrap();
    let num_cons = cs.num_constraints();
    let num_inputs = cs.num_instance_variables() - 1;
    let num_vars = cs.num_witness_variables();
    assert_eq!(num_vars, witness_assignment.len());
    assert_eq!(num_inputs, instance_assignment.len() - 1);

    let num_gr1cs_nonzero_entries = ark_matrices
        .iter()
        .map(|matrix| matrix.iter().map(|row| row.len()).sum::<usize>())
        .sum::<usize>();

    let num_a_nonzeros = rng.gen_range(0..=num_gr1cs_nonzero_entries);
    let num_b_nonzeros = rng.gen_range(0..=(num_gr1cs_nonzero_entries - num_a_nonzeros));
    let num_c_nonzeros = num_gr1cs_nonzero_entries - num_a_nonzeros - num_b_nonzeros;

    let mut A: Vec<(usize, usize, F)> = Vec::with_capacity(num_a_nonzeros);
    let mut B: Vec<(usize, usize, F)> = Vec::with_capacity(num_b_nonzeros);
    let mut C: Vec<(usize, usize, F)> = Vec::with_capacity(num_c_nonzeros);
    for _ in 0..num_a_nonzeros {
        let row = rng.gen_range(0..num_cons);
        let col = rng.gen_range(0..num_vars);
        let value = F::rand(&mut rng);
        A.push((col, row, value));
    }
    for _ in 0..num_b_nonzeros {
        let row = rng.gen_range(0..num_cons);
        let col = rng.gen_range(0..num_vars);
        let value = F::rand(&mut rng);
        B.push((col, row, value));
    }
    for _ in 0..num_c_nonzeros {
        let row = rng.gen_range(0..num_cons);
        let col = rng.gen_range(0..num_vars);
        let value = F::rand(&mut rng);
        C.push((col, row, value));
    }
    let num_non_zero_entries = ark_matrices.iter().map(|x| x.len()).sum();
    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
    let assignment_vars = VarsAssignment::new(&witness_assignment).unwrap();
    let assignment_inputs = InputsAssignment::new(&instance_assignment[1..]).unwrap();
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert!(res.unwrap());

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
