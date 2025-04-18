use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    crh::{rescue::CRH, CRHScheme},
    sponge::Absorb,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
    R1CS_PREDICATE_LABEL,
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng, UniformRand,
};
use garuda_bench::{create_test_rescue_parameter, RescueDemo, WIDTH};
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::{any::type_name, cmp::max, env, ops::Neg, time::Duration};

#[cfg(feature = "r1cs")]
fn run_bench<E: Pairing>(
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
    for _ in 0..WIDTH {
        input.push(<E::ScalarField>::rand(&mut rng));
    }
    let mut expected_image = CRH::<E::ScalarField>::evaluate(&config, input.clone()).unwrap();

    for _i in 0..(num_invocations - 1) {
        let output = vec![expected_image; WIDTH];
        expected_image = CRH::<E::ScalarField>::evaluate(&config, output.clone()).unwrap();
    }

    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let pk_size: usize = 0;
    let vk_size: usize = 0;
    let circuit = RescueDemo::<E::ScalarField> {
        input: Some(input.clone()),
        num_instances: input_size,
        image: Some(expected_image),
        config: config.clone(),
        num_invocations,
    };
    let circuit = circuit.clone();
    let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Weight);
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(cs);
    let mut gens =
        SNARKGens::<E::G1>::new(num_cons, num_vars, num_inputs, num_non_zero_entries + 1000);
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<E::G1>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }
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
    let proof_size = proof.compressed_size();
    let start = ark_std::time::Instant::now();
    for _ in 0..num_verifier_iterations {
        let mut verifier_transcript = Transcript::new(b"benchmark");
        assert!(proof
            .verify(&comm, &inputs, &mut verifier_transcript, &gens)
            .is_ok());
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
        prover_prep_time: Duration::new(0, 0),
        prover_corrected_time: (prover_time / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
        keygen_prep_time: Duration::new(0, 0),
        keygen_corrected_time: (keygen_time / num_keygen_iterations),
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
    for num_invocation in &num_invocations {
        let _ = run_bench::<Bls12_381>(*num_invocation, 20, 1, 1, 100, num_thread)
            .save_to_csv("spartan-r1cs.csv");
    }
}

/// Converts the arkworks R1CS constraint system to the Spartan R1CS format.
fn arkwork_r1cs_adapter<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
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
    let ark_amtrices: Vec<Vec<Vec<(F, usize)>>> =
        cs.to_matrices().unwrap()[R1CS_PREDICATE_LABEL].clone();
    let ark_amtrices = remap_all_matrices(
        ark_amtrices,
        cs.num_instance_variables(),
        cs.num_witness_variables(),
    );

    assert_eq!(ark_amtrices.len(), 3);
    let instance_assignment = cs.instance_assignment().unwrap();
    let witness_assignment = cs.witness_assignment().unwrap();
    let num_cons = cs.num_constraints();
    let num_inputs = cs.num_instance_variables() - 1;
    let num_vars = cs.num_witness_variables();
    assert_eq!(num_vars, witness_assignment.len());
    assert_eq!(num_inputs, instance_assignment.len() - 1);

    let mut a_mat: Vec<(usize, usize, F)> = Vec::new();
    let mut b_mat: Vec<(usize, usize, F)> = Vec::new();
    let mut c_mat: Vec<(usize, usize, F)> = Vec::new();
    ark_amtrices[0]
        .iter()
        .enumerate()
        .for_each(|(row_num, row)| {
            row.iter().for_each(|(entry, col_num)| {
                a_mat.push((row_num, *col_num, *entry));
            });
        });
    ark_amtrices[1]
        .iter()
        .enumerate()
        .for_each(|(row_num, row)| {
            row.iter().for_each(|(entry, col_num)| {
                b_mat.push((row_num, *col_num, *entry));
            });
        });

    ark_amtrices[2]
        .iter()
        .enumerate()
        .for_each(|(row_num, row)| {
            row.iter().for_each(|(entry, col_num)| {
                c_mat.push((row_num, *col_num, *entry));
            });
        });

    let inst = Instance::new(num_cons, num_vars, num_inputs, &a_mat, &b_mat, &c_mat).unwrap();
    let assignment_vars = VarsAssignment::new(&witness_assignment).unwrap();
    let assignment_inputs = InputsAssignment::new(&instance_assignment[1..]).unwrap();
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert!(res.unwrap());
    let num_non_zero_entries = max(a_mat.len(), max(b_mat.len(), c_mat.len()));
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

/// Remaps the columns of the matrices to match the Spartan R1CS format.
/// [ONE, INSTANCE,WITNESS] -> [WITNESS,ONE,INSTANCE]
pub fn remap_all_matrices<F: PrimeField>(
    matrices: Vec<Vec<Vec<(F, usize)>>>,
    num_instance: usize,
    num_witness: usize,
) -> Vec<Vec<Vec<(F, usize)>>> {
    matrices
        .into_iter()
        .map(|matrix| {
            matrix
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|(val, col)| {
                            let new_col = if col < num_instance {
                                col + num_witness
                            } else if col >= num_instance {
                                col - num_instance
                            } else {
                                col // leave untouched if it's outside the expected range
                            };
                            (val, new_col)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}
