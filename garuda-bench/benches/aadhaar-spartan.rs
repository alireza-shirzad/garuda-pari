use std::time::Instant;

use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_std::test_rng;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use ark_serialize::CanonicalSerialize;
fn main() {
    type E = Bn254;
    type G = <E as Pairing>::G1;
    type Fr = <E as Pairing>::ScalarField;

    // Load the WASM and R1CS for witness and proof generation.
    let cfg = CircomConfig::<Fr>::new(
        "./circuits/aadhaar/aadhaar-verifier.wasm",
        "./circuits/aadhaar/aadhaar-verifier.r1cs",
    )
    .expect("circom config");
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let mut builder = CircomBuilder::new(cfg);
    builder
        .load_input_json("./circuits/aadhaar/input.json")
        .expect("load input");
    let circom = builder.build().expect("build circom");

    // Build a constraint system and adapt it to libspartan's R1CS format.
    let cs = ConstraintSystem::<Fr>::new_ref();
    circom
        .clone()
        .generate_constraints(cs.clone())
        .expect("generate constraints");
    cs.finalize();
    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(cs, rng.clone());

    // Key generation (encode the instance).
    let start = Instant::now();
    let mut gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    let keygen_time = start.elapsed();
    println!("Keygen took: {:?}", keygen_time);

    // Proving.
    let start = Instant::now();
    let mut prover_transcript = Transcript::new(b"aadhaar-spartan");
    let proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        vars.clone(),
        &inputs,
        &gens,
        &mut prover_transcript,
    );
    let proof_size = proof.compressed_size();
    let prover_time = start.elapsed();
    println!("Prover took: {:?}, proof size: {} bytes", prover_time, proof_size);

    // Verifying.
    let start = Instant::now();
    let mut verifier_transcript = Transcript::new(b"aadhaar-spartan");
    let ok = proof
        .verify(&comm, &inputs, &mut verifier_transcript, &gens)
        .is_ok();
    let verifier_time = start.elapsed();
    println!("Verifier took: {:?}, verified: {}", verifier_time, ok);
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
    let num_non_zero_entries = std::cmp::max(a.len(), std::cmp::max(b.len(), c.len()));
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
