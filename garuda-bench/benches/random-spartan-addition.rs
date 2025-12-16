use ark_curve25519::EdwardsProjective;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, Variable,
};
use ark_relations::lc;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{
    rand::RngCore,
    rand::{rngs::StdRng, Rng, SeedableRng},
    test_rng,
};
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::cmp::max;
use std::ops::Neg;
use std::time::Duration;

#[derive(Clone)]
enum Target {
    Var(usize),
    One,
}

#[derive(Clone)]
struct ConstraintSpec<F: Field> {
    a_terms: Vec<(F, Target)>,
    b_terms: Vec<(F, Target)>,
    c_terms: Vec<(F, Target)>,
}

#[derive(Clone)]
struct RandomCircuit<F: Field> {
    public_inputs: Vec<F>,
    witness_values: Vec<F>,
    constraints: Vec<ConstraintSpec<F>>,
    total_nonzero_entries: usize,
}

impl<F: Field + UniformRand> RandomCircuit<F> {
    fn new(
        num_constraints: usize,
        nonzero_per_matrix: usize,
        rng: &mut impl Rng,
    ) -> RandomCircuit<F> {
        let base_witness_count = nonzero_per_matrix.max(2);

        let mut witness_values = Vec::with_capacity(base_witness_count);
        witness_values.push(F::zero());
        for _ in 1..base_witness_count {
            witness_values.push(rand_nonzero(rng));
        }
        let a_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let b_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let c_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let total_nonzero_entries: usize = a_counts.iter().sum::<usize>()
            + b_counts.iter().sum::<usize>()
            + c_counts.iter().sum::<usize>();

        let mut constraints = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            let force_zero_product = c_counts[i] == 0;
            let (a_terms, a_value) =
                sample_linear_combination(&witness_values, a_counts[i], force_zero_product, rng);
            let (b_terms, b_value) =
                sample_linear_combination(&witness_values, b_counts[i], force_zero_product, rng);
            let product_value = a_value * b_value;

            let mut c_terms = Vec::new();
            if c_counts[i] > 0 {
                let product_idx = witness_values.len();
                witness_values.push(product_value);
                c_terms.push((F::one(), Target::Var(product_idx)));
                for _ in 1..c_counts[i] {
                    c_terms.push((rand_nonzero(rng), Target::Var(0)));
                }
            } else {
                assert!(product_value.is_zero());
            }

            constraints.push(ConstraintSpec {
                a_terms,
                b_terms,
                c_terms,
            });
        }

        RandomCircuit {
            public_inputs: Vec::new(),
            witness_values,
            constraints,
            total_nonzero_entries,
        }
    }
}

fn distribute_counts(total: usize, slots: usize) -> Vec<usize> {
    if slots == 0 {
        return Vec::new();
    }
    let base = total / slots;
    let remainder = total % slots;

    (0..slots)
        .map(|i| base + usize::from(i < remainder))
        .collect()
}

fn rand_nonzero<F: Field + UniformRand>(rng: &mut impl Rng) -> F {
    loop {
        let candidate = F::rand(rng);
        if !candidate.is_zero() {
            return candidate;
        }
    }
}

fn sample_linear_combination<F: Field + UniformRand>(
    witness_values: &[F],
    count: usize,
    force_zero_value: bool,
    rng: &mut impl Rng,
) -> (Vec<(F, Target)>, F) {
    if count == 0 {
        return (Vec::new(), F::zero());
    }

    let mut terms = Vec::with_capacity(count);
    let mut value = F::zero();

    for _ in 0..count {
        let (coeff, idx) = if force_zero_value {
            (rand_nonzero(rng), 0usize)
        } else {
            (rand_nonzero(rng), rng.gen_range(0..witness_values.len()))
        };
        value += coeff * witness_values[idx];
        terms.push((coeff, Target::Var(idx)));
    }

    (terms, value)
}

impl Target {
    fn to_variable(&self, witnesses: &[Variable]) -> Variable {
        match self {
            Target::Var(idx) => witnesses[*idx],
            Target::One => Variable::One,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RandomCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        for value in self.public_inputs.iter() {
            let _ = cs.new_input_variable(|| Ok(*value))?;
        }

        let mut witness_vars = Vec::with_capacity(self.witness_values.len());
        for value in self.witness_values.iter() {
            let var = cs.new_witness_variable(|| Ok(*value))?;
            witness_vars.push(var);
        }

        for constraint in self.constraints.iter() {
            let a_lc = constraint
                .a_terms
                .iter()
                .fold(lc!(), |acc, (coeff, target)| {
                    acc + (*coeff, target.to_variable(&witness_vars))
                });
            let b_lc = constraint
                .b_terms
                .iter()
                .fold(lc!(), |acc, (coeff, target)| {
                    acc + (*coeff, target.to_variable(&witness_vars))
                });
            let c_lc = constraint
                .c_terms
                .iter()
                .fold(lc!(), |acc, (coeff, target)| {
                    acc + (*coeff, target.to_variable(&witness_vars))
                });

            cs.enforce_r1cs_constraint(|| a_lc.clone(), || b_lc.clone(), || c_lc.clone())?;
        }

        Ok(())
    }
}

fn bench<G: CurveGroup>(
    num_constraints: usize,
    nonzero_per_matrix: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    _zk: bool,
) -> Option<BenchResult>
where
    G::ScalarField: PrimeField + UniformRand,
    G::Affine: Neg<Output = G::Affine>,
    BigUint: From<<G::ScalarField as PrimeField>::BigInt>,
{
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let circuit =
        RandomCircuit::<G::ScalarField>::new(num_constraints, nonzero_per_matrix, &mut rng);

    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let pk_size: usize = 0;
    let vk_size: usize = 0;

    let cs: ConstraintSystemRef<G::ScalarField> = ConstraintSystem::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap(), "R1CS not satisfied");
    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        circuit_to_spartan_instance(&circuit);

    let mut gens = SNARKGens::<G>::new(
        num_cons,
        num_vars,
        num_inputs,
        next_power_of_two(num_non_zero_entries),
    );
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<G>::new(
            num_cons,
            num_vars,
            num_inputs,
            next_power_of_two(num_non_zero_entries),
        );
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }

    let mut prover_transcript = Transcript::new(b"random-spartan-addition");
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
        prover_transcript = Transcript::new(b"random-spartan-addition");
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
        let mut verifier_transcript = Transcript::new(b"random-spartan-addition");
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
        curve: type_name::<G>().to_string(),
        num_constraints: cs.num_constraints(),
        predicate_constraints: cs.get_all_predicates_num_constraints(),
        num_invocations: num_constraints,
        input_size: FIXED_INPUT_SIZE,
        num_nonzero_entries: circuit.total_nonzero_entries,
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

fn circuit_to_spartan_instance<F: PrimeField>(
    circuit: &RandomCircuit<F>,
) -> (
    usize,
    usize,
    usize,
    usize,
    Instance<F>,
    VarsAssignment<F>,
    InputsAssignment<F>,
) {
    let num_cons = circuit.constraints.len();
    let num_inputs = circuit.public_inputs.len();
    let min_vars = circuit.witness_values.len();
    let num_vars = next_power_of_two(min_vars.max(num_inputs + 1));

    // Build R1CS matrices directly from the synthetic constraints.
    let mut a: Vec<(usize, usize, F)> = Vec::new();
    let mut b: Vec<(usize, usize, F)> = Vec::new();
    let mut c: Vec<(usize, usize, F)> = Vec::new();

    let mut a_map = std::collections::HashMap::new();
    let mut b_map = std::collections::HashMap::new();
    let mut c_map = std::collections::HashMap::new();

    for (row_idx, constraint) in circuit.constraints.iter().enumerate() {
        for (coeff, target) in constraint.a_terms.iter() {
            let col = target_to_col(target, num_vars, num_inputs);
            *a_map.entry((row_idx, col)).or_insert(F::zero()) += coeff;
        }
        for (coeff, target) in constraint.b_terms.iter() {
            let col = target_to_col(target, num_vars, num_inputs);
            *b_map.entry((row_idx, col)).or_insert(F::zero()) += coeff;
        }
        for (coeff, target) in constraint.c_terms.iter() {
            let col = target_to_col(target, num_vars, num_inputs);
            *c_map.entry((row_idx, col)).or_insert(F::zero()) += coeff;
        }
    }

    let mut a: Vec<(usize, usize, F)> = a_map.into_iter().map(|((r, c), v)| (r, c, v)).collect();
    let mut b: Vec<(usize, usize, F)> = b_map.into_iter().map(|((r, c), v)| (r, c, v)).collect();
    let mut c: Vec<(usize, usize, F)> = c_map.into_iter().map(|((r, c), v)| (r, c, v)).collect();

    // Spartan expects the entries to be within the column bounds; we only keep non-zero coeffs.
    a.retain(|(_, _, v)| !v.is_zero());
    b.retain(|(_, _, v)| !v.is_zero());
    c.retain(|(_, _, v)| !v.is_zero());

    let inst = Instance::new(num_cons, num_vars, num_inputs, &a, &b, &c).unwrap();
    let assignment_vars = VarsAssignment::new(&circuit.witness_values).unwrap();
    // InputsAssignment excludes the leading 1; we have no public inputs here.
    let assignment_inputs = InputsAssignment::new(&[]).unwrap();
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

fn target_to_col(target: &Target, num_vars: usize, num_inputs: usize) -> usize {
    match target {
        // Spartan ordering: [vars | 1 | inputs]
        Target::One => num_vars,
        Target::Var(idx) => *idx,
    }
}

fn next_power_of_two(n: usize) -> usize {
    if n <= 1 {
        1
    } else {
        n.next_power_of_two()
    }
}

const FIXED_NUM_CONSTRAINTS: usize = 2usize.pow(18);
const FIXED_INPUT_SIZE: usize = 0;
const NONZERO_MULTIPLIERS: [usize; 5] = [2, 4, 8, 16, 32];
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 20;
const ZK: bool = false;

fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let configs: Vec<usize> = NONZERO_MULTIPLIERS
        .iter()
        .map(|mult| mult * FIXED_NUM_CONSTRAINTS)
        .collect();
    for &nonzero_per_matrix in configs.iter() {
        let filename = format!("random-spartan-addition{}-{}t.csv", zk_string, 1);
        let Some(result) = bench::<EdwardsProjective>(
            FIXED_NUM_CONSTRAINTS,
            nonzero_per_matrix,
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
