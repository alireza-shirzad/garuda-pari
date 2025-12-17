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
        // Seed the witness pool. Slot 0 is zero, the rest are random nonzero witnesses.
        let base_witness_count = nonzero_per_matrix.max(2);

        let mut base_values = Vec::with_capacity(base_witness_count);
        base_values.push(F::zero());
        for _ in 1..base_witness_count {
            base_values.push(rand_nonzero(rng));
        }

        let mut witness_values = base_values.clone();
        // Evenly split the requested nonzeros per matrix across constraints.
        let a_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let b_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let c_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let total_nonzero_entries: usize = a_counts.iter().sum::<usize>()
            + b_counts.iter().sum::<usize>()
            + c_counts.iter().sum::<usize>();

        let mut constraints = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            let force_zero_product = c_counts[i] == 0;
            // Pick A and B linear combinations; optionally force them to be zero if C has no slots.
            let (a_terms, a_value) =
                sample_linear_combination(&base_values, a_counts[i], force_zero_product, rng);
            let (b_terms, b_value) =
                sample_linear_combination(&base_values, b_counts[i], force_zero_product, rng);
            let product_value = a_value * b_value;

            let mut c_terms = Vec::new();
            if c_counts[i] > 0 {
                // Materialize the exact product as a new witness and point C to it.
                let product_idx = witness_values.len();
                witness_values.push(product_value);
                c_terms.push((F::one(), Target::Var(product_idx)));
                // Fill remaining requested nonzeros (if any) with dummy refs to witness 0.
                for _ in 1..c_counts[i] {
                    c_terms.push((rand_nonzero(rng), Target::Var(0)));
                }
            } else {
                // When C has no non-zero entries, force the product to be zero.
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
    // Spread `total` as evenly as possible across `slots` (floor + remainder).
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
        // Optionally force the LC to be zero by always pointing to the zero witness.
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
) -> BenchResult
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
    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        arkwork_r1cs_adapter(cs.clone(), rng);

    let mut gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }

    let mut prover_transcript = Transcript::new(b"random-spartan");
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
        prover_transcript = Transcript::new(b"random-spartan");
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
        let mut verifier_transcript = Transcript::new(b"random-spartan");
        let _ = proof
            .verify(&comm, &inputs, &mut verifier_transcript, &gens)
            .is_ok();
    }
    verifier_time += start.elapsed();

    BenchResult {
        curve: type_name::<G>().to_string(),
        num_constraints: cs.num_constraints(),
        predicate_constraints: cs.get_all_predicates_num_constraints(),
        num_invocations: num_constraints,
        input_size: nonzero_per_matrix,
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

const MIN_LOG2_CONSTRAINTS: usize = 1;
const MAX_LOG2_CONSTRAINTS: usize = 30;
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 1;
const ZK: bool = false;

fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let configs: Vec<(usize, usize)> = (MIN_LOG2_CONSTRAINTS..=MAX_LOG2_CONSTRAINTS)
        .map(|i| {
            let num_constraints = 1 << i;
            let nonzero_per_matrix = 1 << i;
            (num_constraints, nonzero_per_matrix)
        })
        .collect();
    for &(num_constraints, nonzero_per_matrix) in configs.iter() {
        let filename = format!("random-spartan{}-{}t.csv", zk_string, 1);
        let _ = bench::<EdwardsProjective>(
            num_constraints,
            nonzero_per_matrix,
            NUM_KEYGEN_ITERATIONS,
            NUM_PROVER_ITERATIONS,
            NUM_VERIFIER_ITERATIONS,
            1,
            ZK,
        )
        .save_to_csv(&filename);
    }
}
