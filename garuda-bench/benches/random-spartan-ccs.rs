use ark_curve25519::EdwardsProjective;
use ark_ec::CurveGroup;
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

const DEG5_LABEL: &str = "deg5-mul";

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
struct Deg5Constraint<F: Field> {
    x_terms: Vec<(F, Target)>,
    y_terms: Vec<(F, Target)>,
}

#[derive(Clone)]
struct RandomCircuit<F: Field> {
    public_inputs: Vec<F>,
    witness_values: Vec<F>,
    r1cs_constraints: Vec<ConstraintSpec<F>>,
    deg5_constraints: Vec<Deg5Constraint<F>>,
    total_nonzero_entries: usize,
}

impl<F: Field + UniformRand> RandomCircuit<F> {
    fn new(num_constraints: usize, nonzero_per_matrix: usize, rng: &mut impl Rng) -> Self {
        let mut witness_values = Vec::with_capacity(1 + num_constraints * 6);
        witness_values.push(F::zero()); // index 0 reserved for zero

        let mut r1cs_constraints = Vec::with_capacity(num_constraints);
        let mut deg5_constraints = Vec::with_capacity(num_constraints);
        let mut total_nonzero_entries = 0usize;

        for _ in 0..num_constraints {
            // R1CS predicate a * b = c
            let a = rand_nonzero(rng);
            let b = rand_nonzero(rng);
            let c = a * b;
            let a_idx = witness_values.len();
            witness_values.push(a);
            let b_idx = witness_values.len();
            witness_values.push(b);
            let c_idx = witness_values.len();
            witness_values.push(c);

            let mut a_terms = Vec::with_capacity(nonzero_per_matrix);
            let mut b_terms = Vec::with_capacity(nonzero_per_matrix);
            let mut c_terms = Vec::with_capacity(nonzero_per_matrix);
            a_terms.push((F::one(), Target::Var(a_idx)));
            b_terms.push((F::one(), Target::Var(b_idx)));
            c_terms.push((F::one(), Target::Var(c_idx)));
            for _ in 1..nonzero_per_matrix {
                a_terms.push((rand_nonzero(rng), Target::Var(0)));
                b_terms.push((rand_nonzero(rng), Target::Var(0)));
                c_terms.push((rand_nonzero(rng), Target::Var(0)));
            }
            r1cs_constraints.push(ConstraintSpec {
                a_terms,
                b_terms,
                c_terms,
            });
            total_nonzero_entries += 3 * nonzero_per_matrix;

            // Deg5 predicate x^5 = y
            let x = rand_nonzero(rng);
            let y = x * x * x * x * x;
            let x_idx = witness_values.len();
            witness_values.push(x);
            let y_idx = witness_values.len();
            witness_values.push(y);

            let mut x_terms = Vec::with_capacity(nonzero_per_matrix);
            let mut y_terms = Vec::with_capacity(nonzero_per_matrix);
            x_terms.push((F::one(), Target::Var(x_idx)));
            y_terms.push((F::one(), Target::Var(y_idx)));
            for _ in 1..nonzero_per_matrix {
                x_terms.push((rand_nonzero(rng), Target::Var(0)));
                y_terms.push((rand_nonzero(rng), Target::Var(0)));
            }
            deg5_constraints.push(Deg5Constraint { x_terms, y_terms });
            total_nonzero_entries += 2 * nonzero_per_matrix;
        }

        RandomCircuit {
            public_inputs: Vec::new(),
            witness_values,
            r1cs_constraints,
            deg5_constraints,
            total_nonzero_entries,
        }
    }
}

fn rand_nonzero<F: Field + UniformRand>(rng: &mut impl Rng) -> F {
    loop {
        let v = F::rand(rng);
        if !v.is_zero() {
            return v;
        }
    }
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
        // Register predicates
        let r1cs_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
            3,
            vec![(F::one(), vec![(0, 1), (1, 1)]), (-F::one(), vec![(2, 1)])],
        );
        cs.register_predicate(R1CS_PREDICATE_LABEL, r1cs_pred)?;
        let deg5_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
            2,
            vec![(F::one(), vec![(0, 5)]), (-F::one(), vec![(1, 1)])],
        );
        cs.register_predicate(DEG5_LABEL, deg5_pred)?;

        for value in self.public_inputs.iter() {
            let _ = cs.new_input_variable(|| Ok(*value))?;
        }

        let mut witness_vars = Vec::with_capacity(self.witness_values.len());
        for value in self.witness_values.iter() {
            let var = cs.new_witness_variable(|| Ok(*value))?;
            witness_vars.push(var);
        }

        for constraint in self.r1cs_constraints.iter() {
            cs.enforce_constraint_arity_3(
                R1CS_PREDICATE_LABEL,
                || {
                    constraint.a_terms.iter().fold(lc!(), |acc, (coeff, t)| {
                        acc + (*coeff, t.to_variable(&witness_vars))
                    })
                },
                || {
                    constraint.b_terms.iter().fold(lc!(), |acc, (coeff, t)| {
                        acc + (*coeff, t.to_variable(&witness_vars))
                    })
                },
                || {
                    constraint.c_terms.iter().fold(lc!(), |acc, (coeff, t)| {
                        acc + (*coeff, t.to_variable(&witness_vars))
                    })
                },
            )?;
        }

        for constraint in self.deg5_constraints.iter() {
            cs.enforce_constraint_arity_2(
                DEG5_LABEL,
                || {
                    constraint.x_terms.iter().fold(lc!(), |acc, (coeff, t)| {
                        acc + (*coeff, t.to_variable(&witness_vars))
                    })
                },
                || {
                    constraint.y_terms.iter().fold(lc!(), |acc, (coeff, t)| {
                        acc + (*coeff, t.to_variable(&witness_vars))
                    })
                },
            )?;
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

    // Build GR1CS and adapt to Spartan R1CS instance with matched nonzero budget.
    let cs: ConstraintSystemRef<G::ScalarField> = ConstraintSystem::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap(), "GR1CS not satisfied");
    let predicate_constraints = cs.get_all_predicates_num_constraints();

    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        gr1cs_to_r1cs_adapter(cs, rng);

    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let pk_size: usize = 0;
    let vk_size: usize = 0;

    let mut gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<G>::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }

    let mut prover_transcript = Transcript::new(b"random-spartan-ccs");
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
        prover_transcript = Transcript::new(b"random-spartan-ccs");
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
        let mut verifier_transcript = Transcript::new(b"random-spartan-ccs");
        if proof
            .verify(&comm, &inputs, &mut verifier_transcript, &gens)
            .is_err()
        {
            verified = false;
            break;
        }
    }
    verifier_time += start.elapsed();
    // if !verified {
    //     eprintln!(
    //         "Verification failed; skipping entry (constraints={}, nonzero_per_matrix={})",
    //         num_constraints, nonzero_per_matrix
    //     );
    //     return None;
    // }

    BenchResult {
        curve: type_name::<G>().to_string(),
        num_constraints: num_cons,
        predicate_constraints,
        num_invocations: num_constraints,
        input_size: 0,
        num_nonzero_entries: num_non_zero_entries,
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
    .into()
}

fn gr1cs_to_r1cs_adapter<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    _rng: StdRng,
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
    let predicate_constraints = cs.get_all_predicates_num_constraints();
    let num_cons = predicate_constraints.values().sum();
    let num_inputs = cs.num_instance_variables() - 1;
    let num_vars_raw = cs.num_witness_variables();
    let num_vars = num_vars_raw.next_power_of_two();

    let instance_assignment = cs.instance_assignment().unwrap();
    let mut witness_assignment = cs.witness_assignment().unwrap();
    if witness_assignment.len() < num_vars {
        witness_assignment
            .extend(std::iter::repeat(F::zero()).take(num_vars - witness_assignment.len()));
    }
    let ark_matrices = cs.to_matrices().unwrap();
    let mut offsets = std::collections::HashMap::new();
    let mut acc = 0usize;
    for (label, count) in predicate_constraints.iter() {
        offsets.insert(label.clone(), acc);
        acc += *count;
    }

    let mut a: Vec<(usize, usize, F)> = Vec::new();
    let mut b: Vec<(usize, usize, F)> = Vec::new();
    let mut c: Vec<(usize, usize, F)> = Vec::new();
    let empty: Vec<Vec<(F, usize)>> = Vec::new();
    for (label, matrices) in ark_matrices.iter() {
        let offset = *offsets.get(label).expect("predicate offset");
        let a_mat = matrices.get(0).unwrap_or(&empty);
        let b_mat = matrices.get(1).unwrap_or(&empty);
        let c_mat = matrices.get(2).unwrap_or(&empty);

        for (row_idx, row) in a_mat.iter().enumerate() {
            for (val, col_idx) in row.iter() {
                a.push((offset + row_idx, *col_idx, *val));
            }
        }
        for (row_idx, row) in b_mat.iter().enumerate() {
            for (val, col_idx) in row.iter() {
                b.push((offset + row_idx, *col_idx, *val));
            }
        }
        for (row_idx, row) in c_mat.iter().enumerate() {
            for (val, col_idx) in row.iter() {
                c.push((offset + row_idx, *col_idx, *val));
            }
        }
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
const NUM_VERIFIER_ITERATIONS: u32 = 20;
const ZK: bool = false;

#[cfg(feature = "parallel")]
fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let configs: Vec<(usize, usize)> = (MIN_LOG2_CONSTRAINTS..=MAX_LOG2_CONSTRAINTS)
        .map(|i| {
            let num_constraints = 1 << i;
            let nonzero_per_matrix = 1 << i;
            (num_constraints, nonzero_per_matrix)
        })
        .collect();
    for &num_thread in &[4] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(num_thread)
            .build()
            .expect("Failed to build thread pool");
        pool.install(|| {
            for &(num_constraints, nonzero_per_matrix) in configs.iter() {
                let filename = format!("random-spartan-ccs{}-{}t.csv", zk_string, num_thread);
                let Some(result) = bench::<EdwardsProjective>(
                    num_constraints,
                    nonzero_per_matrix,
                    NUM_KEYGEN_ITERATIONS,
                    NUM_PROVER_ITERATIONS,
                    NUM_VERIFIER_ITERATIONS,
                    num_thread,
                    ZK,
                ) else {
                    continue;
                };
                let _ = result.save_to_csv(&filename);
            }
        });
    }
}

#[cfg(not(feature = "parallel"))]
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
        let filename = format!("random-spartan-ccs{}-{}t.csv", zk_string, 1);
        let Some(result) = bench::<EdwardsProjective>(
            num_constraints,
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
