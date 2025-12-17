use ark_curve25519::{EdwardsProjective, Fr as CurveFr};
use ark_ff::{Field, PrimeField};
use ark_relations::gr1cs::{
    predicate::PredicateConstraintSystem, ConstraintSynthesizer, ConstraintSystemRef,
    SynthesisError, Variable, R1CS_PREDICATE_LABEL,
};
use ark_relations::lc;
use ark_relations::utils::{HashBuilder, IndexMap};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{
    rand::RngCore,
    rand::{rngs::StdRng, Rng, SeedableRng},
    test_rng,
};
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::cmp::max;
use std::time::Duration;

const DEG5_LABEL: &str = "deg5-mul";
// Split evenly so total constraints remain 2^18 across predicates.
const FIXED_R1CS_CONSTRAINTS: usize = 2usize.pow(17);
const FIXED_DEG5_CONSTRAINTS: usize = 2usize.pow(17);

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
    fn new(nonzero_per_matrix: usize, rng: &mut impl Rng) -> Self {
        let mut witness_values =
            Vec::with_capacity(1 + (FIXED_R1CS_CONSTRAINTS + FIXED_DEG5_CONSTRAINTS) * 6);
        witness_values.push(F::zero()); // index 0 reserved for zero

        let mut r1cs_constraints = Vec::with_capacity(FIXED_R1CS_CONSTRAINTS);
        let mut deg5_constraints = Vec::with_capacity(FIXED_DEG5_CONSTRAINTS);
        let mut total_nonzero_entries = 0usize;

        for _ in 0..FIXED_R1CS_CONSTRAINTS {
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
        }

        for _ in 0..FIXED_DEG5_CONSTRAINTS {
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
    let mut witness_values = circuit.witness_values.clone();
    let mut a: Vec<(usize, usize, F)> = Vec::new();
    let mut b: Vec<(usize, usize, F)> = Vec::new();
    let mut c: Vec<(usize, usize, F)> = Vec::new();
    let mut row_idx = 0usize;

    let mut add_row =
        |a_terms: &[(F, Target)], b_terms: &[(F, Target)], c_terms: &[(F, Target)], row: usize| {
            for (coeff, t) in a_terms.iter() {
                a.push((row, target_to_col(t), *coeff));
            }
            for (coeff, t) in b_terms.iter() {
                b.push((row, target_to_col(t), *coeff));
            }
            for (coeff, t) in c_terms.iter() {
                c.push((row, target_to_col(t), *coeff));
            }
        };

    for constraint in circuit.r1cs_constraints.iter() {
        add_row(
            &constraint.a_terms,
            &constraint.b_terms,
            &constraint.c_terms,
            row_idx,
        );
        row_idx += 1;
    }

    for constraint in circuit.deg5_constraints.iter() {
        let x_idx = match constraint.x_terms.get(0) {
            Some((_, Target::Var(idx))) => *idx,
            _ => 0,
        };
        let y_idx = match constraint.y_terms.get(0) {
            Some((_, Target::Var(idx))) => *idx,
            _ => 0,
        };
        let x = witness_values[x_idx];
        let _y = witness_values[y_idx];
        let t1 = x * x;
        let t2 = t1 * x;
        let t3 = t2 * x;
        let t1_idx = witness_values.len();
        witness_values.push(t1);
        let t2_idx = witness_values.len();
        witness_values.push(t2);
        let t3_idx = witness_values.len();
        witness_values.push(t3);

        let one = F::one();
        add_row(
            &[(one, Target::Var(x_idx))],
            &[(one, Target::Var(x_idx))],
            &[(one, Target::Var(t1_idx))],
            row_idx,
        );
        row_idx += 1;
        add_row(
            &[(one, Target::Var(t1_idx))],
            &[(one, Target::Var(x_idx))],
            &[(one, Target::Var(t2_idx))],
            row_idx,
        );
        row_idx += 1;
        add_row(
            &[(one, Target::Var(t2_idx))],
            &[(one, Target::Var(x_idx))],
            &[(one, Target::Var(t3_idx))],
            row_idx,
        );
        row_idx += 1;
        add_row(
            &[(one, Target::Var(t3_idx))],
            &[(one, Target::Var(x_idx))],
            &[(one, Target::Var(y_idx))],
            row_idx,
        );
        row_idx += 1;
    }

    let num_cons_raw = row_idx.max(1);
    let num_cons = num_cons_raw.next_power_of_two();
    let num_inputs = 0;
    let num_vars_raw = witness_values.len().max(1);
    let num_vars = num_vars_raw.next_power_of_two();
    if witness_values.len() < num_vars {
        witness_values.extend(std::iter::repeat(F::zero()).take(num_vars - witness_values.len()));
    }

    let inst = Instance::new(num_cons, num_vars, num_inputs, &a, &b, &c).unwrap();
    let assignment_vars = VarsAssignment::new(&witness_values).unwrap();
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

fn target_to_col(target: &Target) -> usize {
    match target {
        Target::One => 0,
        Target::Var(idx) => 1 + idx,
    }
}

fn bench_spartan(
    num_constraints: usize,
    nonzero_per_matrix: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    zk: bool,
) -> Option<BenchResult> {
    type Fr = CurveFr;
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = RandomCircuit::<Fr>::new(nonzero_per_matrix, &mut rng);

    let (num_cons, num_vars, num_inputs, num_non_zero_entries, inst, vars, inputs) =
        circuit_to_spartan_instance(&circuit);
    // Report logical GR1CS counts (pre-expansion) to match garuda-gr1cs-addition configs.
    let logical_num_constraints = FIXED_R1CS_CONSTRAINTS + FIXED_DEG5_CONSTRAINTS;
    let logical_num_nonzero_entries = (3 * nonzero_per_matrix * FIXED_R1CS_CONSTRAINTS)
        + (2 * nonzero_per_matrix * FIXED_DEG5_CONSTRAINTS);
    let mut predicate_constraints: IndexMap<_, _> = IndexMap::with_hasher(HashBuilder::default());
    predicate_constraints.insert(R1CS_PREDICATE_LABEL.to_string(), FIXED_R1CS_CONSTRAINTS);
    predicate_constraints.insert(DEG5_LABEL.to_string(), FIXED_DEG5_CONSTRAINTS);

    let mut prover_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let pk_size: usize = 0;
    let vk_size: usize = 0;

    let mut gens = SNARKGens::<EdwardsProjective>::new(
        num_cons,
        num_vars,
        num_inputs,
        num_non_zero_entries.next_power_of_two().max(1),
    );
    let (mut comm, mut decomm) = SNARK::encode(&inst, &gens);
    for _ in 0..num_keygen_iterations {
        let start = ark_std::time::Instant::now();
        gens = SNARKGens::<EdwardsProjective>::new(
            num_cons,
            num_vars,
            num_inputs,
            num_non_zero_entries.next_power_of_two().max(1),
        );
        (comm, decomm) = SNARK::encode(&inst, &gens);
        keygen_time += start.elapsed();
    }

    let mut prover_transcript = Transcript::new(b"random-spartan-ccs-addition");
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
        prover_transcript = Transcript::new(b"random-spartan-ccs-addition");
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
        let mut verifier_transcript = Transcript::new(b"random-spartan-ccs-addition");
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
        curve: type_name::<EdwardsProjective>().to_string(),
        num_constraints: logical_num_constraints,
        predicate_constraints,
        num_invocations: num_constraints,
        input_size: 0,
        num_nonzero_entries: logical_num_nonzero_entries,
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

// Number of nonzeros per row (per constraint) to sweep.
const NONZERO_PER_ROW: [usize; 5] = [2, 4, 8, 16, 32];
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 1;
const ZK: bool = false;

fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let configs: Vec<usize> = NONZERO_PER_ROW.to_vec();
    for &nonzero_per_matrix in configs.iter() {
        let filename = format!("random-spartan-ccs-addition{}-{}t.csv", zk_string, 1);
        let Some(result) = bench_spartan(
            FIXED_R1CS_CONSTRAINTS + FIXED_DEG5_CONSTRAINTS,
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
