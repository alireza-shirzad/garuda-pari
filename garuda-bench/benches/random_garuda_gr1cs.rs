use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField};
use ark_relations::gr1cs::{
    predicate::PredicateConstraintSystem, ConstraintSynthesizer, ConstraintSystem,
    ConstraintSystemRef, R1CS_PREDICATE_LABEL, SynthesisError, Variable,
};
use ark_relations::lc;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{
    rand::RngCore,
    rand::{rngs::StdRng, Rng, SeedableRng},
    test_rng,
};
use garuda::Garuda;
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
use std::ops::Neg;
use std::panic::{self, AssertUnwindSafe};
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
    y_terms: Vec<(F, Target)>, // y = x^5
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
        witness_values.push(F::zero()); // idx 0 => zero witness

        let mut r1cs_constraints = Vec::with_capacity(num_constraints);
        let mut deg5_constraints = Vec::with_capacity(num_constraints);
        let mut total_nonzero_entries = 0usize;

        for _ in 0..num_constraints {
            // R1CS predicate: a * b = c
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

            // Deg5 predicate: y = x^5
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
        use ark_relations::gr1cs::predicate::PredicateConstraintSystem;

        // Register predicates: standard R1CS and degree-5 multiplication.
        let r1cs_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
            3,
            vec![
                (F::one(), vec![(0, 1), (1, 1)]),
                (-F::one(), vec![(2, 1)]),
            ],
        );
        cs.register_predicate(R1CS_PREDICATE_LABEL, r1cs_pred)?;

        let deg5_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
            2,
            vec![
                (F::one(), vec![(0, 5)]),
                (-F::one(), vec![(1, 1)]),
            ],
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
                    constraint
                        .a_terms
                        .iter()
                        .fold(lc!(), |acc, (coeff, t)| acc + (*coeff, t.to_variable(&witness_vars)))
                },
                || {
                    constraint
                        .b_terms
                        .iter()
                        .fold(lc!(), |acc, (coeff, t)| acc + (*coeff, t.to_variable(&witness_vars)))
                },
                || {
                    constraint
                        .c_terms
                        .iter()
                        .fold(lc!(), |acc, (coeff, t)| acc + (*coeff, t.to_variable(&witness_vars)))
                },
            )?;
        }

        for constraint in self.deg5_constraints.iter() {
            cs.enforce_constraint_arity_2(
                DEG5_LABEL,
                || {
                    constraint
                        .x_terms
                        .iter()
                        .fold(lc!(), |acc, (coeff, t)| acc + (*coeff, t.to_variable(&witness_vars)))
                },
                || {
                    constraint
                        .y_terms
                        .iter()
                        .fold(lc!(), |acc, (coeff, t)| acc + (*coeff, t.to_variable(&witness_vars)))
                },
            )?;
        }

        Ok(())
    }
}

fn bench<E: Pairing>(
    num_constraints: usize,
    nonzero_per_matrix: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    zk: bool,
) -> Option<BenchResult>
where
    E::ScalarField: PrimeField + UniformRand,
    E::G1Affine: Neg<Output = E::G1Affine>,
    <E::G1Affine as AffineRepr>::BaseField: PrimeField,
{
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let circuit =
        RandomCircuit::<E::ScalarField>::new(num_constraints, nonzero_per_matrix, &mut rng);
    let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap(), "GR1CS not satisfied");

    let mut prover_time = Duration::new(0, 0);
    let mut prover_prep_time = Duration::new(0, 0);
    let mut keygen_time = Duration::new(0, 0);
    let mut keygen_prep_time = Duration::new(0, 0);
    let mut verifier_time = Duration::new(0, 0);
    let (mut pk, mut vk) = (None, None);

    for _ in 0..num_keygen_iterations {
        let setup_circuit = circuit.clone();

        let start = ark_std::time::Instant::now();
        let _cs = Garuda::<E>::circuit_to_keygen_cs(setup_circuit.clone(), zk).unwrap();
        keygen_prep_time += start.elapsed();
        let start = ark_std::time::Instant::now();
        let (ipk, ivk) = Garuda::<E>::keygen(setup_circuit, zk, &mut rng);
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
        let zk_rng = if zk { Some(&mut rng) } else { None };
        let prover_circuit = circuit.clone();

        let start = ark_std::time::Instant::now();
        let _cs = Garuda::<E>::circuit_to_prover_cs(prover_circuit.clone(), zk).unwrap();
        prover_prep_time += start.elapsed();
        let start = ark_std::time::Instant::now();
        proof = pk
            .as_ref()
            .map(|pk| Garuda::prove(pk, zk_rng, prover_circuit).unwrap());
        prover_time += start.elapsed();
    }

    let proof_size = proof
        .as_ref()
        .unwrap()
        .serialized_size(ark_serialize::Compress::Yes);

    let start = ark_std::time::Instant::now();
    let mut all_verified = true;
    for _ in 0..num_verifier_iterations {
        let verified = panic::catch_unwind(AssertUnwindSafe(|| {
            Garuda::verify(proof.as_ref().unwrap(), vk.as_ref().unwrap(), &[])
        }))
        .map(|ok| ok)
        .unwrap_or(false);
        if !verified {
            all_verified = false;
            break;
        }
    }
    verifier_time += start.elapsed();
    if !all_verified {
        eprintln!(
            "Verification failed; skipping entry (constraints={}, nonzero_per_matrix={})",
            num_constraints, nonzero_per_matrix
        );
        return None;
    }

    let prover_corrected = prover_time
        .checked_sub(prover_prep_time)
        .unwrap_or_else(|| Duration::new(0, 0));
    let keygen_corrected = keygen_time
        .checked_sub(keygen_prep_time)
        .unwrap_or_else(|| Duration::new(0, 0));

    BenchResult {
        curve: type_name::<E>().to_string(),
        num_invocations: num_constraints,
        input_size: 0,
        num_nonzero_entries: circuit.total_nonzero_entries,
        num_constraints: cs.num_constraints(),
        predicate_constraints: cs.get_all_predicates_num_constraints(),
        num_thread,
        num_keygen_iterations: num_keygen_iterations as usize,
        num_prover_iterations: num_prover_iterations as usize,
        num_verifier_iterations: num_verifier_iterations as usize,
        pk_size,
        vk_size,
        proof_size,
        prover_time: (prover_time / num_prover_iterations),
        prover_prep_time: (prover_prep_time / num_prover_iterations),
        prover_corrected_time: (prover_corrected / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
        keygen_prep_time: (keygen_prep_time / num_keygen_iterations),
        keygen_corrected_time: (keygen_corrected / num_keygen_iterations),
    }
    .into()
}

const FIXED_NUM_CONSTRAINTS: usize = 512;
const MIN_LOG2_NONZERO: usize = 1;
const MAX_LOG2_NONZERO: usize = 30;
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 20;
const ZK: bool = false;

#[cfg(feature = "parallel")]
fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let configs: Vec<usize> = (MIN_LOG2_NONZERO..=MAX_LOG2_NONZERO)
        .map(|i| 1 << i)
        .collect();
    for &num_thread in &[4] {
        let pool = ThreadPoolBuilder::new()
            .num_threads(num_thread)
            .build()
            .expect("Failed to build thread pool");
        pool.install(|| {
            for &nonzero_per_matrix in configs.iter() {
                let filename = format!("random-garuda-gr1cs{}-{}t.csv", zk_string, num_thread);
                let Some(result) = bench::<Bls12_381>(
                    FIXED_NUM_CONSTRAINTS,
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
    let configs: Vec<usize> = (MIN_LOG2_NONZERO..=MAX_LOG2_NONZERO)
        .map(|i| 1 << i)
        .collect();
    for &nonzero_per_matrix in configs.iter() {
        let filename = format!("random-garuda-gr1cs{}-{}t.csv", zk_string, 1);
        let Some(result) = bench::<Bls12_381>(
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
