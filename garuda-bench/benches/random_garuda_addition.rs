use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
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
use garuda::Garuda;

use shared_utils::BenchResult;
use std::any::type_name;
use std::ops::Neg;
use std::panic::{self, AssertUnwindSafe};
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
        // Keep a small, fixed witness pool (0, x, y) and add per-constraint
        // witnesses for the product to avoid huge allocations when sweeping
        // large nonzero counts.
        let mut witness_values = Vec::with_capacity(3 + num_constraints * 3);
        witness_values.push(F::zero()); // index 0 is always zero
        witness_values.push(rand_nonzero(rng)); // a seed witness
        witness_values.push(rand_nonzero(rng)); // another seed witness
        let a_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let b_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let c_counts = distribute_counts(nonzero_per_matrix, num_constraints);
        let mut total_nonzero_entries: usize = 0;

        let mut constraints = Vec::with_capacity(num_constraints);

        for i in 0..num_constraints {
            let a_target = a_counts[i];
            let b_target = b_counts[i];
            let c_target = c_counts[i];

            // If the requested counts are all zero, emit an empty (0 = 0) constraint.
            if a_target == 0 && b_target == 0 && c_target == 0 {
                constraints.push(ConstraintSpec {
                    a_terms: Vec::new(),
                    b_terms: Vec::new(),
                    c_terms: Vec::new(),
                });
                continue;
            }

            // Ensure each matrix has at least one nonzero if the constraint is active.
            let a_count = a_target.max(1);
            let b_count = b_target.max(1);
            let c_count = c_target.max(1);

            // Create fresh witnesses for this constraint.
            let x = rand_nonzero(rng);
            let y = rand_nonzero(rng);
            let z = x * y;
            let x_idx = witness_values.len();
            witness_values.push(x);
            let y_idx = witness_values.len();
            witness_values.push(y);
            let z_idx = witness_values.len();
            witness_values.push(z);

            // Fill A terms (first term uses x, rest are dummy multipliers on witness 0).
            let mut a_terms = Vec::with_capacity(a_count);
            a_terms.push((F::one(), Target::Var(x_idx)));
            for _ in 1..a_count {
                a_terms.push((rand_nonzero(rng), Target::Var(0)));
            }

            // Fill B terms (first term uses y, rest dummy).
            let mut b_terms = Vec::with_capacity(b_count);
            b_terms.push((F::one(), Target::Var(y_idx)));
            for _ in 1..b_count {
                b_terms.push((rand_nonzero(rng), Target::Var(0)));
            }

            // Fill C terms (first term uses z, rest dummy).
            let mut c_terms = Vec::with_capacity(c_count);
            c_terms.push((F::one(), Target::Var(z_idx)));
            for _ in 1..c_count {
                c_terms.push((rand_nonzero(rng), Target::Var(0)));
            }

            total_nonzero_entries += a_count + b_count + c_count;

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
    let cs_check: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    circuit
        .clone()
        .generate_constraints(cs_check.clone())
        .unwrap();
    cs_check.finalize();
    assert!(cs_check.is_satisfied().unwrap(), "circuit not satisfied");
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

    let prover_corrected = prover_time
        .checked_sub(prover_prep_time)
        .unwrap_or_else(|| Duration::new(0, 0));

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

    let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    let _ = circuit.clone().generate_constraints(cs.clone());
    cs.finalize();

    let keygen_corrected = keygen_time
        .checked_sub(keygen_prep_time)
        .unwrap_or_else(|| Duration::new(0, 0));

    Some(BenchResult {
        curve: type_name::<E>().to_string(),
        num_invocations: num_constraints,
        input_size: FIXED_INPUT_SIZE,
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
    })
}

const FIXED_NUM_CONSTRAINTS: usize = 2usize.pow(18);
const FIXED_INPUT_SIZE: usize = 1;
const NONZERO_MULTIPLIERS: [usize; 5] = [2, 4, 8, 16, 32];
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 1;
const ZK: bool = false;

fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let configs: Vec<usize> = NONZERO_MULTIPLIERS
        .iter()
        .map(|mult| mult * FIXED_NUM_CONSTRAINTS)
        .collect();
    for &nonzero_per_matrix in configs.iter() {
        let filename = format!("random-garuda-addition{}-{}t.csv", zk_string, 1);
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
