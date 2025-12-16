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
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use shared_utils::BenchResult;
use std::any::type_name;
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

fn bench<E: Pairing>(
    num_constraints: usize,
    nonzero_per_matrix: usize,
    num_keygen_iterations: u32,
    num_prover_iterations: u32,
    num_verifier_iterations: u32,
    num_thread: usize,
    zk: bool,
) -> BenchResult
where
    E::ScalarField: PrimeField + UniformRand,
    E::G1Affine: Neg<Output = E::G1Affine>,
    <E::G1Affine as AffineRepr>::BaseField: PrimeField,
{
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let circuit =
        RandomCircuit::<E::ScalarField>::new(num_constraints, nonzero_per_matrix, &mut rng);
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
    for _ in 0..num_verifier_iterations {
        assert!(Garuda::verify(
            proof.as_ref().unwrap(),
            vk.as_ref().unwrap(),
            &[]
        ));
    }
    verifier_time += start.elapsed();

    let cs: ConstraintSystemRef<E::ScalarField> = ConstraintSystem::new_ref();
    let _ = circuit.clone().generate_constraints(cs.clone());
    cs.finalize();

    BenchResult {
        curve: type_name::<E>().to_string(),
        // Reuse the `input_size` and `num_invocations` fields to log the requested knobs.
        input_size: nonzero_per_matrix,
        num_invocations: num_constraints,
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
        prover_corrected_time: ((prover_time - prover_prep_time) / num_prover_iterations),
        verifier_time: (verifier_time / num_verifier_iterations),
        keygen_time: (keygen_time / num_keygen_iterations),
        keygen_prep_time: (keygen_prep_time / num_keygen_iterations),
        keygen_corrected_time: ((keygen_time - keygen_prep_time) / num_keygen_iterations),
    }
}

const MIN_LOG2_CONSTRAINTS: usize = 1;
const MAX_LOG2_CONSTRAINTS: usize = 30;
const NUM_KEYGEN_ITERATIONS: u32 = 1;
const NUM_PROVER_ITERATIONS: u32 = 1;
const NUM_VERIFIER_ITERATIONS: u32 = 20;
const ZK: bool = false;

fn main() {
    let zk_string = if ZK { "-zk" } else { "" };
    let configs: Vec<(usize, usize)> = (MIN_LOG2_CONSTRAINTS..=MAX_LOG2_CONSTRAINTS)
        .map(|i| {
            let num_constraints = 1 << i;
            let nonzero_per_matrix = 1 << i; // double nonzeros as constraints double
            (num_constraints, nonzero_per_matrix)
        })
        .collect();
    for &(num_constraints, nonzero_per_matrix) in configs.iter() {
        let filename = format!("random-garuda{}-{}t.csv", zk_string, 1);
        let _ = bench::<Bls12_381>(
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
