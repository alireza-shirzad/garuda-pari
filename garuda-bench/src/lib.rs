pub const INPUT_BENCHMARK: &str = "input";
pub const RESCUE_APPLICATION_NAME: &str = "rescue";

pub mod bellpepper_adapter;

use std::{
    fs::{create_dir_all, OpenOptions},
    io::Write,
    path::Path,
};

use ark_crypto_primitives::sponge::rescue::constraints::RESCUE_PREDICATE;
use ark_crypto_primitives::{
    crh::{
        rescue::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    },
    sponge::rescue::RescueConfig,
};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisError, SynthesisMode};
use garuda::ConstraintSystemRef;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
pub const RESCUE_ROUNDS: usize = 12;
pub const WIDTH: usize = 9;

/// This is our demo circuit for proving knowledge of the
/// preimage of a Rescue hash invocation.
#[derive(Clone)]
pub struct RescueDemo<F: PrimeField> {
    pub input: Option<Vec<F>>,
    pub image: Option<F>,
    pub num_instances: usize,
    pub config: RescueConfig<F>,
    pub num_invocations: usize,
    pub should_use_custom_predicate: bool,
}

pub fn create_test_rescue_parameter<F: PrimeField + ark_ff::PrimeField>(
    rng: &mut impl Rng,
) -> RescueConfig<F> {
    let mut mds = vec![vec![]; 4];
    for mds_row in mds.iter_mut() {
        for _ in 0..4 {
            mds_row.push(F::rand(rng));
        }
    }

    let mut ark = vec![vec![]; 25];
    for row in ark.iter_mut() {
        for _ in 0..4 {
            row.push(F::rand(rng));
        }
    }
    // Compute alpha^{-1} mod (p - 1) for the active field so parameters stay valid across curves.
    let alpha_inv = compute_alpha_inv::<F>(5);
    RescueConfig::<F>::new(RESCUE_ROUNDS, 5, alpha_inv, mds, ark, 3, 1)
}

/// Compute the modular inverse of `alpha` modulo `p - 1`, where `p` is the field modulus.
fn compute_alpha_inv<F: PrimeField>(alpha: u64) -> BigUint {
    // modulus minus one for the field as a BigUint
    let modulus_minus_one = BigUint::from_bytes_le(&F::MODULUS.to_bytes_le()) - BigUint::from(1u32);
    let alpha = BigUint::from(alpha);

    // Extended Euclidean algorithm to find the inverse of `alpha` mod (p - 1)
    let mut t = BigInt::zero(); // Bezout coefficient for modulus_minus_one
    let mut new_t = BigInt::one(); // Bezout coefficient for alpha
    let mut r = BigInt::from(modulus_minus_one.clone()); // remainder for modulus_minus_one
    let mut new_r = BigInt::from(alpha); // remainder for alpha

    while new_r != BigInt::zero() {
        let quotient = &r / &new_r;
        (t, new_t) = (new_t.clone(), &t - &quotient * &new_t);
        (r, new_r) = (new_r.clone(), &r - &quotient * &new_r);
    }

    // If gcd(alpha, p-1) != 1 there is no inverse; this should not happen for valid parameters.
    assert_eq!(r, BigInt::one(), "alpha and p-1 are not coprime");

    if t < BigInt::zero() {
        t += BigInt::from(modulus_minus_one);
    }

    t.to_biguint().expect("inverse should be positive")
}

impl<F: PrimeField + ark_ff::PrimeField + ark_crypto_primitives::sponge::Absorb>
    ConstraintSynthesizer<F> for RescueDemo<F>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        if self.should_use_custom_predicate {
            use ark_relations::gr1cs::predicate::PredicateConstraintSystem;
            let pow_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
                2,
                vec![(F::from(1i8), vec![(0, 5)]), (F::from(-1i8), vec![(1, 1)])],
            );
            cs.register_predicate(RESCUE_PREDICATE, pow_pred).unwrap();
        }
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
                Some(CRHGadget::<F>::evaluate(&params_g, &vec![crh_a_g.unwrap(); WIDTH]).unwrap());
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

/// This is our demo circuit for proving knowledge of the
/// preimage of a Rescue hash invocation.
#[derive(Clone)]
pub struct RandomCircuit<F: PrimeField> {
    pub num_constraints: usize,
    pub num_non_zero_per_constraint: usize,
    pub should_use_custom_predicate: bool,
    pub a: F,
    pub b: F,
    pub rng_seed: [u8; 32],
}

impl<F: PrimeField> RandomCircuit<F> {
    pub fn new(
        num_constraints: usize,
        num_non_zero_per_constraint: usize,
        should_use_custom_predicate: bool,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let rng_seed: [u8; 32] = rng.gen();
        Self {
            num_constraints,
            num_non_zero_per_constraint,
            should_use_custom_predicate,
            a: F::rand(&mut rng),
            b: F::rand(&mut rng),
            rng_seed,
        }
    }
}


impl<F: PrimeField> ConstraintSynthesizer<F> for RandomCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let rng = &mut StdRng::from_seed(self.rng_seed);
        if self.should_use_custom_predicate {
            use ark_relations::gr1cs::predicate::PredicateConstraintSystem;
            let pow_pred = PredicateConstraintSystem::new_polynomial_predicate_cs(
                2,
                vec![(F::from(1i8), vec![(0, 5)]), (F::from(-1i8), vec![(1, 1)])],
            );
            cs.register_predicate(RESCUE_PREDICATE, pow_pred).unwrap();
        }
        let a = FpVar::new_witness(cs.clone(), || Ok(self.a)).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(self.b)).unwrap();
        let mut vars = vec![a.clone(), b.clone()];
        
        let num_r1cs_constraints = if self.should_use_custom_predicate {
            self.num_constraints / 2
        } else {
            self.num_constraints
        };
        let num_custom_pred_constraints = self.num_constraints - num_r1cs_constraints;

        for _ in 0..num_r1cs_constraints {
            let l = (0..self.num_non_zero_per_constraint / 2)
                .map(|_| {
                    let var = vars.choose(rng).unwrap();
                    let coeff = FpVar::Constant(F::rand(rng));
                    var * coeff
                })
                .sum::<FpVar<F>>();
            let r = (0..self.num_non_zero_per_constraint / 2)
                .map(|_| {
                    let var = vars.choose(rng).unwrap();
                    let coeff = FpVar::Constant(F::rand(rng));
                    var * coeff
                })
                .sum::<FpVar<F>>();
            let c = l * r;
            vars.push(c);
        }
        for _ in 0..num_custom_pred_constraints {
            let lhs = (0..self.num_non_zero_per_constraint)
                .map(|_| {
                    let var = vars.choose(rng).unwrap();
                    let coeff = FpVar::Constant(F::rand(rng));
                    var * coeff
                })
                .sum::<FpVar<F>>();

            let rhs = FpVar::new_witness(cs.clone(), || lhs.value().map(|v| v.pow(&[5]))).unwrap();
            let FpVar::Var(l) = lhs else {
                return Err(SynthesisError::Unsatisfiable);
            };
            let FpVar::Var(r) = rhs else {
                return Err(SynthesisError::Unsatisfiable);
            };
            cs.enforce_constraint_arity_2(RESCUE_PREDICATE, || ark_relations::lc![l.variable], || ark_relations::lc![r.variable])?;
        }

        Ok(())
    }
}

pub fn arkwork_r1cs_adapter<F: PrimeField>(
    should_use_custom_predicate: bool,
    cs: ConstraintSystemRef<F>,
    mut rng: StdRng,
) -> (
    usize,
    usize,
    usize,
    usize,
    libspartan::Instance<F>,
    libspartan::VarsAssignment<F>,
    libspartan::InputsAssignment<F>,
) {
    use libspartan::*;
    assert!(cs.is_satisfied().unwrap());
    if should_use_custom_predicate {
        assert_eq!(cs.num_predicates(), 2);
    } else {
        assert_eq!(cs.num_predicates(), 1);
    }
    let num_cons = cs.num_constraints();
    let num_inputs = cs.num_instance_variables() - 1;
    let num_vars = cs.num_witness_variables();

    let instance_assignment = cs.instance_assignment().unwrap();
    let witness_assignment = cs.witness_assignment().unwrap();
    let ark_matrices = cs.to_matrices().unwrap();

    let assignment_vars = VarsAssignment::new(&witness_assignment).unwrap();
    let assignment_inputs = InputsAssignment::new(&instance_assignment[1..]).unwrap();

    let (inst, total_num_non_zero) = if should_use_custom_predicate {
        let mut non_zero_values = Vec::new();
        for matrices in ark_matrices.values() {
            for matrix in matrices {
                for row in matrix {
                    non_zero_values.extend(row.iter().map(|(coeff, _)| *coeff));
                }
            }
        }
        let num_non_zero_a = non_zero_values.len() / 3;
        let num_non_zero_b = non_zero_values.len() / 3;

        let a = non_zero_values[..num_non_zero_a]
            .iter()
            .map(|value| {
                let row = rng.gen_range(0..num_cons);
                let col = rng.gen_range(0..num_vars + num_inputs + 1);
                (row, col, *value)
            })
            .collect::<Vec<_>>();
        let b = non_zero_values[num_non_zero_a..][..num_non_zero_b]
            .iter()
            .map(|value| {
                let row = rng.gen_range(0..num_cons);
                let col = rng.gen_range(0..num_vars + num_inputs + 1);
                (row, col, *value)
            })
            .collect::<Vec<_>>();
        let c = non_zero_values[num_non_zero_a + num_non_zero_b..]
            .iter()
            .map(|value| {
                let row = rng.gen_range(0..num_cons);
                let col = rng.gen_range(0..num_vars + num_inputs + 1);
                (row, col, *value)
            })
            .collect::<Vec<_>>();
        (
            Instance::new(num_cons, num_vars, num_inputs, &a, &b, &c).unwrap(),
            non_zero_values.len(),
        )
    } else {
        let ark_a = &ark_matrices[R1CS_PREDICATE_LABEL][0];
        let ark_b = &ark_matrices[R1CS_PREDICATE_LABEL][1];
        let ark_c = &ark_matrices[R1CS_PREDICATE_LABEL][2];
        let mut a = Vec::with_capacity(ark_a.len());
        let mut b = Vec::with_capacity(ark_b.len());
        let mut c = Vec::with_capacity(ark_c.len());
        for (row, constraint) in ark_a.iter().enumerate() {
            for (coeff, col) in constraint {
                a.push((row, *col, *coeff));
            }
        }

        for (row, constraint) in ark_b.iter().enumerate() {
            for (coeff, col) in constraint {
                b.push((row, *col, *coeff));
            }
        }

        for (row, constraint) in ark_c.iter().enumerate() {
            for (coeff, col) in constraint {
                c.push((row, *col, *coeff));
            }
        }
        (
            Instance::new(num_cons, num_vars, num_inputs, &a, &b, &c).unwrap(),
            a.len() + b.len() + c.len(),
        )
    };

    (
        num_cons,
        num_vars,
        num_inputs,
        total_num_non_zero,
        inst,
        assignment_vars,
        assignment_inputs,
    )
}

pub fn append_csv_row(header: &str, path: &Path, row: &str) {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).unwrap();
    }
    let file_exists = path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    if !file_exists {
        writeln!(file, "{header}").unwrap();
    }
    writeln!(file, "{row}").unwrap();
}

pub fn prover_prep<E: Pairing, C: ConstraintSynthesizer<E::ScalarField>>(circuit: C) {
    let cs = ConstraintSystem::new_ref();

    // Set the optimization goal
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: false,
    });

    // Synthesize the circuit.
    circuit.generate_constraints(cs.clone()).unwrap();

    cs.finalize();
}
