use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_poly::DenseMultilinearExtension;
use ark_poly_commit::{
    multilinear_pc::data_structures::{Commitment, CommitterKey, UniversalParams},
    Evaluations,
};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
use ark_std::rand::RngCore;

pub use ark_relations::gr1cs::constraint_system::ConstraintSynthesizer;
use ark_std::{
    collections::BTreeMap,
    format,
    marker::PhantomData,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use ark_poly_commit::multilinear_pc::MultilinearPC;
use ark_relations::r1cs::Field; // Add missing import // Add missing import
pub mod data_structures;
pub mod generator;
pub mod prover;
pub mod verifier;

pub struct Garuda<E: Pairing>(#[doc(hidden)] PhantomData<E>);

#[macro_export]
macro_rules! write_bench {
    ($fmt:expr, $($arg:tt)*) => {{
        use std::io::Write;
        let mut file = std::fs::File::options().append(true).create(false).open("../../garuda_bench.txt").unwrap();
        write!(file, $fmt, $($arg)*).unwrap();
    }};
}

#[macro_export]
macro_rules! file_dbg {
    ($val:expr) => {{
        use std::io::Write;
        let mut file = std::fs::File::options()
            .append(true)
            .create(true)
            .open("debug_output.txt")
            .unwrap();
        writeln!(file, "[{}:{}]: {:?}", file!(), line!(), &$val).unwrap();
        $val
    }};
}

#[cfg(test)]
mod temp_tests {
    use crate::{
        data_structures::{Proof, ProverKey, VerifierKey},
        Garuda,
    };
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use ark_relations::gr1cs::{
        sample::*, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal,
    };
    use ark_std::test_rng;

    #[test]
    fn temp() {
        let mut rng = ark_std::test_rng();
        let circuit = DummyCircuit_1;
        let (pk, vk): (ProverKey<Bls12_381>, VerifierKey<Bls12_381>) =
            Garuda::<Bls12_381>::setup(&mut rng, circuit.clone());
        let proof: Proof<Bls12_381> = Garuda::<Bls12_381>::prove(&mut rng, circuit.clone(), pk);

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.clone().generate_constraints(cs.clone());
        debug_assert!(cs.is_satisfied().unwrap());
        let verifier = cs.borrow().unwrap();
        let input_assignment = &verifier.instance_assignment[1..];
        assert!(Garuda::<Bls12_381>::verify(
            &mut rng,
            proof,
            vk,
            input_assignment
        ));
    }
}
