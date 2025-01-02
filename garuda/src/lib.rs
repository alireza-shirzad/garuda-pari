#![feature(associated_type_defaults)]
#![allow(unreachable_patterns)]

use ark_ec::pairing::Pairing;
use ark_std::rand::RngCore;

pub use ark_relations::gr1cs::ConstraintSystemRef;
use ark_std::marker::PhantomData;

mod arithmetic;
mod data_structures;
mod epc;
mod generator;
mod piop;
mod prover;
mod tests;
mod transcript;
mod utils;
mod verifier;

#[macro_export]
macro_rules! write_bench {
    ($fmt:expr, $($arg:tt)*) => {{
        use std::io::Write;
        let mut file = std::fs::File::options().append(true).create(false).open("../../garuda_bench.txt").unwrap();
        write!(file, $fmt, $($arg)*).unwrap();
    }};
}

/// The SNARK of [[Garuda]](https://eprint.iacr.org/2024/1245.pdf).
pub struct Garuda<E: Pairing, R: RngCore> {
    _p: PhantomData<E>,
    _r: PhantomData<R>,
}

impl<E: Pairing, R: RngCore> Garuda<E, R> {
    pub const SNARK_NAME: &'static str = "Garuda";
}

#[cfg(test)]
mod temp_tests {
    use crate::tests::circuit1::Circuit1;
    use crate::{
        data_structures::{Proof, ProvingKey, VerifyingKey},
        Garuda,
    };
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
    use ark_std::{
        rand::{rngs::StdRng, Rng, RngCore, SeedableRng},
        test_rng,
    };
    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn temp() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let circuit = Circuit1 {
            x1: Fr::from(1u8),
            x2: Fr::from(2u8),
            x3: Fr::from(3u8),
            x4: Fr::from(0u8),
            x5: Fr::from(1255254u32),
            w1: Fr::from(4u8),
            w2: Fr::from(2u8),
            w3: Fr::from(5u8),
            w4: Fr::from(29u8),
            w5: Fr::from(28u8),
            w6: Fr::from(10u8),
            w7: Fr::from(57u8),
            w8: Fr::from(22022u32),
        };
        let (pk, vk): (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) =
            Garuda::<Bls12_381, StdRng>::keygen(circuit.clone(), &mut rng);
        let proof: Proof<Bls12_381> =
            Garuda::<Bls12_381, StdRng>::prove(circuit.clone(), pk).unwrap();

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.clone().generate_constraints(cs.clone());
        debug_assert!(cs.is_satisfied().unwrap());
        let verifier = cs.borrow().unwrap();
        let input_assignment = &verifier.instance_assignment().unwrap()[1..];
        assert!(Garuda::<Bls12_381, StdRng>::verify(
            proof,
            vk,
            input_assignment
        ));
    }
}
