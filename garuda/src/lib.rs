#![feature(associated_type_defaults)]
#![allow(unreachable_patterns)]

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSynthesizer, LinearCombination, SynthesisError, Variable};
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
        let mut file = std::fs::File::options().append(true).create(false).open("./garuda_bench.txt").unwrap();
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
