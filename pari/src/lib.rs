#![feature(associated_type_defaults)]
#![allow(unreachable_patterns)]

use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_relations::{
    gr1cs::{
        predicate::PredicateConstraintSystem, ConstraintSynthesizer, ConstraintSystem,
        LinearCombination, SynthesisError, Variable,
    },
    lc, ns,
};

use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};

pub use ark_relations::gr1cs::ConstraintSystemRef;
use ark_std::marker::PhantomData;

pub mod data_structures;
mod generator;
mod prover;
mod verifier;
mod utils;
#[cfg(test)]
mod test;

/// The SNARK of [[Pari]](https://eprint.iacr.org/2024/1245.pdf).
pub struct Pari<E: Pairing, R: RngCore> {
    _p: PhantomData<E>,
    _r: PhantomData<R>,
}

impl<E: Pairing, R: RngCore> Pari<E, R> {
    pub const SNARK_NAME: &'static str = "Pari";
}
