use ark_ec::pairing::Pairing;
use ark_std::marker::PhantomData;

pub use ark_relations::gr1cs::ConstraintSystemRef;

mod arithmetic;
pub mod data_structures;
mod epc;
mod generator;
mod piop;
mod prover;
mod tests;
mod utils;
mod verifier;
mod zk;

/// The SNARK of [[Garuda]](https://eprint.iacr.org/2024/1245.pdf).
pub struct Garuda<E: Pairing> {
    _p: PhantomData<E>,
}

impl<E: Pairing> Garuda<E> {
    pub const SNARK_NAME: &'static str = "Garuda";
}
