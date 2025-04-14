use ark_ec::pairing::Pairing;
use ark_std::rand::RngCore;

pub use ark_relations::gr1cs::ConstraintSystemRef;
use ark_std::marker::PhantomData;

mod arithmetic;
pub mod data_structures;
mod epc;
mod generator;
mod piop;
mod prover;
mod tests;
mod utils;
mod verifier;

/// The SNARK of [[Garuda]](https://eprint.iacr.org/2024/1245.pdf).
pub struct Garuda<E: Pairing, R: RngCore> {
    _p: PhantomData<E>,
    _r: PhantomData<R>,
}

impl<E: Pairing, R: RngCore> Garuda<E, R> {
    pub const SNARK_NAME: &'static str = "Garuda";
}
