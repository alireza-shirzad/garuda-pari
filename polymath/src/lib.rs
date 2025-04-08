use ark_ec::pairing::Pairing;

pub use ark_relations::gr1cs::ConstraintSystemRef;
use ark_std::marker::PhantomData;

pub mod data_structures;
mod generator;
mod prover;
// #[cfg(feature = "sol")]
// mod solidity;
mod utils;
mod verifier;
mod shared;

#[cfg(test)]
mod test;

/// The SNARK of [[Polymath]](https://eprint.iacr.org/2024/916.pdf).
pub struct Polymath<E: Pairing> {
    _p: PhantomData<E>,
}

impl<E: Pairing> Polymath<E> {
    pub const SNARK_NAME: &'static [u8; 8] = b"Polymath";
}

const BND_A: usize = 1;
const ALPHA: isize = -1;
const GAMMA: isize = -5;
const MINUS_ALPHA: usize = 1;
const MINUS_GAMMA: usize = 5;
