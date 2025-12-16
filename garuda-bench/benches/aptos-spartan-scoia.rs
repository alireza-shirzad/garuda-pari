use std::{fs::File, io::Read, path::Path, sync::Arc, time::Instant};

use bellpepper::gadgets::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use circom_scotia::{
    calculate_witness,
    r1cs::{CircomConfig, CircomInput, R1CS},
    synthesize,
};
use ff::PrimeField;
use serde_json::Value;
use spartan2::{
    provider::{keccak::Keccak256Transcript, pcs::hyrax_pc::HyraxPCS, traits::DlogGroup},
    spartan::SpartanSNARK,
    traits::{
        transcript::TranscriptReprTrait, Engine, Group, PrimeFieldExt, circuit::SpartanCircuit,
        snark::R1CSSNARKTrait,
    },
};
use sha3::Shake256;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

// Minimal Spartan2 engine for BN254/Bn256 using Hyrax PCS.
mod bn256_engine {
    use super::*;

    use halo2curves::{
        bn256::{Fq as BaseField, Fr as ScalarField, G1 as CurvePoint, G1Affine},
        ff::PrimeField as HaloPrimeField,
        group::{Curve, Group},
    };
    use num_integer::Integer;
    use num_traits::ToPrimitive;
    use spartan2::provider::traits::{DlogGroup, DlogGroupExt};

    impl Group for CurvePoint {
        type Base = BaseField;
        type Scalar = ScalarField;

        fn group_params() -> (Self::Base, Self::Base, BigInt, BigInt) {
            let a = BaseField::zero();
            let b = BaseField::from_u64(3).unwrap();
            let order = BigInt::from_str_radix(
                "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
                16,
            )
            .unwrap();
            let base = BigInt::from_str_radix(
                "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
                16,
            )
            .unwrap();
            (a, b, order, base)
        }
    }

    impl DlogGroup for CurvePoint {
        type AffineGroupElement = G1Affine;

        fn affine(&self) -> Self::AffineGroupElement {
            self.to_affine()
        }

        fn group(p: &Self::AffineGroupElement) -> Self {
            CurvePoint::from(*p)
        }

        fn from_label(label: &'static [u8], n: usize) -> Vec<Self::AffineGroupElement> {
            let mut shake = Shake256::default();
            shake.update(label);
            let mut reader = shake.finalize_xof();
            (0..n)
                .map(|i| {
                    let mut uniform_bytes = [0u8; 64];
                    uniform_bytes[0] = i as u8;
                    reader
                        .read_exact(&mut uniform_bytes[1..])
                        .expect("xof read");
                    let scalar = ScalarField::from_uniform_bytes(&uniform_bytes);
                    (CurvePoint::generator() * scalar).to_affine()
                })
                .collect()
        }

        fn zero() -> Self {
            CurvePoint::identity()
        }

        fn generator() -> Self {
            CurvePoint::generator()
        }

        fn to_coordinates(&self) -> (Self::Base, Self::Base, bool) {
            let affine = self.to_affine();
            let coords = affine.coordinates();
            if let Some(coords) = coords {
                (*coords.x(), *coords.y(), false)
            } else {
                (Self::Base::zero(), Self::Base::zero(), true)
            }
        }
    }

    impl DlogGroupExt for CurvePoint {
        fn vartime_multiscalar_mul(
            scalars: &[Self::Scalar],
            bases: &[Self::AffineGroupElement],
            _use_parallelism_internally: bool,
        ) -> Result<Self, spartan2::errors::SpartanError> {
            let acc = scalars
                .iter()
                .zip(bases.iter())
                .fold(CurvePoint::identity(), |acc, (s, b)| acc + b * s);
            Ok(acc)
        }

        fn vartime_multiscalar_mul_small<T: Integer + Into<u64> + Copy + Sync + ToPrimitive>(
            scalars: &[T],
            bases: &[Self::AffineGroupElement],
            _use_parallelism_internally: bool,
        ) -> Result<Self, spartan2::errors::SpartanError> {
            let acc = scalars
                .iter()
                .zip(bases.iter())
                .fold(CurvePoint::identity(), |acc, (s, b)| {
                    let val = s.to_u64().unwrap_or(0);
                    acc + b * ScalarField::from(val)
                });
            Ok(acc)
        }
    }

    impl PrimeFieldExt for ScalarField {
        fn from_uniform(bytes: &[u8]) -> Self {
            let mut arr = [0u8; 64];
            let take = bytes.len().min(64);
            arr[..take].copy_from_slice(&bytes[..take]);
            ScalarField::from_uniform_bytes(&arr)
        }
    }

    impl<G: Group> TranscriptReprTrait<G> for ScalarField {
        fn to_transcript_bytes(&self) -> Vec<u8> {
            self.to_bytes().into_iter().rev().collect()
        }
    }

    impl<G: Group> TranscriptReprTrait<G> for BaseField {
        fn to_transcript_bytes(&self) -> Vec<u8> {
            self.to_bytes().into_iter().rev().collect()
        }
    }

    impl<G: Group> TranscriptReprTrait<G> for G1Affine {
        fn to_transcript_bytes(&self) -> Vec<u8> {
            let coords = self.coordinates();
            if let Some(c) = coords {
                let x = c.x().to_bytes().into_iter();
                let y = c.y().to_bytes().into_iter();
                x.rev().chain(y.rev()).collect()
            } else {
                vec![]
            }
        }
    }

    impl<G: Group> TranscriptReprTrait<G> for CurvePoint {
        fn to_transcript_bytes(&self) -> Vec<u8> {
            self.to_affine().to_transcript_bytes()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Bn256HyraxEngine;

    impl Engine for Bn256HyraxEngine {
        type Base = BaseField;
        type Scalar = ScalarField;
        type GE = CurvePoint;
        type TE = Keccak256Transcript<Self>;
        type PCS = HyraxPCS<Self>;
    }
}

use bn256_engine::Bn256HyraxEngine as E;

type Fr = <E as Engine>::Scalar;

#[derive(Clone)]
struct CircomSpartanCircuit {
    r1cs: Arc<R1CS<Fr>>,
    witness: Arc<Vec<Fr>>,
    num_public: usize,
}

impl CircomSpartanCircuit {
    fn new(r1cs: R1CS<Fr>, witness: Vec<Fr>) -> Self {
        let num_public = r1cs.num_inputs - 1;
        Self {
            r1cs: Arc::new(r1cs),
            witness: Arc::new(witness),
            num_public,
        }
    }
}

impl SpartanCircuit<E> for CircomSpartanCircuit {
    fn public_values(&self) -> Result<Vec<Fr>, SynthesisError> {
        Ok(self.witness[1..1 + self.num_public].to_vec())
    }

    fn shared<CS: ConstraintSystem<Fr>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Fr>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Fr>],
        _: &[AllocatedNum<Fr>],
        _: Option<&[Fr]>,
    ) -> Result<(), SynthesisError> {
        synthesize(cs, (*self.r1cs).clone(), Some((*self.witness).clone()))
            .map(|_| ())
    }
}

fn main() {
    let wtns_path = "./circuits/aptos/main.wasm";
    let r1cs_path = "./circuits/aptos/main.r1cs";
    let input_path = "./circuits/aptos/input.json";

    let cfg: CircomConfig<Fr> = CircomConfig::new(wtns_path, r1cs_path).expect("circom config");
    let inputs = load_inputs(input_path);
    let witness = calculate_witness(&cfg, inputs, true).expect("calculate witness");

    let circuit = CircomSpartanCircuit::new(cfg.r1cs.clone(), witness);

    let start = Instant::now();
    let (pk, vk) = SpartanSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    println!("Keygen took: {:?}", start.elapsed());

    let start = Instant::now();
    let prep = SpartanSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep failed");
    println!("Prep-prove took: {:?}", start.elapsed());

    let start = Instant::now();
    let proof = SpartanSNARK::<E>::prove(&pk, circuit.clone(), &prep, false).expect("prove failed");
    println!("Prover took: {:?}", start.elapsed());

    let start = Instant::now();
    proof.verify(&vk).expect("verify failed");
    println!("Verifier took: {:?}", start.elapsed());
}

fn load_inputs(path: impl AsRef<Path>) -> Vec<CircomInput<Fr>> {
    let file = File::open(path).expect("open input file");
    let value: Value = serde_json::from_reader(file).expect("parse input json");
    let obj = value.as_object().expect("input must be a JSON object");

    obj.iter()
        .map(|(name, val)| {
            let values = match val {
                Value::Array(items) => items.iter().map(value_to_field::<Fr>).collect(),
                _ => vec![value_to_field::<Fr>(val)],
            };
            CircomInput::new(name.clone(), values)
        })
        .collect()
}

fn value_to_field<F: PrimeField>(v: &Value) -> F {
    match v {
        Value::String(s) => F::from_str_vartime(s)
            .or_else(|| s.parse::<u64>().ok().and_then(|n| F::from_str_vartime(&n.to_string())))
            .unwrap_or_else(|| panic!("cannot parse string field element: {s}")),
        Value::Number(n) => {
            let s = n.to_string();
            F::from_str_vartime(&s)
                .unwrap_or_else(|| panic!("cannot parse numeric field element: {s}"))
        }
        Value::Bool(b) => {
            if *b {
                F::ONE
            } else {
                F::ZERO
            }
        }
        _ => panic!("unexpected JSON value in inputs"),
    }
}
