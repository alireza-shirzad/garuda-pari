use ark_ff::{BigInteger, BigInteger256, Field as arkField, PrimeField as arkPrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::gr1cs::{
    ConstraintSystemRef, Namespace, SynthesisError as arkSynthesisError, R1CS_PREDICATE_LABEL,
};
use bellpepper_core::{
    num::AllocatedNum, Circuit, ConstraintSystem, LinearCombination,
    SynthesisError as bpSynthesisError,
};
use core::borrow::Borrow;
use ff::{Field as novaField, PrimeField as novaPrimeField};
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use std::sync::Arc;

pub trait AllocIoVar<V: ?Sized, A: arkField>: Sized + AllocVar<V, A> {
    /// Allocates a new input/output pair of type `Self` in the `ConstraintSystem`
    /// `cs`.
    fn new_input_output_pair<T: Borrow<V>>(
        cs: impl Into<Namespace<A>> + Clone,
        f_in: impl FnOnce() -> Result<T, arkSynthesisError>,
        f_out: impl FnOnce() -> Result<T, arkSynthesisError>,
    ) -> Result<(Self, Self), arkSynthesisError> {
        let alloc_in = Self::new_variable(cs.clone(), f_in, AllocationMode::Input)?;
        let alloc_out = Self::new_variable(cs, f_out, AllocationMode::Input)?;

        Ok((alloc_in, alloc_out))
    }
}

impl<A: arkField> AllocIoVar<bool, A> for Boolean<A> {}
impl<A: arkPrimeField> AllocIoVar<A, A> for FpVar<A> {}

pub fn ark_to_nova_field<
    A: arkPrimeField<BigInt = BigInteger256>,
    N: novaPrimeField<Repr = [u8; 32]>,
>(
    ark_ff: &A,
) -> N {
    // ark F -> ark BigInt
    let b = ark_ff.into_bigint();

    // BigInt -> bytes
    let bytes = u64x4_to_u8x32(&b.0);

    // bytes -> nova F
    N::from_repr(TryInto::<[u8; 32]>::try_into(bytes).unwrap()).unwrap()
}

fn u64x4_to_u8x32(input: &[u64; 4]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (chunk, &val) in output.chunks_mut(8).zip(input) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }
    output
}

pub fn nova_to_ark_field<N: novaPrimeField<Repr = [u8; 32]>, A: arkPrimeField>(nova_ff: &N) -> A {
    // nova F -> bytes
    let b = nova_ff.to_repr();

    // bytes -> ark F
    A::from_le_bytes_mod_order(&b)
}

fn bellpepper_lc<N: novaPrimeField, CS: ConstraintSystem<N>>(
    alloc_io: &Vec<AllocatedNum<N>>,
    alloc_wits: &Vec<AllocatedNum<N>>,
    lc: &Vec<(N, usize)>,
    i: usize,
) -> LinearCombination<N> {
    let mut lc_bellpepper = LinearCombination::zero();

    let num_io = alloc_io.len();

    for (val, idx) in lc {
        if *idx == 0 {
            // constant
            lc_bellpepper = lc_bellpepper + (*val, CS::one());
        } else if *idx <= num_io {
            // input
            lc_bellpepper = lc_bellpepper + (*val, alloc_io[*idx - 1].get_variable());
        } else {
            // witness
            lc_bellpepper = lc_bellpepper + (*val, alloc_wits[*idx - 1 - num_io].get_variable());
        }
    }

    lc_bellpepper
}

#[derive(Clone, Debug)]
pub struct FCircuit<N: novaPrimeField<Repr = [u8; 32]>> {
    pub lcs: Vec<(Vec<(N, usize)>, Vec<(N, usize)>, Vec<(N, usize)>)>,
    wit_assignments: Vec<N>,
    input_assignments: Vec<N>,
}

impl<N: novaPrimeField<Repr = [u8; 32]>> FCircuit<N> {
    // make circuits and witnesses for round i
    // the ark_cs should only have witness and input/output PAIRs
    // (i.e. a user should have never called new_input())
    pub fn new<A: arkPrimeField<BigInt = BigInteger256>>(
        ark_cs_ref: ConstraintSystemRef<A>,
    ) -> Self {
        ark_cs_ref.finalize();
        // assert!(ark_cs_ref.is_satisfied().unwrap());
        

        let ark_cs = ark_cs_ref.borrow().unwrap();

        // io pairs + constant
        let instance_assignment = ark_cs.instance_assignment().unwrap();
        assert_eq!(instance_assignment[0], A::one());


        let input_assignments: Vec<N> = ark_cs
            .witness_assignment()
            .unwrap()
            .par_iter()
            .map(|f| ark_to_nova_field(f))
            .collect();

        let wit_assignments: Vec<N> = ark_cs
            .witness_assignment()
            .unwrap()
            .par_iter()
            .map(|f| ark_to_nova_field(f))
            .collect();

        let ark_matrices = &ark_cs.to_matrices().unwrap()[R1CS_PREDICATE_LABEL];
        let lcs = (0..ark_matrices[0].len())
            .into_par_iter()
            .map(|i| {
                (
                    ark_matrices[0][i]
                        .par_iter()
                        .map(|(val, index)| (ark_to_nova_field(val), *index))
                        .collect(),
                    ark_matrices[1][i]
                        .par_iter()
                        .map(|(val, index)| (ark_to_nova_field(val), *index))
                        .collect(),
                    ark_matrices[2][i]
                        .par_iter()
                        .map(|(val, index)| (ark_to_nova_field(val), *index))
                        .collect(),
                )
            })
            .collect();

        FCircuit {
            lcs,
            input_assignments,
            wit_assignments,
        }
    }

}

impl<N: novaPrimeField<Repr = [u8; 32]>> Circuit<N> for FCircuit<N> {
    fn synthesize<CS: ConstraintSystem<N>>(self, cs: &mut CS) -> Result<(), bpSynthesisError> {
        // allocate all inputs
        let alloc_inputs = self
            .input_assignments
            .iter()
            .enumerate()
            .map(|(i, w)| AllocatedNum::alloc(cs.namespace(|| format!("inp {}", i)), || Ok(*w)))
            .collect::<Result<Vec<AllocatedNum<N>>, bpSynthesisError>>()?;
        // allocate all wits
        let alloc_wits = self
            .wit_assignments
            .iter()
            .enumerate()
            .map(|(i, w)| AllocatedNum::alloc(cs.namespace(|| format!("wit {}", i)), || Ok(*w)))
            .collect::<Result<Vec<AllocatedNum<N>>, bpSynthesisError>>()?;

        // add constraints

        let mut saved_lcs = Vec::new();

        self.lcs.iter().enumerate().for_each(|(i, (a, b, c))| {
            let a_lc = bellpepper_lc::<N, CS>(&alloc_inputs, &alloc_wits, a, i);
            let b_lc = bellpepper_lc::<N, CS>(&alloc_inputs, &alloc_wits, b, i);
            let c_lc = bellpepper_lc::<N, CS>(&alloc_inputs, &alloc_wits, c, i);

            saved_lcs.push((a_lc.clone(), b_lc.clone(), c_lc.clone()));

            cs.enforce(|| format!("con{}", i), |_| a_lc, |_| b_lc, |_| c_lc);
        });

        Ok(())
    }
}
