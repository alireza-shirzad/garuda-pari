use crate::data_structures::Index;
use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_relations::gr1cs::{Matrix, R1CS_PREDICATE_LABEL};
use ark_std::{cfg_iter, cfg_iter_mut, end_timer, start_timer};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(not(feature = "parallel"))]
use ark_std::iter::repeat_n;
#[cfg(feature = "parallel")]
use rayon::iter::repeatn as repeat_n;

/// Takes as input a struct, and converts them to a series of bytes. All traits
/// that implement `CanonicalSerialize` can be automatically converted to bytes
/// in this manner.
#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = ark_std::vec![];
        ark_serialize::CanonicalSerialize::serialize_uncompressed($x, &mut buf).map(|_| buf)
    }};
}

pub(crate) fn stack_matrices<F: Field>(index: &mut Index<F>) -> Vec<Matrix<F>> {
    let stacking_time = start_timer!(|| "Stacking matrices");

    let r1cs = R1CS_PREDICATE_LABEL;
    if index.predicate_matrices.len() == 1 {
        let (_, value) = index.predicate_matrices.pop_first().unwrap();
        end_timer!(stacking_time);
        return value;
    }
    let mut stacked_matrices = vec![vec![]; index.max_arity];
    // Append the R1CS predicate matrices first
    append_matrices(
        &mut stacked_matrices,
        index.predicate_matrices.remove(r1cs).unwrap(),
    );

    // Append the other predicate matrices
    let pred_matrices = std::mem::take(&mut index.predicate_matrices);
    for pred_matrices in pred_matrices
        .into_iter()
        .filter_map(|(label, m)| (label != r1cs).then_some(m))
    {
        append_matrices(&mut stacked_matrices, pred_matrices);
    }

    // Pad out each matrix to next power of 2
    end_timer!(stacking_time);
    stacked_matrices
}

pub fn append_matrices<F: Field>(
    stacked_matrices: &mut Vec<Matrix<F>>,
    pred_matrices: Vec<Matrix<F>>,
) {
    let num_pred_matrices = pred_matrices.len();
    let num_pred_constraints = pred_matrices[0].len();
    let (current, rest) = stacked_matrices.split_at_mut(num_pred_matrices);
    cfg_iter_mut!(current)
        .zip(pred_matrices)
        .for_each(|(stacked_i, pred_i)| stacked_i.par_extend(pred_i));
    for stacked_i in rest.iter_mut() {
        stacked_i.par_extend(repeat_n(vec![], num_pred_constraints));
    }
}

/// Multiply a matrix by a vector.
pub fn mat_vec_mul<F: Field>(
    matrix: &Matrix<F>,
    vector: &[F],
    num_instances: usize,
) -> (Vec<F>, Vec<F>) {
    let next_power_of_two = matrix.len().next_power_of_two();
    let (mut mz, mut mw): (Vec<_>, Vec<_>) = cfg_iter!(matrix)
        .map(|row| {
            let mut mx_sum = F::zero();
            let mut mw_sum = F::zero();
            for (value, col) in row {
                let value = if value.is_one() {
                    vector[*col]
                } else {
                    vector[*col] * value
                };
                if *col < num_instances {
                    mx_sum += value
                } else {
                    mw_sum += value
                }
            }
            (mx_sum + mw_sum, mw_sum)
        })
        .unzip();
    mz.resize(next_power_of_two, F::zero());
    mw.resize(next_power_of_two, F::zero());
    (mz, mw)
}

pub fn evaluate_batch<F: Field>(mles: &[DenseMultilinearExtension<F>], point: &[F]) -> Vec<F> {
    let eq_evals = EqEvalIter::new(point.to_vec()).evals();

    mles.iter()
        .map(|mle| {
            cfg_iter!(mle.evaluations)
                .zip(&eq_evals)
                .filter_map(|(c, e)| (!c.is_zero()).then(|| *c * e))
                .sum()
        })
        .collect()
}

#[cfg(feature = "parallel")]
use rayon::iter::MinLen;
use rayon::vec;

/// An iterator that generates the evaluations of the polynomial
/// eq(r, y || x) over the Boolean hypercube.
///
/// Here y = `self.fixed_vars`, and r = `self.r`.
pub struct EqEvalIter<F> {
    multiplier: F,
    cur_index: usize,
    r: Vec<F>,
    one_minus_r: Vec<F>,
    zero_values: Vec<F>,
    one_values: Vec<F>,
    boolean_mask: usize,
    r_only_boolean: usize,
}

impl<F: Field> EqEvalIter<F> {
    pub fn new(r: Vec<F>) -> Self {
        Self::new_with_multiplier(r, F::one())
    }

    pub fn new_with_multiplier(r: Vec<F>, multiplier: F) -> Self {
        let mut r_inv = r.clone();
        ark_ff::batch_inversion(&mut r_inv);
        assert_eq!(r.len(), r_inv.len());

        let one_minus_r = r.iter().map(|r| F::one() - r).collect::<Vec<_>>();
        let mut one_minus_r_inv = one_minus_r.clone();
        ark_ff::batch_inversion(&mut one_minus_r_inv);
        assert_eq!(r.len(), one_minus_r.len());
        let boolean_mask = r
            .iter()
            .enumerate()
            .map(|(i, r_j)| ((r_j.is_one() || r_j.is_zero()) as usize) << i)
            .sum::<usize>();
        let r_only_boolean = r
            .iter()
            .enumerate()
            .map(|(i, r_j)| (r_j.is_one() as usize) << i)
            .sum::<usize>();

        let zero_values = one_minus_r_inv
            .into_iter()
            .zip(&r)
            .map(|(r, one_minus_r_inv)| r * one_minus_r_inv)
            .collect::<Vec<_>>();

        let one_values = r_inv
            .into_iter()
            .zip(&one_minus_r)
            .map(|(one_minus_r, r_inv)| one_minus_r * r_inv)
            .collect::<Vec<_>>();

        EqEvalIter {
            cur_index: 0,
            multiplier,
            r,
            one_minus_r,
            zero_values,
            one_values,
            r_only_boolean,
            boolean_mask,
        }
    }

    pub fn new_with_fixed_vars(r: Vec<F>, fixed_vars: Vec<F>) -> Self {
        assert!(fixed_vars.len() <= r.len());
        let (first_r, rest_r) = r.split_at(fixed_vars.len());
        let multiplier = eq_eval(first_r, &fixed_vars).unwrap();
        Self::new_with_multiplier(rest_r.to_vec(), multiplier)
    }

    fn next_batch(&mut self) -> Option<MinLen<rayon::vec::IntoIter<F>>> {
        let nv = self.r.len();
        let total_num_evals = 1 << nv;
        if self.cur_index >= total_num_evals {
            None
        } else {
            let batch_size = total_num_evals.min(BUFFER_SIZE);
            let batch_start = self.cur_index;
            let batch_end = self.cur_index + batch_size;

            let result = (batch_start..batch_end)
                .into_par_iter()
                .step_by(CHUNK_SIZE)
                .flat_map(|c_start| {
                    let c_end = c_start + CHUNK_SIZE.min(batch_size);
                    let starting_value =
                        compute_starting_value(&self, c_start, c_end) * self.multiplier;
                    p(&self, starting_value, c_start, c_end)
                })
                .collect::<Vec<_>>();
            self.cur_index += batch_size;
            Some(result.into_par_iter().with_min_len(1 << 7))
        }
    }

    pub fn evals(&mut self) -> Vec<F> {
        let mut vec = Vec::new();
        while let Some(batch) = self.next_batch() {
            vec.par_extend(batch);
        }
        vec
    }
}

const BUFFER_SIZE: usize = 1 << 20;
const CHUNK_SIZE: usize = if BUFFER_SIZE < (1 << 14) {
    BUFFER_SIZE
} else {
    1 << 14
};

fn p<F: Field>(iter: &EqEvalIter<F>, starting_value: F, start: usize, end: usize) -> Vec<F> {
    let nv = iter.r.len();
    let mut next_m = starting_value;
    (start..end)
        .map(|i| {
            let next_i = i + 1;
            let this_m = next_m;
            let this_is_zero = ((i & iter.boolean_mask) ^ iter.r_only_boolean) != 0;

            for j in 0..nv {
                let r_j_is_boolean = (iter.boolean_mask & (1 << j)) != 0;
                if r_j_is_boolean {
                    continue;
                }
                let cur_bit = i & (1 << j);
                let next_bit = next_i & (1 << j);
                if cur_bit != next_bit {
                    if cur_bit == 0 {
                        next_m *= iter.zero_values[j];
                        break;
                    } else {
                        next_m *= iter.one_values[j];
                    }
                }
            }

            if this_is_zero {
                F::zero()
            } else {
                this_m
            }
        })
        .collect()
}

/// Computes the starting value for chunk `chunk_idx` by using the product
/// of `r` and `one_minus_r` vectors and the binary decomposition of `chunk_idx * chunk_size - 1`
#[inline]
fn compute_starting_value<F: Field>(iter: &EqEvalIter<F>, c_start: usize, c_end: usize) -> F {
    // Compute the location where `c` differs from `r` in the boolean locations;
    // Flipping those bits will give us the first index where the value is non-zero.
    let new_c = c_start | iter.r_only_boolean;
    if !((c_start..c_end).contains(&new_c)) {
        F::zero()
    } else {
        let mut m = F::one();
        for j in 0..iter.r.len() {
            if (new_c >> j) & 1 == 0 {
                m *= iter.one_minus_r[j];
            } else {
                m *= iter.r[j];
            }
        }
        m
    }
}

pub fn eq_eval<F: Field>(x: &[F], y: &[F]) -> Option<F> {
    if x.len() != y.len() {
        return None;
    }
    // let start = start_timer!(|| "eq_eval");
    let mut res = F::one();
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::one();
    }
    // end_timer!(start);
    Some(res)
}
