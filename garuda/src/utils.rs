use crate::data_structures::Index;
use ark_ff::Field;
use ark_relations::gr1cs::{Matrix, R1CS_PREDICATE_LABEL};
use ark_std::{cfg_iter, cfg_iter_mut, end_timer, start_timer};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

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

pub(crate) fn stack_matrices<F: Field>(index: &Index<F>) -> Vec<Matrix<F>> {
    let stacking_time = start_timer!(|| "Stacking matrices");

    let mut stacked_matrices = vec![vec![]; index.max_arity];
    // Append the R1CS predicate matrices first
    let r1cs = R1CS_PREDICATE_LABEL;
    append_matrices(&mut stacked_matrices, &index.predicate_matrices[r1cs]);

    // Append the other predicate matrices
    for pred_matrices in index
        .predicate_matrices
        .iter()
        .filter_map(|(label, m)| (label != r1cs).then_some(m))
    {
        append_matrices(&mut stacked_matrices, pred_matrices);
    }

    // Pad out each matrix to next power of 2

    let next_power_of_2 = 2usize.pow(index.log_num_constraints as u32);
    for stacked_i in stacked_matrices.iter_mut() {
        stacked_i.resize(next_power_of_2, vec![]);
    }

    end_timer!(stacking_time);

    stacked_matrices
}

pub fn append_matrices<F: Field>(
    stacked_matrices: &mut Vec<Matrix<F>>,
    pred_matrices: &[Matrix<F>],
) {
    let num_pred_matrices = pred_matrices.len();
    let num_pred_constraints = pred_matrices[0].len();
    let (current, rest) = stacked_matrices.split_at_mut(num_pred_matrices);
    cfg_iter_mut!(current)
        .zip(pred_matrices)
        .for_each(|(stacked_i, pred_i)| stacked_i.extend_from_slice(pred_i));
    for stacked_i in rest.iter_mut() {
        #[cfg(not(feature = "parallel"))]
        use ark_std::iter::repeat_n;
        #[cfg(feature = "parallel")]
        use rayon::iter::repeatn as repeat_n;
        stacked_i.par_extend(repeat_n(vec![], num_pred_constraints));
    }
}

/// Multiply a matrix by a vector.
pub fn mat_vec_mul<F: Field>(matrix: &Matrix<F>, vector: &[F]) -> Vec<F> {
    cfg_iter!(matrix)
        .map(|row| {
            let mut sum: F = F::zero();
            for (value, col) in row {
                sum += vector[*col] * value;
            }
            sum
        })
        .collect()
}
