use crate::data_structures::Index;
use ark_ff::Field;
use ark_relations::gr1cs::{Matrix, R1CS_PREDICATE_LABEL};

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
    let mut stacked_matrices: Vec<Matrix<F>> =
        vec![vec![Vec::new(); 2_usize.pow(index.log_num_constraints as u32)]; index.max_arity];
    let mut num_of_previous_rows = 0;
    let label = R1CS_PREDICATE_LABEL;
    let matrices = index.predicate_matrices.get(label).unwrap();
    for (t, matrix_i_t) in matrices.iter().enumerate() {
        for (row_num, row) in matrix_i_t.iter().enumerate() {
            for (value, col) in row {
                stacked_matrices[t][row_num + num_of_previous_rows].push((*value, *col));
            }
        }
    }
    num_of_previous_rows += index.predicate_num_constraints[label];

    for (label, matrices) in index.predicate_matrices.iter() {
        if label != R1CS_PREDICATE_LABEL {
            for (t, matrix_i_t) in matrices.iter().enumerate() {
                for (row_num, row) in matrix_i_t.iter().enumerate() {
                    for (value, col) in row {
                        stacked_matrices[t][row_num + num_of_previous_rows].push((*value, *col));
                    }
                }
            }
            num_of_previous_rows += index.predicate_num_constraints[label];
        }
    }

    stacked_matrices
}
