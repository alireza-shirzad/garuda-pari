// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

use ark_ff::Field;
use ark_std::cfg_chunks;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub use ark_poly::DenseMultilinearExtension;

pub fn fix_variables<F: Field>(
    poly: &DenseMultilinearExtension<F>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );
    let nv = poly.num_vars;
    let mut poly = poly.evaluations.to_vec();
    let dim = partial_point.len();
    // evaluate single variable of partial point from left to right
    for point in partial_point.iter().take(dim) {
        poly = fix_one_variable_helper(&poly, point);
    }

    DenseMultilinearExtension::<F>::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
}

fn fix_one_variable_helper<F: Field>(data: &[F], point: &F) -> Vec<F> {
    cfg_chunks!(data, 2)
        .map(|d| {
            let [d_even, d_odd] = d else { unreachable!() };
            *d_even + (*d_odd - d_even) * point
        })
        .collect()
}
