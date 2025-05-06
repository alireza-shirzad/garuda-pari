// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

mod errors;
mod multilinear_polynomial;
mod univariate_polynomial;
mod util;
mod virtual_polynomial;

pub use errors::ArithErrors;
pub use multilinear_polynomial::{fix_variables, random_mle_list, DenseMultilinearExtension};
pub use util::bit_decompose;
pub use virtual_polynomial::{eq_eval, VPAuxInfo, VirtualPolynomial};
