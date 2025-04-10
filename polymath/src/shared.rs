use core::num;
use std::fmt::Debug;
use std::iter::repeat_n;
use std::ops::Neg;

use crate::{Polymath, data_structures::VerifyingKey};
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial, SparsePolynomial};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_relations::gr1cs::{ConstraintSynthesizer, Matrix};
use ark_std::Zero;
use ark_std::rand::RngCore;

impl<E: Pairing> Polymath<E> {
    pub(crate) fn compute_c_at_x1(
        y1_gamma: E::ScalarField,
        y1_alpha: E::ScalarField,
        a_at_x1: E::ScalarField,
        x1: E::ScalarField,
        vk: &VerifyingKey<E>,
        pi_poly: &DensePolynomial<E::ScalarField>,
    ) -> E::ScalarField {
        let pi_at_x1 = pi_poly.evaluate(&x1);
        dbg!(pi_at_x1);
        let n_field = E::ScalarField::from(vk.n as u64);
        ((a_at_x1 + y1_gamma) * a_at_x1 - pi_at_x1 / n_field) / y1_alpha
    }

    pub fn tilde(public_inputs: &[E::ScalarField]) -> Vec<E::ScalarField> {
        let m0 = public_inputs.len();
        let one = E::ScalarField::ONE;
        let mut z_tilde = Vec::with_capacity(m0);
        for i in 0..m0 {
            let z_tilde_i = match i {
                0 => one + one,

                i if i < m0 => {
                    let j = i;
                    one + public_inputs[j]
                }

                i if i == m0 => E::ScalarField::zero(),

                i => {
                    // i > m0
                    let j = i - m0;
                    one - public_inputs[j]
                }
            };
            z_tilde.push(z_tilde_i);
        }
        z_tilde
    }

    pub(crate) fn remove_every_kth<T: Clone>(v: &[T], k: usize) -> Vec<T> {
        assert!(k > 0, "k must be non-zero");
        v.iter()
            .enumerate()
            .filter(|(i, _)| i % k != 0)
            .map(|(_, item)| item.clone())
            .collect()
    }

    pub(crate) fn domain_normalizer(
        h_domain: &GeneralEvaluationDomain<E::ScalarField>,
        k_domain: &GeneralEvaluationDomain<E::ScalarField>,
    ) -> DensePolynomial<E::ScalarField> {
        let domain_ratio = h_domain.size() / k_domain.size();
        let num = DenseOrSparsePolynomial::from(SparsePolynomial::from_coefficients_slice(&[
            (0, -E::ScalarField::ONE),
            (h_domain.size(), E::ScalarField::ONE),
        ]));
        let den = DenseOrSparsePolynomial::from(SparsePolynomial::from_coefficients_slice(&[
            (0, -E::ScalarField::ONE),
            (k_domain.size(), E::ScalarField::ONE),
        ]));

        let (q, r) = num.divide_with_q_and_r(&den).unwrap();
        q * E::ScalarField::from(domain_ratio as u64).inverse().unwrap()
    }

    pub(crate) fn reindex(
        ind: usize,
        num_witness: usize,
        num_instance: usize,
        domain_ratio: usize,
    ) -> usize {
        let num_vars = num_witness + num_instance;
        if ind < num_witness {
            ind + ind / domain_ratio
        } else if ind >= num_witness && ind < num_vars {
            (ind - num_witness) * domain_ratio
        } else {
            panic!("Index out of bounds");
        }
    }

    pub(crate) fn reshape_mat_inplace<T>(
        mat: &mut Matrix<T>,
        num_witness: usize,
        num_instance: usize,
        domain_ratio: usize,
    ) where
        T: Clone + Zero + Debug,
    {
        for row in mat {
            for (_, i) in row.iter_mut() {
                *i = Self::reindex(*i, num_witness, num_instance, domain_ratio);
            }
        }
    }

    pub(crate) fn reshape_slice<T>(
        vec: &[T],
        num_witness: usize,
        num_instance: usize,
        domain_ratio: usize,
    ) -> Vec<T>
    where
        T: Clone + Zero + Debug,
    {
        let wit_slice = &vec[0..num_witness];
        let inst_slice = &vec[num_witness..num_witness + num_instance];
        let num_output_chunks = (wit_slice.len() + (domain_ratio - 2)) / (domain_ratio - 1);
        if num_output_chunks > num_instance {
            let mut new_vec = Vec::with_capacity(num_output_chunks * domain_ratio);
            wit_slice
                .chunks(domain_ratio - 1)
                .enumerate()
                .for_each(|(i, chunk)| {
                    if i < num_instance {
                        new_vec.push(inst_slice[i].clone());
                    } else {
                        new_vec.push(T::zero());
                    }
                    new_vec.extend_from_slice(chunk);
                });
            new_vec
        } else {
            let mut new_vec = Vec::with_capacity(num_instance * domain_ratio);
            let padded_wit = Self::pad_slice_to_multiple_of_k(wit_slice, domain_ratio - 1);
            inst_slice.iter().enumerate().for_each(|(i, inst_elem)| {
                new_vec.push(inst_elem.clone());
                if i < num_output_chunks {
                    new_vec.extend_from_slice(
                        &padded_wit[i * (domain_ratio - 1)..(i + 1) * (domain_ratio - 1)],
                    );
                } else {
                    new_vec.extend_from_slice(&vec![T::zero(); domain_ratio - 1]);
                }
            });
            new_vec
        }
    }

    fn pad_slice_to_multiple_of_k<T>(slice: &[T], k: usize) -> Vec<T>
    where
        T: Clone + Zero,
    {
        assert!(k > 0, "k must be non-zero");
        let rem = slice.len() % k;
        let mut out = slice.to_vec();
        if rem != 0 {
            let pad_len = k - rem;
            out.extend(repeat_n(T::zero(), pad_len));
        }
        out
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Bls12_381;

    use crate::Polymath;

    // Test reshape_slice function
    #[test]
    fn test_reshape_slice() {
        assert_eq!(
            Polymath::<Bls12_381>::reshape_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 8, 3, 3,),
            vec![9, 1, 2, 10, 3, 4, 11, 5, 6, 0, 7, 8]
        );

        assert_eq!(
            Polymath::<Bls12_381>::reshape_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 9, 2, 3,),
            vec![10, 1, 2, 11, 3, 4, 0, 5, 6, 0, 7, 8, 0, 9]
        );

        assert_eq!(
            Polymath::<Bls12_381>::reshape_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 2, 9, 3,),
            vec![
                3, 1, 2, 4, 0, 0, 5, 0, 0, 6, 0, 0, 7, 0, 0, 8, 0, 0, 9, 0, 0, 10, 0, 0, 11, 0, 0
            ]
        );

        assert_eq!(
            Polymath::<Bls12_381>::reshape_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], 3, 8, 3,),
            vec![
                4, 1, 2, 5, 3, 0, 6, 0, 0, 7, 0, 0, 8, 0, 0, 9, 0, 0, 10, 0, 0, 11, 0, 0
            ]
        );
    }
}
