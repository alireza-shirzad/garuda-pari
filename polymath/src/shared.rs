use core::{num, panic};
use std::cmp::max;
use std::fmt::Debug;
use std::iter::repeat_n;
use std::ops::Neg;

use crate::{Polymath, data_structures::VerifyingKey};
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial, SparsePolynomial};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial, domain};
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
        if ind < num_instance {
            ind * domain_ratio
        } else if ind < num_instance + num_witness {
            let wit_ind = ind - num_instance;
            let group_ind = (wit_ind) / (domain_ratio - 1);
            let group_offset = (wit_ind % (domain_ratio - 1)) + 1;
            group_ind * domain_ratio + group_offset
        } else {
            panic!("Index out of bounds")
        }
    }

    pub(crate) fn reshape_matrix<T>(
        mat: &Matrix<T>,
        num_witness: usize,
        num_instance: usize,
        domain_ratio: usize,
    ) -> Matrix<T>
    where
        T: Clone + Zero + Debug,
    {
        let mut new_matrix = mat.clone();
        for row in &mut new_matrix {
            for (_, i) in row.iter_mut() {
                *i = Self::reindex(*i, num_witness, num_instance, domain_ratio);
            }
        }
        new_matrix
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
        let new_num_vars = max(
            (num_witness / (domain_ratio - 1)) * domain_ratio
                + num_witness % (domain_ratio - 1)
                + 1,
            (num_instance - 1) * domain_ratio + 1,
        );
        let mut out = vec![T::zero(); new_num_vars];
        for (i, item) in vec.iter().enumerate() {
            let new_index = Self::reindex(i, num_witness, num_instance, domain_ratio);
            out[new_index] = item.clone();
        }
        out
    }
}
