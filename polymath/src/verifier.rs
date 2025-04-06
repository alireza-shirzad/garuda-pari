use crate::utils::compute_chall;
use crate::GAMMA;
use crate::{
    Polymath,
    data_structures::{Proof, VerifyingKey},
};
use ark_ec::AffineRepr;
use ark_ec::{VariableBaseMSM, pairing::Pairing};
use ark_ff::PrimeField;
use ark_ff::{BigInteger, FftField, Field, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, ops::Neg, start_timer};

impl<E: Pairing> Polymath<E> {
    pub fn verify(proof: &Proof<E>, vk: &VerifyingKey<E>, public_input: &[E::ScalarField]) -> bool
    where
        <E::G1Affine as AffineRepr>::BaseField: PrimeField,
        E::G1Affine: Neg<Output = E::G1Affine>,
    {
        let timer_verify =
            start_timer!(|| format!("Verification (|x|= {})", vk.succinct_index.num_instance));
        debug_assert_eq!(public_input.len(), vk.succinct_index.num_instance - 1);
        let Proof { a_x_1, a, c, d } = proof;

        /////////////////////// Challenge Computation ///////////////////////
        let timer_transcript_init = start_timer!(|| "Computing Challenge");
        let x_1 = compute_chall::<E>(&vk, public_input, &a, &c, None);
        end_timer!(timer_transcript_init);
        let x_2 = compute_chall::<E>(&vk, public_input, &a, &c, Some((x_1, *a_x_1)));
        end_timer!(timer_transcript_init);

        /////////////////////// Some variables ///////////////////////

        let n = vk.domain.size();
        let sigma = n + 3;
        let y_1 = x_1.pow([sigma as u64]);
        let y1_to_gamma = y_1.pow([GAMMA as u64]);

        /////////////////////// Computing polynomials x_A ///////////////////////

        let timer_x_poly = start_timer!(|| "Compute x_a polynomial");
        let mut px_evaluations = Vec::with_capacity(vk.succinct_index.num_instance);
        let r1cs_orig_num_cnstrs = vk.succinct_index.num_constraints - vk.succinct_index.num_instance;

        px_evaluations.push(E::ScalarField::ONE);
        px_evaluations.extend_from_slice(&public_input[..(vk.succinct_index.num_instance - 1)]);
        let lag_coeffs_time = start_timer!(|| "Computing last lagrange coefficients");
        let (lagrange_coeffs, vanishing_poly_at_chall_inv) =
            Self::eval_last_lagrange_coeffs::<E::ScalarField>(
                &vk.domain,
                x_1,
                r1cs_orig_num_cnstrs,
                vk.succinct_index.num_instance,
            );
        end_timer!(lag_coeffs_time);

        let x_a = lagrange_coeffs
            .into_iter()
            .zip(px_evaluations)
            .fold(E::ScalarField::zero(), |acc, (x, d)| acc + x * d);
        let pi_x1 = x_a * y1_to_gamma;
        end_timer!(timer_x_poly);

        /////////////////////////////// C_x1 ///////////////////////

        let z_h_over_k: E::ScalarField = todo!();
        let c_x1 = (*a_x_1 + y1_to_gamma) * a_x_1 - pi_x1;

        /////////////////////// Final Pairing///////////////////////

        let first_left = (*a) + (*c) * x_2 - vk.g * ((*a_x_1) + x_2 * c_x1);
        let second_right = vk.x_h - vk.h * x_1;

        


        let timer_pairing = start_timer!(|| "Final Pairing");
        let right = E::multi_pairing([first_left, (*d).into_group()], [
            vk.z_h, 
            second_right.into()
        ]);
        assert!(right.is_zero());
        end_timer!(timer_pairing);
        end_timer!(timer_verify);
        true
    }

    #[cfg(feature = "sol")]
    fn eval_last_lagrange_coeffs_traced<F: FftField>(
        domain: &Radix2EvaluationDomain<F>,
        tau: F,
        start_ind: usize,
        count: usize,
    ) -> (Vec<F>, Vec<F>, Vec<F>)
    where
        E::BaseField: PrimeField + FftField,
        E::BaseField: FftField,
    {
        let size: usize = domain.size();
        let z_h_at_tau: F = domain.evaluate_vanishing_polynomial(tau);
        let mut neg_hi = Vec::new();
        let mut nom_i = Vec::new();
        let offset: F = domain.coset_offset();
        let group_gen: F = domain.group_gen();
        let _starting_g: F = offset * group_gen.pow([start_ind as u64]);
        let group_gen_inv = domain.group_gen_inv();
        let v_0_inv = domain.size_as_field_element() * offset.pow([size as u64 - 1]);
        let start_gen = group_gen.pow([start_ind as u64]);
        let mut l_i = z_h_at_tau.inverse().unwrap() * v_0_inv;
        let mut negative_cur_elem = (-offset) * (start_gen);
        let mut lagrange_coefficients_inverse = vec![F::zero(); count];
        for (_, coeff) in &mut lagrange_coefficients_inverse.iter_mut().enumerate() {
            neg_hi.push(negative_cur_elem);
            let nom = start_gen * (l_i.inverse().unwrap());
            nom_i.push(nom);
            let r_i = tau + negative_cur_elem;
            *coeff = l_i * r_i;
            l_i *= &group_gen_inv;
            negative_cur_elem *= &group_gen;
        }
        batch_inversion_and_mul(lagrange_coefficients_inverse.as_mut_slice(), &start_gen);
        (lagrange_coefficients_inverse, neg_hi, nom_i)
    }

    fn eval_last_lagrange_coeffs<F: FftField>(
        domain: &Radix2EvaluationDomain<F>,
        tau: F,
        start_ind: usize,
        count: usize,
    ) -> (Vec<F>, F) {
        let z_h_at_tau: F = domain.evaluate_vanishing_polynomial(tau);
        let group_gen: F = domain.group_gen();

        assert!(!z_h_at_tau.is_zero());

        let group_gen_inv = domain.group_gen_inv();
        let v_0_inv = domain.size_as_field_element();

        let start_gen = group_gen.pow([start_ind as u64]);
        let z_h_at_tau_inv = z_h_at_tau.inverse().unwrap();
        let mut l_i = z_h_at_tau_inv * v_0_inv;
        let mut negative_cur_elem = -start_gen;
        let mut lagrange_coefficients_inverse = vec![F::zero(); count];
        for coeff in &mut lagrange_coefficients_inverse.iter_mut() {
            *coeff = l_i * (tau + negative_cur_elem);
            l_i *= &group_gen_inv;
            negative_cur_elem *= &group_gen;
        }
        batch_inversion_and_mul(lagrange_coefficients_inverse.as_mut_slice(), &start_gen);
        (lagrange_coefficients_inverse, z_h_at_tau_inv)
    }
}

// Compute msm using windowed non-adjacent form
fn msm_bigint_wnaf<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    scalars: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {
    const C: usize = 2;
    let digits_count = const { (V::ScalarField::MODULUS_BIT_SIZE as usize).div_ceil(C) };
    let radix: u64 = 1 << C;
    let scalar_digits = scalars
        .iter()
        .flat_map(|s| make_digits::<C>(s, digits_count, radix))
        .collect::<Vec<_>>();
    let zero = V::zero();
    let mut window_sums = (0..digits_count).map(|i| {
        let mut buckets = [zero; 1 << C];
        for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
            use ark_std::cmp::Ordering;
            // digits is the digits thing of the first scalar?
            let scalar = digits[i];
            match 0.cmp(&scalar) {
                Ordering::Less => buckets[(scalar - 1) as usize] += base,
                Ordering::Greater => buckets[(-scalar - 1) as usize] -= base,
                Ordering::Equal => (),
            }
        }

        let mut running_sum = V::zero();
        let mut res = V::zero();
        buckets.into_iter().rev().for_each(|b| {
            running_sum += &b;
            res += &running_sum;
        });
        res
    });

    // We store the sum for the lowest window.
    let lowest = window_sums.next().unwrap();

    // We're traversing windows from high to low.
    lowest
        + &window_sums.rev().fold(zero, |mut total, sum_i| {
            total += sum_i;
            for _ in 0..C {
                total.double_in_place();
            }
            total
        })
}

// From: https://github.com/arkworks-rs/gemini/blob/main/src/kzg/msm/variable_base.rs#L20
#[inline]
fn make_digits<const W: usize>(
    a: &impl BigInteger,
    digits_count: usize,
    radix: u64,
) -> impl Iterator<Item = i64> + '_ {
    let scalar = a.as_ref();
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    (0..digits_count).map(move |i| {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * W;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let scalar_at_idx = scalar[u64_idx];
        let bit_buf = if bit_idx < 64 - W || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            scalar_at_idx >> bit_idx
        } else {
            let scalar_at_idx_next = scalar[1 + u64_idx];
            // Combine the current u64's bits with the bits from the next u64
            (scalar_at_idx >> bit_idx) | (scalar_at_idx_next << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> W;
        let mut digit = (coef as i64) - (carry << W) as i64;

        if i == digits_count - 1 {
            digit += (carry << W) as i64;
        }
        digit
    })
}

/// Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}.
/// This method is explicitly single-threaded.
fn batch_inversion_and_mul<F: Field>(v: &mut [F], coeff: &F) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2
    // but with an optimization to multiply every element in the returned vector by
    // coeff

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = F::one();
    for f in v.iter().filter(|f| !f.is_zero()) {
        tmp *= f;
        prod.push(tmp);
    }

    // Invert `tmp`.
    tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

    // Multiply product by coeff, so all inverses will be scaled by coeff
    tmp *= coeff;

    // Second pass: iterate backwards to compute inverses
    for (mut f, s) in v
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|f| !f.is_zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(F::one())))
    {
        // tmp := tmp * f; f := tmp * s = 1/f
        let new_tmp = tmp * *f;
        *f = tmp * &s;
        tmp = new_tmp;
    }
}
