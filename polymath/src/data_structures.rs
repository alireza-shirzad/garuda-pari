use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::{GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalSerialize;

/// The proving key for Pari
/// The naming matches the one in the figure 6, item 8 of the paper: https://eprint.iacr.org/2024/1245.pdf
#[derive(CanonicalSerialize, Clone)]
pub struct ProvingKey<E>
where
    E: Pairing,
    E::ScalarField: Field,
{
    pub x_to_j_g1_vec: Vec<E::G1Affine>,
    pub x_to_i_y_to_alpha_g1_vec: Vec<E::G1Affine>,
    pub x_to_i_y_to_gamma_g1_vec: Vec<E::G1Affine>,
    pub u_w_g1_vec: Vec<E::G1Affine>,
    pub x_zh_over_y_alpha_g1_vec: Vec<E::G1Affine>,
    pub x_z_g1_vec: Vec<E::G1Affine>,
    pub vk: VerifyingKey<E>,
}

/// The verifying key for Pari
#[derive(Clone, Debug, CanonicalSerialize)]
pub struct VerifyingKey<E: Pairing> {
    pub n: usize,
    pub sigma: usize,
    pub m0: usize,
    pub succinct_index: SuccinctIndex,
    pub g: E::G1Affine,
    pub x_h: E::G2Affine,
    pub z_h: E::G2Affine,
    pub h: E::G2Affine,
    pub h_domain: GeneralEvaluationDomain<E::ScalarField>,
    pub k_domain: GeneralEvaluationDomain<E::ScalarField>,
    // TODO: Remove these
    pub x: E::ScalarField,
    pub y: E::ScalarField,
    pub z: E::ScalarField,
}

// impl<E: Pairing> CanonicalSerialize for VerifyingKey<E> {
//     fn serialize_with_mode<W: std::io::Write>(
//         &self,
//         mut writer: W,
//         compress: ark_serialize::Compress,
//     ) -> Result<(), ark_serialize::SerializationError> {
//         // Serialize each field in order
//         self.succinct_index
//             .serialize_with_mode(&mut writer, compress)?;
//         self.alpha_g.serialize_with_mode(&mut writer, compress)?;
//         self.beta_g.serialize_with_mode(&mut writer, compress)?;
//         self.delta_two_h
//             .serialize_with_mode(&mut writer, compress)?;
//         self.tau_h.serialize_with_mode(&mut writer, compress)?;
//         self.g.serialize_with_mode(&mut writer, compress)?;
//         self.h.serialize_with_mode(&mut writer, compress)?;

//         Ok(())
//     }

//     fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
//         let mut size = 0;
//         size += ark_serialize::CanonicalSerialize::serialized_size(&self.succinct_index, compress);
//         size += ark_serialize::CanonicalSerialize::serialized_size(&self.alpha_g, compress);
//         size += ark_serialize::CanonicalSerialize::serialized_size(&self.beta_g, compress);
//         size += ark_serialize::CanonicalSerialize::serialized_size(&self.delta_two_h, compress);
//         size += ark_serialize::CanonicalSerialize::serialized_size(&self.tau_h, compress);
//         size += ark_serialize::CanonicalSerialize::serialized_size(&self.g, compress);
//         size += ark_serialize::CanonicalSerialize::serialized_size(&self.h, compress);
//         size
//     }
// }

//  The succinct index for Polymath
//  This contains enough information from the GR1CS to verify the proof
#[derive(CanonicalSerialize, Clone, Debug)]
pub struct SuccinctIndex {
    /// The log of number of constraints rounded up, will be translated to the number of variables in the ml extensions
    pub num_constraints: usize,
    /// The length of the instance variables
    pub num_instance: usize,
}

#[derive(CanonicalSerialize, Clone)]
pub struct Proof<E: Pairing> {
    pub a: E::G1Affine,
    pub c: E::G1Affine,
    pub d: E::G1Affine,
    pub a_x_1: E::ScalarField,
}
