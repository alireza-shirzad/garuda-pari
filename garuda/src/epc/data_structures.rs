use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[allow(type_alias_bounds)]
/// Evaluations over {0,1}^n for G1
pub type EvaluationHyperCubeOnG1<E: Pairing> = Vec<E::G1Affine>;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MLPublicParameters<E: Pairing> {
    pub num_var: usize,
    pub num_constraints: usize,
    pub generators: Generators<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub(crate) struct Generators<E: Pairing> {
    pub g: E::G1,
    pub h: E::G2,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MLCommitmentKey<E: Pairing> {
    /// number of variables
    pub nv: usize,
    /// pp_k defined by libra
    pub powers_of_g: Vec<EvaluationHyperCubeOnG1<E>>,
    /// generator for G1
    pub g: E::G1Affine,
    /// generator for G2
    pub h: E::G2Affine,
    pub consistency_pk: Vec<E::G1Affine>,
}

/// Public Parameter used by prover
#[derive(Clone, Debug)]
pub struct MLVerifyingKey<E: Pairing> {
    /// number of variables
    pub nv: usize,
    /// generator of G1
    pub g: E::G1Affine,
    /// generator of G2
    pub h: E::G2Affine,
    pub h_prep: E::G2Prepared,
    /// g^t1, g^t2, ...
    pub h_mask_random: Vec<E::G2Affine>,
    pub h_mask_random_prep: Vec<E::G2Prepared>,
    pub consistency_vk: Vec<E::G2Affine>,
    pub consistency_vk_prep: Vec<E::G2Prepared>,
}

impl<E: Pairing> ark_serialize::CanonicalSerialize for MLVerifyingKey<E> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        CanonicalSerialize::serialize_with_mode(&self.nv, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.g, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.h, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.h_mask_random, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.consistency_vk, &mut writer, compress)?;
        Ok(())
    }
    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let mut size = 0;
        size += CanonicalSerialize::serialized_size(&self.nv, compress);
        size += CanonicalSerialize::serialized_size(&self.g, compress);
        size += CanonicalSerialize::serialized_size(&self.h, compress);
        size += CanonicalSerialize::serialized_size(&self.h_mask_random, compress);
        size += CanonicalSerialize::serialized_size(&self.consistency_vk, compress);
        size
    }
}

impl<E: Pairing> CanonicalDeserialize for MLVerifyingKey<E> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let nv = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let g = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let h = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let h_mask_random =
            Vec::<E::G2Affine>::deserialize_with_mode(&mut reader, compress, validate)?;
        let consistency_vk =
            Vec::<E::G2Affine>::deserialize_with_mode(&mut reader, compress, validate)?;
        let h_prep = E::G2Prepared::from(h);
        let h_mask_random_prep = h_mask_random.iter().copied().map(Into::into).collect();
        let consistency_vk_prep = consistency_vk.iter().copied().map(Into::into).collect();
        Ok(MLVerifyingKey {
            g,
            h,
            h_mask_random,
            consistency_vk,
            h_mask_random_prep,
            consistency_vk_prep,
            h_prep,
            nv,
        })
    }
}
impl<E: Pairing> ark_serialize::Valid for MLVerifyingKey<E> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        ark_serialize::Valid::check(&self.nv)?;
        ark_serialize::Valid::check(&self.g)?;
        ark_serialize::Valid::check(&self.h)?;
        ark_serialize::Valid::check(&self.h_mask_random)?;
        ark_serialize::Valid::check(&self.consistency_vk)?;
        Ok(())
    }
    fn batch_check<'a>(
        batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), ark_serialize::SerializationError>
    where
        Self: 'a,
    {
        let batch: Vec<_> = batch.collect();
        ark_serialize::Valid::batch_check(batch.iter().map(|v| &v.nv))?;
        ark_serialize::Valid::batch_check(batch.iter().map(|v| &v.g))?;
        ark_serialize::Valid::batch_check(batch.iter().map(|v| &v.h))?;
        ark_serialize::Valid::batch_check(batch.iter().map(|v| &v.h_mask_random))?;
        ark_serialize::Valid::batch_check(batch.iter().map(|v| &v.consistency_vk))?;
        Ok(())
    }
}

/// Public Parameter used by prover
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MLTrapdoor<E: Pairing> {
    pub tau: Vec<E::ScalarField>,
    pub consistency_challanges: Vec<E::ScalarField>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Copy)]
/// commitment
pub struct MLCommitment<E: Pairing> {
    /// number of variables
    pub nv: usize,
    /// product of g as described by the vRAM paper
    pub g_product: E::G1Affine,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
/// commitment
pub struct MLBatchedCommitment<E: Pairing> {
    pub individual_comms: Vec<MLCommitment<E>>,
    pub consistency_comm: Option<E::G1Affine>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
/// proof of opening
pub struct MLProof<E: Pairing> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}
