use ark_ff::Field;
use ark_std::rand::{Rng, RngCore};

pub mod data_structures;
pub mod multilinear;
mod test;
pub trait EPC<F: Field> {
    type PublicParameters;
    type OpeningProof;
    type BatchedOpeningProof;
    type CommitmentKey;
    type VerifyingKey;
    type EvaluationPoint;
    type Trapdoor;
    type ProverState;
    type ProverBatchedState;
    type Commitment;
    type BatchedCommitment;
    type Polynomial;
    type BasisPoly;
    type PolynomialBasis;
    type EquifficientConstraint;

    fn setup(
        rng: &mut impl RngCore,
        pp: &Self::PublicParameters,
        hiding_bound: Option<usize>,
        equifficient_constrinats: &Self::EquifficientConstraint,
    ) -> (Self::CommitmentKey, Self::VerifyingKey, Self::Trapdoor);

    /// `rest_zero` indicates that the rest of the coefficients are zero.
    /// Implementations can use this to skip work.
    fn commit(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        rng: Option<&mut impl Rng>,
        hiding_bound: Option<usize>,
        rest_zero: Option<usize>,
    ) -> (Self::Commitment, Self::ProverState);

    /// The second component of the `polys` tuple is `rest_zero` as in the `commit` function.
    fn batch_commit(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        rest_zeros: &[Option<usize>],
        rng: &Option<&mut impl Rng>,
        hiding_bounds: &[Option<usize>],
        equifficients: Option<&[F]>,
    ) -> (Self::BatchedCommitment, Self::ProverBatchedState);

    fn open(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        point: &Self::EvaluationPoint,
        comm: &Self::Commitment,
        state: &Self::ProverState,
    ) -> Self::OpeningProof;

    fn batch_open(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        points: &Self::EvaluationPoint,
        comms: &Self::BatchedCommitment,
        state: &Self::ProverBatchedState,
    ) -> Self::BatchedOpeningProof;

    #[allow(dead_code)]
    fn verify(
        vk: &Self::VerifyingKey,
        comm: &Self::Commitment,
        point: &Self::EvaluationPoint,
        eval: F,
        proof: &Self::OpeningProof,
    ) -> bool;

    fn batch_verify(
        vk: &Self::VerifyingKey,
        comm: &Self::BatchedCommitment,
        point: &Self::EvaluationPoint,
        evals: &[F],
        proofs: &Self::BatchedOpeningProof,
        constrained_num: usize,
    ) -> bool;
}
