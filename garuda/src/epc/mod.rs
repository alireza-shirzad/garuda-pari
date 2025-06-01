use ark_std::rand::{Rng, RngCore};

pub mod data_structures;
pub mod multilinear;
pub trait EPC {
    type PublicParameters;
    type OpeningProof;
    type BatchedOpeningProof;
    type CommitmentKey;
    type VerifyingKey;
    type Evaluation;
    type EvaluationPoint;
    type Trapdoor;
    type ProverZKState;
    type ProverBatchedZKState;
    type Commitment;
    type BatchedCommitment;
    type Polynomial;
    type BasisPoly;
    type PolynomialBasis;
    type EquifficientConstraint;

    fn setup(
        rng: impl RngCore,
        pp: &Self::PublicParameters,
        hiding_bound: Option<usize>,
        equifficient_constrinats: &Self::EquifficientConstraint,
    ) -> (Self::CommitmentKey, Self::VerifyingKey, Self::Trapdoor);

    /// `rest_zero` indicates that the rest of the coefficients are zero.
    /// Implementations can use this to skip work.
    fn commit(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        rng: &mut impl Rng,
        hiding_bound: Option<usize>,
        rest_zero: Option<usize>,
    ) -> (Self::Commitment, Self::ProverZKState);

    /// The second component of the `polys` tuple is `rest_zero` as in the `commit` function.
    fn batch_commit(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        rest_zeros: &[Option<usize>],
        hiding_bounds: &[Option<usize>],
        equifficients: Option<&[Self::Equifficient]>,
    ) -> (Self::BatchedCommitment, Self::ProverBatchedZKState);

    fn open(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        point: &Self::EvaluationPoint,
        comm: &Self::Commitment,
        state: &Self::ProverZKState,
    ) -> Self::OpeningProof;

    fn batch_open(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        points: &Self::EvaluationPoint,
        comms: &Self::BatchedCommitment,
        state: &Self::ProverBatchedZKState,
    ) -> Self::BatchedOpeningProof;

    #[allow(dead_code)]
    fn verify(
        vk: &Self::VerifyingKey,
        comm: &Self::Commitment,
        point: &Self::EvaluationPoint,
        eval: &Self::Evaluation,
        proof: &Self::OpeningProof,
    ) -> bool;

    fn batch_verify(
        vk: &Self::VerifyingKey,
        comm: &Self::BatchedCommitment,
        point: &Self::EvaluationPoint,
        evals: &[Self::Evaluation],
        proofs: &Self::BatchedOpeningProof,
        constrained_num: usize,
    ) -> bool;
}
