use ark_std::rand::RngCore;

pub mod data_structures;
pub mod multilinear;
pub trait EPC {
    type PublicParameters;
    type OpeningProof;
    type BatchedOpeningProof;
    type Equifficient;
    type CommitmentKey;
    type VerifyingKey;
    type Evaluation;
    type EvaluationPoint;
    type Trapdoor;
    type Commitment;
    type BatchedCommitment;
    type Polynomial;
    type BasisPoly;
    type PolynomialBasis;
    type EquifficientConstraint;

    fn setup(
        rng: impl RngCore,
        pp: &Self::PublicParameters,
        equifficient_constrinats: &Self::EquifficientConstraint,
    ) -> (Self::CommitmentKey, Self::VerifyingKey, Self::Trapdoor);

    /// `rest_zero` indicates that the rest of the coefficients are zero.
    /// Implementations can use this to skip work.
    fn commit(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        rest_zero: Option<usize>,
    ) -> Self::Commitment;

    /// The second component of the `polys` tuple is `rest_zero` as in the `commit` function.
    fn batch_commit(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        rest_zeros: &[Option<usize>],
        equifficients: Option<&[Self::Equifficient]>,
    ) -> Self::BatchedCommitment;

    fn open(
        ck: &Self::CommitmentKey,
        poly: &Self::Polynomial,
        point: &Self::EvaluationPoint,
        comm: &Self::Commitment,
    ) -> Self::OpeningProof;

    fn batch_open(
        ck: &Self::CommitmentKey,
        polys: &[Self::Polynomial],
        points: &Self::EvaluationPoint,
        comms: &Self::BatchedCommitment,
    ) -> Self::BatchedOpeningProof;

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
