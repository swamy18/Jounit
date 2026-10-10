use std::fmt;

/// Every failure mode is a *deterministic, consensus-visible* condition: two
/// conforming nodes that evaluate the same block must produce the same `Error`
/// variant, because callers branch on it (e.g. `ReorgWouldCrossFinality`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `difficulty` outside `[1, MAX_DIFFICULTY]`
    InvalidDifficulty(u128),
    /// Target division would not fit in the u128 remainder accumulator
    TargetOverflow(u128),
    /// Malformed byte stream while deserializing
    Malformed(&'static str),
    /// Serialization disagrees with an expected size
    BadLength { expected: usize, got: usize },
    /// header.height != parent.height + 1
    BadHeight { expected: u64, got: u64 },
    /// header.prev_hash mismatch
    BadPrevHash,
    /// U256(block_hash) > target(difficulty)
    PowInvalid { hash: String, difficulty: u128 },
    /// puzzle_id unknown or not active at this height
    UnknownPuzzle(u64),
    /// epoch_id != height / nn_epoch_blocks
    BadEpoch { expected: u32, got: u32 },
    /// difficulty != expected_difficulty(history)
    BadDifficulty { expected: u128, got: u128 },
    /// computed merkle root != header.merkle_root
    BadMerkleRoot,
    /// timestamp below median of previous 11
    TimestampTooOld { median: u64, got: u64 },
    /// timestamp above median + future_limit
    TimestampTooFuture { limit: u64, got: u64 },
    /// gas_used > gas_cap
    GasOverCap { used: u64, cap: u64 },
    /// more transactions than `max_tx_count`
    TooManyTxs { got: usize, cap: usize },
    /// serialized block larger than `max_block_bytes`
    BlockTooLarge { got: usize, cap: usize },
    /// coinbase missing / not at index 0 / wrong shape
    BadCoinbase(&'static str),
    /// two transactions in the block share a txid
    DuplicateTxid,
    /// spending an output that does not exist or is already spent
    UnknownOutPoint,
    /// the same input referenced twice
    DuplicateInput,
    /// inputs do not cover outputs + fee
    ValueOverflow,
    /// fee below the required base fee, or the miner over-claimed the reward
    BadFee(&'static str),
    /// coinbase output is not yet spendable
    ImmatureCoinbase { height: u64, required: u64 },
    /// signature did not verify for the address owning the spent output
    BadSignature { scheme: u8 },
    /// signature scheme id not recognised by this implementation
    UnsupportedSigScheme(u8),
    /// signature bundle declared no components
    EmptySignatureBundle,
    /// bundle carries more components than `MAX_BUNDLE_COMPONENTS`
    TooManyBundleComponents { got: usize, cap: usize },
    /// a single component's length was zero or over `MAX_COMPONENT_BYTES`
    BadComponentLength(usize),
    /// the same scheme appears twice in one bundle
    DuplicateBundleScheme(u8),
    /// signature bundle and key bundle hold different component counts
    BundleKeyMismatch { sigs: usize, keys: usize },
    /// a signature component has no key component of the same scheme
    MissingKeyForScheme(u8),
    /// the input carries a single-scheme bundle where a hybrid is required
    HybridRequired,
    /// pubkey is not a valid compressed secp256k1 point
    BadPubkey,
    /// address derived from the input pubkey does not own the spent output
    WrongAddress,
    /// would exceed the rate anchor in effect at this height (Stage SA-1/SA-3)
    SupplyRateExceeded {
        already: u64,
        requested: u64,
        allowed_in_period: u64,
    },
    /// key material was not 32 bytes, or a keypair was not generated
    BadKey(&'static str),
    /// puzzle registry entry fails its own work-share audit
    BadPuzzleSpec(String),
    /// chain reorg would rewrite a finalized block
    ReorgWouldCrossFinality { finalized_height: u64 },
    /// wallet lacks funds for the requested spend
    InsufficientFunds { needed: u64, available: u64 },
    /// block already known
    AlreadyKnown,
    /// no parent found for a submitted block
    UnknownParent,
    /// bonded-stake rule violated (bond, unbond or slash refusal names its rule)
    StakeInvalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidDifficulty(d) => write!(f, "invalid difficulty {d}"),
            Error::TargetOverflow(d) => write!(f, "target division overflows for difficulty {d}"),
            Error::Malformed(w) => write!(f, "malformed byte stream: {w}"),
            Error::BadLength { expected, got } => {
                write!(f, "bad length: expected {expected}, got {got}")
            }
            Error::BadHeight { expected, got } => {
                write!(f, "bad height: expected {expected}, got {got}")
            }
            Error::BadPrevHash => write!(f, "prev_hash does not match parent"),
            Error::PowInvalid { hash, difficulty } => {
                write!(f, "pow invalid: {hash} > target(difficulty={difficulty})")
            }
            Error::UnknownPuzzle(id) => write!(f, "unknown puzzle id {id}"),
            Error::BadEpoch { expected, got } => {
                write!(f, "bad epoch_id: expected {expected}, got {got}")
            }
            Error::BadDifficulty { expected, got } => {
                write!(f, "bad difficulty: expected {expected}, got {got}")
            }
            Error::BadMerkleRoot => write!(f, "merkle root mismatch"),
            Error::TimestampTooOld { median, got } => {
                write!(f, "timestamp {got} below median-time {median}")
            }
            Error::TimestampTooFuture { limit, got } => {
                write!(f, "timestamp {got} above median+future-limit {limit}")
            }
            Error::GasOverCap { used, cap } => write!(f, "gas used {used} over cap {cap}"),
            Error::TooManyTxs { got, cap } => write!(f, "{got} transactions exceeds cap {cap}"),
            Error::BlockTooLarge { got, cap } => {
                write!(f, "block is {got} bytes, cap is {cap}")
            }
            Error::BadCoinbase(w) => write!(f, "bad coinbase: {w}"),
            Error::DuplicateTxid => write!(f, "duplicate txid in block"),
            Error::UnknownOutPoint => write!(f, "spending an unknown or already spent output"),
            Error::DuplicateInput => write!(f, "duplicate input within transaction"),
            Error::ValueOverflow => write!(f, "inputs do not cover outputs plus fee"),
            Error::BadFee(w) => write!(f, "bad fee: {w}"),
            Error::ImmatureCoinbase { height, required } => {
                write!(f, "coinbase at height {height} immature until {required}")
            }
            Error::BadSignature { scheme } => write!(
                f,
                "{}-signature does not verify",
                crate::sig::scheme_name(*scheme)
            ),
            Error::UnsupportedSigScheme(s) => write!(f, "unsupported sig_scheme {s}"),
            Error::EmptySignatureBundle => write!(f, "signature bundle is empty"),
            Error::TooManyBundleComponents { got, cap } => {
                write!(f, "signature bundle has {got} components, cap {cap}")
            }
            Error::BadComponentLength(n) => {
                write!(f, "signature component length {n} outside 1..=4096")
            }
            Error::DuplicateBundleScheme(s) => write!(
                f,
                "signature scheme {} appears twice in one bundle",
                crate::sig::scheme_name(*s)
            ),
            Error::BundleKeyMismatch { sigs, keys } => write!(
                f,
                "signature bundle has {sigs} components but key bundle has {keys}"
            ),
            Error::MissingKeyForScheme(s) => write!(
                f,
                "no {} key for a signature component",
                crate::sig::scheme_name(*s)
            ),
            Error::HybridRequired => {
                write!(f, "a hybrid signature bundle is required here")
            }
            Error::BadPubkey => write!(f, "invalid compressed secp256k1 pubkey"),
            Error::WrongAddress => write!(f, "pubkey does not own the spent output"),
            Error::SupplyRateExceeded {
                already,
                requested,
                allowed_in_period,
            } => write!(
                f,
                "mint exceeds the rate anchor: issued {already} + reward {requested} > {allowed_in_period} sat allowed in this period"
            ),
            Error::BadKey(w) => write!(f, "bad key material: {w}"),
            Error::BadPuzzleSpec(w) => write!(f, "invalid puzzle spec: {w}"),
            Error::ReorgWouldCrossFinality { finalized_height } => {
                write!(f, "reorg would rewrite finalized height {finalized_height}")
            }
            Error::InsufficientFunds { needed, available } => {
                write!(f, "insufficient funds: need {needed}, have {available}")
            }
            Error::AlreadyKnown => write!(f, "block already known"),
            Error::UnknownParent => write!(f, "parent block unknown"),
            Error::StakeInvalid(w) => write!(f, "bonded-stake rule violated: {w}"),
        }
    }
}

impl From<crate::bls::BlsError> for Error {
    fn from(e: crate::bls::BlsError) -> Self {
        // Mapped onto `BadKey` rather than a new variant: every `BlsError` is
        // either unusable key material (`BadSeed`, `BadPoint`) or a rejected
        // signature, and a caller only ever needs to refuse the operation. The
        // detail is folded into the message rather than leaked into the variant
        // list, so `?` on a BLS call stays total without widening `Error`.
        Error::BadKey(match e {
            crate::bls::BlsError::BadSeed => "unusable BLS seed or scalar",
            crate::bls::BlsError::BadPoint { .. } => "not a valid BLS point",
            crate::bls::BlsError::BadSignature { .. } => "BLS signature rejected",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
