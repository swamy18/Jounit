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
    BadSignature,
    /// signature scheme id not recognised by this implementation
    UnsupportedSigScheme(u8),
    /// pubkey is not a valid compressed secp256k1 point
    BadPubkey,
    /// address derived from the input pubkey does not own the spent output
    WrongAddress,
    /// would mint past the hard supply cap
    SupplyCapExceeded {
        already: u64,
        requested: u64,
        cap: u64,
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
            Error::BadSignature => write!(f, "signature does not verify"),
            Error::UnsupportedSigScheme(s) => write!(f, "unsupported sig_scheme {s}"),
            Error::BadPubkey => write!(f, "invalid compressed secp256k1 pubkey"),
            Error::WrongAddress => write!(f, "pubkey does not own the spent output"),
            Error::SupplyCapExceeded {
                already,
                requested,
                cap,
            } => write!(
                f,
                "mint would exceed cap: issued {already} + reward {requested} > cap {cap}"
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
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
