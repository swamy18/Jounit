//! Streaming micro-payments (pay-as-you-use).
//!
//! A `PaymentStream` is the single primitive that lets a consumer pay a
//! provider *as the service is consumed* — per block, at a fixed rate, under
//! a hard cap — without one transaction per unit of work. It connects to the
//! pieces Decision 16 already shipped (agent identity, `SpendPolicy`, signed
//! `MachinePayment`) without touching any of them.
//!
//! # What this module is
//!
//! A **pure, deterministic streaming layer**. It answers exactly one question:
//! *at this height, how much of this stream may the recipient withdraw, and is
//! this withdrawal receipt valid?* The flow is:
//!
//! 1. the payer signs a [`PaymentStream`]: rate per block, first block, expiry
//!    height and a hard cap;
//! 2. as blocks advance, value accrues: `min(rate * blocks, cap)`;
//! 3. the recipient collects by presenting payer-signed [`StreamSettlement`]
//!    receipts; the [`StreamBook`] enforces that every receipt is exact,
//!    ordered and within the cap.
//!
//! Settlement still goes through the ordinary payment path — a receipt is
//! carried as a `MachinePayment` amount with `reference` = the stream id — so
//! coin movement needs no new transaction type and no consensus rule changes.
//!
//! # What this module is not
//!
//! - **Not custody.** Opening a stream locks nothing on chain; the cap is a
//!   signed promise, enforced by the book's exact-settlement rule and by the
//!   payer's wallet balance at settlement time, exactly like any other
//!   off-chain authorization in this codebase.
//! - **Not a second budget engine.** `SpendPolicy` caps and windows stay in
//!   `agent::PolicyBook`. Streams require a governing policy for autonomous
//!   (non-human) payers, but window accounting is the caller's job.
//! - **Not time-based.** Accrual is per block height, the only deterministic
//!   clock available offline. Wall-clock rates are the caller's conversion.
//!
//! # Fail-closed rules (locked)
//!
//! - zero rate, cap below one block of rate, and an expiry at or before the
//!   start are refused by name;
//! - a non-human payer without a governing policy is refused
//!   (`StreamError::PolicyRequired`), same rule as `MachinePayment`;
//! - accrual math is checked, never wrapping: an unrepresentable product
//!   refuses instead of accruing (`StreamError::Overflow`);
//! - a settlement must match the stream's accrued value **exactly** — over-
//!   and under-claims are both refused (`StreamError::AmountMismatch`);
//! - `through_height` must move strictly forward and never into the future:
//!   replaying a height and claiming unaccrued blocks are refused by name;
//! - a refused settlement commits nothing: budget is consumed only on `Ok`.

use crate::agent::{derive_agent_id, AgentId, AgentRole};
use crate::error::Error;
use crate::hash::{sha256_dom, Address, Hash};
use crate::l2::Auth;
use crate::ser::{Reader, Writer};
use crate::sig::Bundle;
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use std::fmt;

/// Stream encoding version. A future format MUST use a new value.
pub const STREAM_VERSION: u8 = 1;
/// Domain tag for the stream-open signing hash (also the stream id).
pub const DOM_PAYMENT_STREAM: &[u8] = b"srct/payment-stream/v1";
/// Domain tag for the settlement-receipt signing hash.
pub const DOM_STREAM_SETTLEMENT: &[u8] = b"srct/stream-settlement/v1";
/// Longest accepted network id (bytes), same bound the policy layer uses.
pub const MAX_STREAM_NETWORK_ID_LEN: usize = 64;
/// Default cap on tracked streams, so a caller cannot grow state forever.
pub const DEFAULT_MAX_TRACKED_STREAMS: usize = 1024;

/// Why a stream or settlement was refused. Named and `PartialEq`, so callers
/// (and tests) can assert the exact clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// Bytes could not be decoded as a stream or settlement.
    Malformed(&'static str),
    /// `version` is not [`STREAM_VERSION`].
    UnsupportedVersion(u8),
    /// `network_id` is empty.
    EmptyNetworkId,
    /// `network_id` exceeds [`MAX_STREAM_NETWORK_ID_LEN`].
    NetworkIdTooLong(usize),
    /// `rate_sat_per_block == 0`: a stream that accrues nothing is refused.
    ZeroRate,
    /// `max_total_sat < rate_sat_per_block`: the cap must cover one block.
    CapBelowRate { rate: u64, cap: u64 },
    /// `expires_at_height <= start_height`: the window must move forward.
    BadWindow { start: u64, expires: u64 },
    /// `agent_id` is not `derive_agent_id(network_id, payer_type, payer)`.
    IdentityMismatch,
    /// A machine/service payer without a governing policy is refused.
    PolicyRequired,
    /// Stream and settlement (or stream and book) name different networks.
    WrongNetwork { expected: String, got: String },
    /// Accrual or settlement arithmetic would overflow.
    Overflow,
    /// Settlement references a stream the book never opened.
    UnknownStream,
    /// The same stream opened twice into one book.
    DuplicateStream,
    /// The book is at capacity and refuses a new stream.
    BookFull { cap: usize },
    /// The settlement references a different stream than the one presented.
    NotOurStream,
    /// A settlement amount of zero accrues nothing and settles nothing.
    ZeroAmount,
    /// Settlement `nonce == 0`; the first nonce must be 1 or higher.
    ZeroNonce,
    /// The signing keys do not derive the stream payer's address.
    SignerNotPayer { signer: Address, payer: Address },
    /// A signature component did not verify.
    SignatureInvalid(&'static str),
    /// Settlement nonce is not strictly above the stream's last one.
    NonceReplay { got: u64, last: u64 },
    /// `through_height` rewinds to (or repeats) an already-settled range.
    HeightRewind { through: u64, last: u64 },
    /// `through_height` claims blocks that have not happened yet.
    ClaimBeforeTime { through: u64, at: u64 },
    /// Settlement amount differs from `accrued(through) - settled`.
    AmountMismatch { expected: u64, got: u64 },
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Malformed(w) => write!(f, "malformed stream bytes: {w}"),
            StreamError::UnsupportedVersion(v) => {
                write!(f, "unsupported stream version {v}")
            }
            StreamError::EmptyNetworkId => write!(f, "stream network id is empty"),
            StreamError::NetworkIdTooLong(n) => write!(
                f,
                "stream network id is {n} bytes, cap {MAX_STREAM_NETWORK_ID_LEN}"
            ),
            StreamError::ZeroRate => write!(f, "stream rate is zero"),
            StreamError::CapBelowRate { rate, cap } => {
                write!(f, "stream cap {cap} is below one block of rate {rate}")
            }
            StreamError::BadWindow { start, expires } => {
                write!(
                    f,
                    "stream window [{start}, {expires}) does not move forward"
                )
            }
            StreamError::IdentityMismatch => {
                write!(
                    f,
                    "agent id is not derived from payer type, payer and network"
                )
            }
            StreamError::PolicyRequired => {
                write!(f, "a machine/service stream must name its governing policy")
            }
            StreamError::WrongNetwork { expected, got } => {
                write!(f, "stream is for network {expected}, checked against {got}")
            }
            StreamError::Overflow => write!(f, "arithmetic overflow in stream"),
            StreamError::UnknownStream => write!(f, "stream was never opened in this book"),
            StreamError::DuplicateStream => write!(f, "stream is already open in this book"),
            StreamError::BookFull { cap } => {
                write!(f, "stream book is full ({cap} streams)")
            }
            StreamError::NotOurStream => {
                write!(f, "settlement references a different stream")
            }
            StreamError::ZeroAmount => write!(f, "settlement amount is zero"),
            StreamError::ZeroNonce => write!(f, "settlement nonce is zero"),
            StreamError::SignerNotPayer { signer, payer } => write!(
                f,
                "signing keys address {:02x?} is not payer {payer:02x?}",
                signer
            ),
            StreamError::SignatureInvalid(w) => {
                write!(f, "stream signature invalid: {w}")
            }
            StreamError::NonceReplay { got, last } => {
                write!(f, "settlement nonce {got} is not above last {last}")
            }
            StreamError::HeightRewind { through, last } => {
                write!(
                    f,
                    "settlement through height {through} rewinds settled height {last}"
                )
            }
            StreamError::ClaimBeforeTime { through, at } => {
                write!(
                    f,
                    "settlement claims through height {through} at height {at}"
                )
            }
            StreamError::AmountMismatch { expected, got } => {
                write!(f, "settlement settles {got}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for StreamError {}

impl From<Error> for StreamError {
    fn from(e: Error) -> Self {
        match e {
            Error::Malformed(w) => StreamError::Malformed(w),
            Error::WrongAddress => StreamError::SignatureInvalid("signer address mismatch"),
            _ => StreamError::SignatureInvalid("signature bundle rejected"),
        }
    }
}

/// The signed stream-open: *"I pay this recipient this rate per block from
/// this height to this expiry, at most this cap, once."*
///
/// `signing_hash` doubles as the **stream id**: a receipt names it, the book
/// keys on it, and a settlement payment carries it as `reference`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentStream {
    pub version: u8,
    /// Network binding, ≤ [`MAX_STREAM_NETWORK_ID_LEN`] bytes.
    pub network_id: String,
    /// Who is paying: human wallet, machine wallet, or service.
    pub payer_type: AgentRole,
    /// Payer's ordinary §1 address — the address the signature must match.
    pub payer: Address,
    /// `derive_agent_id(network_id, payer_type, payer)`, re-derived on verify.
    pub agent_id: AgentId,
    /// Who gets paid.
    pub recipient: Address,
    /// Service identity tag, when the stream pays for a service.
    pub service: Option<[u8; 32]>,
    /// Satoshis accruing per block, starting at `start_height` (inclusive).
    pub rate_sat_per_block: u64,
    /// First block that accrues (inclusive).
    pub start_height: u64,
    /// First block that accrues nothing new (exclusive).
    pub expires_at_height: u64,
    /// Hard cap on the stream's lifetime: accrual never exceeds it.
    pub max_total_sat: u64,
    /// Anti-replay counter for the open itself (one open per stream id).
    pub nonce: u64,
    /// Governing `SpendPolicy::hash()`. Zero only for human, policy-less opens.
    pub policy_hash: Hash,
    /// Public keys of the payer (hybrid bundle, same shape as an L1 input).
    pub keys: Bundle,
    /// Signatures of the payer over [`PaymentStream::signing_hash`].
    pub sigs: Bundle,
}

impl PaymentStream {
    /// The canonical body: every signed field, no signatures. Both the
    /// signing hash and the exact inverse encode/decode run through this one
    /// encoding, so there is exactly one byte string per stream.
    pub fn body(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(224);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .u8(self.payer_type.as_u8())
            .fixed(&self.payer)
            .fixed(&self.agent_id)
            .fixed(&self.recipient);
        match &self.service {
            Some(tag) => {
                w.u8(1).fixed(tag);
            }
            None => {
                w.u8(0);
            }
        }
        w.u64le(self.rate_sat_per_block)
            .u64le(self.start_height)
            .u64le(self.expires_at_height)
            .u64le(self.max_total_sat)
            .u64le(self.nonce)
            .fixed(&self.policy_hash);
        w.into_vec()
    }

    /// Domain-separated hash of the body. This is what the payer signs and
    /// what doubles as the stream id.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_PAYMENT_STREAM, &[&self.body()])
    }

    /// Canonical wire encoding: `body ‖ keys ‖ sigs`. Deterministic and
    /// self-delimiting; `deserialize` is its exact inverse.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.keys.to_bytes());
        out.extend_from_slice(&self.sigs.to_bytes());
        out
    }

    /// Bounded decode. The structural rules run before the caller sees the
    /// object.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, StreamError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| StreamError::Malformed("version"))?;
        if version != STREAM_VERSION {
            return Err(StreamError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| StreamError::Malformed("network len"))? as usize;
        if net_len == 0 {
            return Err(StreamError::EmptyNetworkId);
        }
        if net_len > MAX_STREAM_NETWORK_ID_LEN {
            return Err(StreamError::NetworkIdTooLong(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| StreamError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| StreamError::Malformed("network id is not utf-8"))?
            .to_string();
        let payer_type_raw = r.u8().map_err(|_| StreamError::Malformed("payer type"))?;
        let payer_type = AgentRole::from_u8(payer_type_raw)
            .ok_or(StreamError::Malformed("payer type out of range"))?;
        let payer = r
            .fixed::<20>()
            .map_err(|_| StreamError::Malformed("payer"))?;
        let agent_id = r
            .fixed::<20>()
            .map_err(|_| StreamError::Malformed("agent id"))?;
        let recipient = r
            .fixed::<20>()
            .map_err(|_| StreamError::Malformed("recipient"))?;
        let svc_flag = r.u8().map_err(|_| StreamError::Malformed("service flag"))?;
        let service = match svc_flag {
            0 => None,
            1 => Some(
                r.fixed::<32>()
                    .map_err(|_| StreamError::Malformed("service tag"))?,
            ),
            _ => return Err(StreamError::Malformed("service flag not 0 or 1")),
        };
        let rate_sat_per_block = r.u64le().map_err(|_| StreamError::Malformed("rate"))?;
        let start_height = r
            .u64le()
            .map_err(|_| StreamError::Malformed("start height"))?;
        let expires_at_height = r
            .u64le()
            .map_err(|_| StreamError::Malformed("expiry height"))?;
        let max_total_sat = r.u64le().map_err(|_| StreamError::Malformed("cap"))?;
        let nonce = r.u64le().map_err(|_| StreamError::Malformed("nonce"))?;
        let policy_hash = r
            .fixed::<32>()
            .map_err(|_| StreamError::Malformed("policy hash"))?;

        let keys = Bundle::from_reader(&mut r).map_err(StreamError::from)?;
        let sigs = Bundle::from_reader(&mut r).map_err(StreamError::from)?;
        r.expect_end()
            .map_err(|_| StreamError::Malformed("trailing bytes"))?;

        let stream = PaymentStream {
            version,
            network_id,
            payer_type,
            payer,
            agent_id,
            recipient,
            service,
            rate_sat_per_block,
            start_height,
            expires_at_height,
            max_total_sat,
            nonce,
            policy_hash,
            keys,
            sigs,
        };
        stream.validate()?;
        Ok(stream)
    }

    /// Structural self-consistency. Separate from signature verification so a
    /// stream can be rejected before any crypto work.
    pub fn validate(&self) -> Result<(), StreamError> {
        if self.version != STREAM_VERSION {
            return Err(StreamError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() {
            return Err(StreamError::EmptyNetworkId);
        }
        if self.network_id.len() > MAX_STREAM_NETWORK_ID_LEN {
            return Err(StreamError::NetworkIdTooLong(self.network_id.len()));
        }
        if self.rate_sat_per_block == 0 {
            return Err(StreamError::ZeroRate);
        }
        if self.max_total_sat < self.rate_sat_per_block {
            return Err(StreamError::CapBelowRate {
                rate: self.rate_sat_per_block,
                cap: self.max_total_sat,
            });
        }
        if self.expires_at_height <= self.start_height {
            return Err(StreamError::BadWindow {
                start: self.start_height,
                expires: self.expires_at_height,
            });
        }
        // Identity binding: the stream cannot name another identity.
        let expected = derive_agent_id(&self.network_id, self.payer_type, &self.payer);
        if expected != self.agent_id {
            return Err(StreamError::IdentityMismatch);
        }
        // Autonomous actors must be policy-governed; humans may open directly.
        if self.payer_type != AgentRole::Human && self.policy_hash == [0u8; 32] {
            return Err(StreamError::PolicyRequired);
        }
        Ok(())
    }

    /// Offline verification: structure, network binding, signer-address
    /// binding and every signature component. Public material only.
    pub fn verify(&self, network_id: &str) -> Result<(), StreamError> {
        if self.network_id != network_id {
            return Err(StreamError::WrongNetwork {
                expected: self.network_id.clone(),
                got: network_id.to_string(),
            });
        }
        self.validate()?;
        let signer = self.keys.address()?;
        if signer != self.payer {
            return Err(StreamError::SignerNotPayer {
                signer,
                payer: self.payer,
            });
        }
        let msg = self.signing_hash();
        crate::sig::verify_bundle(&self.sigs, &self.keys, &msg)?;
        Ok(())
    }

    /// Total satoshis accrued through `at_height` (inclusive), capped at
    /// `max_total_sat`. Zero before `start_height`; frozen at the cap after
    /// expiry. `None` when the product does not fit — a refusal, never a wrap.
    pub fn accrued(&self, at_height: u64) -> Option<u64> {
        if at_height < self.start_height {
            return Some(0);
        }
        let blocks = at_height.checked_sub(self.start_height)?.checked_add(1)?;
        let raw = self.rate_sat_per_block.checked_mul(blocks)?;
        Some(raw.min(self.max_total_sat))
    }
}

/// Everything but the key that opens a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenSpec {
    pub network_id: String,
    pub payer_type: AgentRole,
    pub recipient: Address,
    pub service: Option<[u8; 32]>,
    pub rate_sat_per_block: u64,
    pub start_height: u64,
    pub expires_at_height: u64,
    pub max_total_sat: u64,
    pub nonce: u64,
    pub policy_hash: Hash,
}

/// Build and sign a stream-open with the payer's wallet. The wallet is passed
/// in, never stored: nothing in this module reads, persists or emits a
/// private key.
pub fn build_stream(wallet: &Wallet, spec: StreamOpenSpec) -> Result<PaymentStream, StreamError> {
    let payer = wallet.address()?;
    let mut stream = PaymentStream {
        version: STREAM_VERSION,
        agent_id: derive_agent_id(&spec.network_id, spec.payer_type, &payer),
        payer,
        payer_type: spec.payer_type,
        network_id: spec.network_id.clone(),
        recipient: spec.recipient,
        service: spec.service,
        rate_sat_per_block: spec.rate_sat_per_block,
        start_height: spec.start_height,
        expires_at_height: spec.expires_at_height,
        max_total_sat: spec.max_total_sat,
        nonce: spec.nonce,
        policy_hash: spec.policy_hash,
        keys: Auth::keys_for(wallet)?,
        sigs: Bundle::default(),
    };
    stream.validate()?;
    let msg = stream.signing_hash();
    stream.sigs = Auth::sigs_for(wallet, &msg)?;
    stream.verify(&spec.network_id)?;
    Ok(stream)
}

/// The signed settlement receipt: *"of this stream, this much is withdrawn
/// through this height."*
///
/// A receipt is only meaningful against its stream — the book checks that its
/// amount equals exactly `accrued(through_height) - already_settled`, so a
/// receipt can neither mint value nor leave value stranded. Carry the settled
/// amount chain-side as a `MachinePayment` with `reference` = the stream id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSettlement {
    pub version: u8,
    /// Must equal the stream's network.
    pub network_id: String,
    /// The stream this receipt settles (`PaymentStream::signing_hash`).
    pub stream_id: Hash,
    /// Last height this receipt settles (inclusive). Must move forward and
    /// never exceed the height the book is told to check at.
    pub through_height: u64,
    /// Satoshis settled by this receipt: exactly the newly accrued amount.
    pub amount_sat: u64,
    /// Strictly increasing per stream (starts at 1).
    pub nonce: u64,
    /// Payment/transaction reference: the `MachinePayment` id that carried
    /// this receipt chain-side, or zero when still offline.
    pub reference: Hash,
    /// Public keys of the stream payer.
    pub keys: Bundle,
    /// Signatures of the payer over [`StreamSettlement::signing_hash`].
    pub sigs: Bundle,
}

impl StreamSettlement {
    /// The canonical body: every signed field, no signatures.
    pub fn body(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.stream_id)
            .u64le(self.through_height)
            .u64le(self.amount_sat)
            .u64le(self.nonce)
            .fixed(&self.reference);
        w.into_vec()
    }

    /// Domain-separated hash of the body. This is what the payer signs.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_STREAM_SETTLEMENT, &[&self.body()])
    }

    /// Canonical wire encoding: `body ‖ keys ‖ sigs`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.keys.to_bytes());
        out.extend_from_slice(&self.sigs.to_bytes());
        out
    }

    /// Bounded decode against the stream it claims to settle: the stream id
    /// and network are checked at decode time, the signature by [`verify`].
    pub fn deserialize(bytes: &[u8], stream: &PaymentStream) -> Result<Self, StreamError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| StreamError::Malformed("version"))?;
        if version != STREAM_VERSION {
            return Err(StreamError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| StreamError::Malformed("network len"))? as usize;
        if net_len == 0 {
            return Err(StreamError::EmptyNetworkId);
        }
        if net_len > MAX_STREAM_NETWORK_ID_LEN {
            return Err(StreamError::NetworkIdTooLong(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| StreamError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| StreamError::Malformed("network id is not utf-8"))?
            .to_string();
        let stream_id = r
            .fixed::<32>()
            .map_err(|_| StreamError::Malformed("stream id"))?;
        let through_height = r
            .u64le()
            .map_err(|_| StreamError::Malformed("through height"))?;
        let amount_sat = r.u64le().map_err(|_| StreamError::Malformed("amount"))?;
        let nonce = r.u64le().map_err(|_| StreamError::Malformed("nonce"))?;
        let reference = r
            .fixed::<32>()
            .map_err(|_| StreamError::Malformed("reference"))?;

        let keys = Bundle::from_reader(&mut r).map_err(StreamError::from)?;
        let sigs = Bundle::from_reader(&mut r).map_err(StreamError::from)?;
        r.expect_end()
            .map_err(|_| StreamError::Malformed("trailing bytes"))?;

        let settlement = StreamSettlement {
            version,
            network_id,
            stream_id,
            through_height,
            amount_sat,
            nonce,
            reference,
            keys,
            sigs,
        };
        settlement.verify(stream)?;
        Ok(settlement)
    }

    /// Structural self-consistency, without the stream or any signature.
    pub fn validate(&self) -> Result<(), StreamError> {
        if self.version != STREAM_VERSION {
            return Err(StreamError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() {
            return Err(StreamError::EmptyNetworkId);
        }
        if self.network_id.len() > MAX_STREAM_NETWORK_ID_LEN {
            return Err(StreamError::NetworkIdTooLong(self.network_id.len()));
        }
        if self.stream_id == [0u8; 32] {
            return Err(StreamError::NotOurStream);
        }
        if self.amount_sat == 0 {
            return Err(StreamError::ZeroAmount);
        }
        if self.nonce == 0 {
            return Err(StreamError::ZeroNonce);
        }
        Ok(())
    }

    /// Offline verification against the stream: network and stream-id binding,
    /// signer-is-payer binding, and every signature component.
    pub fn verify(&self, stream: &PaymentStream) -> Result<(), StreamError> {
        if self.network_id != stream.network_id {
            return Err(StreamError::WrongNetwork {
                expected: stream.network_id.clone(),
                got: self.network_id.clone(),
            });
        }
        if self.stream_id != stream.signing_hash() {
            return Err(StreamError::NotOurStream);
        }
        self.validate()?;
        let signer = self.keys.address()?;
        if signer != stream.payer {
            return Err(StreamError::SignerNotPayer {
                signer,
                payer: stream.payer,
            });
        }
        let msg = self.signing_hash();
        crate::sig::verify_bundle(&self.sigs, &self.keys, &msg)?;
        Ok(())
    }
}

/// Everything but the key that signs a settlement receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSettleSpec {
    pub through_height: u64,
    pub amount_sat: u64,
    pub nonce: u64,
    pub reference: Hash,
}

/// Build and sign a settlement receipt with the stream payer's wallet. The
/// wallet must be the stream's payer: a third party cannot mint receipts for
/// a stream it does not fund.
pub fn build_settlement(
    wallet: &Wallet,
    stream: &PaymentStream,
    spec: StreamSettleSpec,
) -> Result<StreamSettlement, StreamError> {
    let payer = wallet.address()?;
    if payer != stream.payer {
        return Err(StreamError::SignerNotPayer {
            signer: payer,
            payer: stream.payer,
        });
    }
    let mut settlement = StreamSettlement {
        version: STREAM_VERSION,
        network_id: stream.network_id.clone(),
        stream_id: stream.signing_hash(),
        through_height: spec.through_height,
        amount_sat: spec.amount_sat,
        nonce: spec.nonce,
        reference: spec.reference,
        keys: Auth::keys_for(wallet)?,
        sigs: Bundle::default(),
    };
    settlement.validate()?;
    let msg = settlement.signing_hash();
    settlement.sigs = Auth::sigs_for(wallet, &msg)?;
    settlement.verify(stream)?;
    Ok(settlement)
}

/// Per-stream accounting tracked by the book.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamState {
    /// Total satoshis settled so far on this stream.
    pub settled_sat: u64,
    /// Last height settled (inclusive). `None` before the first settlement.
    pub last_settled_height: Option<u64>,
    /// Last settlement nonce accepted. `0` before the first settlement.
    pub last_nonce: u64,
    /// Number of accepted settlements.
    pub settlements: u64,
}

/// Bounded set of open streams, keyed by stream id (`signing_hash`).
///
/// Deliberately a cap-with-refusal structure, like `PolicyBook`: a full book
/// refuses rather than evicts, because evicting would forget the settled
/// totals that close the double-withdrawal window.
#[derive(Debug, Clone)]
pub struct StreamBook {
    states: BTreeMap<Hash, StreamState>,
    max_streams: usize,
}

impl Default for StreamBook {
    fn default() -> Self {
        StreamBook::with_capacity(DEFAULT_MAX_TRACKED_STREAMS)
    }
}

impl StreamBook {
    pub fn with_capacity(max_streams: usize) -> Self {
        StreamBook {
            states: BTreeMap::new(),
            max_streams,
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub fn state(&self, stream_id: &Hash) -> Option<&StreamState> {
        self.states.get(stream_id)
    }

    /// Forget a stream's accounting (used when a stream is retired after full
    /// settlement). The caller must be sure no live receipt can still arrive.
    pub fn forget(&mut self, stream_id: &Hash) -> Option<StreamState> {
        self.states.remove(stream_id)
    }

    /// Satoshis the recipient may withdraw at `at_height`, or `None` when the
    /// stream is unknown or the accrual does not fit. Pure view: no state.
    pub fn claimable(&self, stream: &PaymentStream, at_height: u64) -> Option<u64> {
        let st = self.states.get(&stream.signing_hash())?;
        stream.accrued(at_height)?.checked_sub(st.settled_sat)
    }

    /// Open a stream into the book. Validates structure, binds the network,
    /// verifies the payer's signature, then commits the zero-settled state.
    ///
    /// Nothing is mutated on any error path: a refused open leaves the book
    /// exactly as it was.
    pub fn open(&mut self, stream: &PaymentStream, network_id: &str) -> Result<Hash, StreamError> {
        stream.validate()?;
        if stream.network_id != network_id {
            return Err(StreamError::WrongNetwork {
                expected: stream.network_id.clone(),
                got: network_id.to_string(),
            });
        }
        stream.verify(network_id)?;
        let id = stream.signing_hash();
        if self.states.contains_key(&id) {
            return Err(StreamError::DuplicateStream);
        }
        if self.states.len() >= self.max_streams {
            return Err(StreamError::BookFull {
                cap: self.max_streams,
            });
        }
        self.states.insert(
            id,
            StreamState {
                settled_sat: 0,
                last_settled_height: None,
                last_nonce: 0,
                settlements: 0,
            },
        );
        Ok(id)
    }

    /// Accept one settlement receipt. Checks, in order: the stream is known;
    /// the receipt names this stream; the signature; a strictly increasing
    /// nonce; a strictly increasing, non-future `through_height`; and the
    /// exact newly-accrued amount. Returns the stream's cumulative settled
    /// total on success.
    ///
    /// Nothing is mutated on any error path: a refused receipt leaves the
    /// accounting exactly as it was.
    pub fn settle(
        &mut self,
        stream: &PaymentStream,
        settlement: &StreamSettlement,
        at_height: u64,
    ) -> Result<u64, StreamError> {
        stream.validate()?;
        settlement.validate()?;
        if stream.network_id != settlement.network_id {
            return Err(StreamError::WrongNetwork {
                expected: stream.network_id.clone(),
                got: settlement.network_id.clone(),
            });
        }
        let id = stream.signing_hash();
        let st = self
            .states
            .get(&id)
            .copied()
            .ok_or(StreamError::UnknownStream)?;
        if settlement.stream_id != id {
            return Err(StreamError::NotOurStream);
        }
        settlement.verify(stream)?;
        if settlement.nonce <= st.last_nonce {
            return Err(StreamError::NonceReplay {
                got: settlement.nonce,
                last: st.last_nonce,
            });
        }
        if let Some(last) = st.last_settled_height {
            if settlement.through_height <= last {
                return Err(StreamError::HeightRewind {
                    through: settlement.through_height,
                    last,
                });
            }
        }
        if settlement.through_height > at_height {
            return Err(StreamError::ClaimBeforeTime {
                through: settlement.through_height,
                at: at_height,
            });
        }
        let accrued = stream
            .accrued(settlement.through_height)
            .ok_or(StreamError::Overflow)?;
        let expected = accrued
            .checked_sub(st.settled_sat)
            .ok_or(StreamError::Overflow)?;
        if settlement.amount_sat != expected {
            return Err(StreamError::AmountMismatch {
                expected,
                got: settlement.amount_sat,
            });
        }
        let settled_sat = st
            .settled_sat
            .checked_add(settlement.amount_sat)
            .ok_or(StreamError::Overflow)?;
        self.states.insert(
            id,
            StreamState {
                settled_sat,
                last_settled_height: Some(settlement.through_height),
                last_nonce: settlement.nonce,
                settlements: st.settlements.saturating_add(1),
            },
        );
        Ok(settled_sat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2::Auth;

    const NET: &str = "srct/testnet";

    fn wallet() -> Wallet {
        Wallet::new_random("payer")
    }

    fn stream_for(owner: Address) -> PaymentStream {
        PaymentStream {
            version: STREAM_VERSION,
            network_id: NET.to_string(),
            payer_type: AgentRole::Machine,
            payer: owner,
            agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
            recipient: [1u8; 20],
            service: Some([9u8; 32]),
            rate_sat_per_block: 10,
            start_height: 100,
            expires_at_height: 200,
            max_total_sat: 900,
            nonce: 1,
            policy_hash: [7u8; 32],
            keys: Bundle::default(),
            sigs: Bundle::default(),
        }
    }

    #[test]
    fn accrual_is_zero_before_start_linear_then_capped() {
        let w = wallet();
        let owner = w.address().unwrap();
        let s = stream_for(owner);
        assert_eq!(s.accrued(0), Some(0));
        assert_eq!(s.accrued(99), Some(0));
        assert_eq!(s.accrued(100), Some(10));
        assert_eq!(s.accrued(109), Some(100));
        // 10 * 101 = 1010, capped at 900.
        assert_eq!(s.accrued(199), Some(900));
        // Frozen after expiry, never above the cap.
        assert_eq!(s.accrued(10_000), Some(900));
    }

    #[test]
    fn accrual_refuses_instead_of_wrapping() {
        let w = wallet();
        let owner = w.address().unwrap();
        let mut s = stream_for(owner);
        s.rate_sat_per_block = u64::MAX / 2;
        s.max_total_sat = u64::MAX;
        assert_eq!(s.accrued(100), Some(u64::MAX / 2));
        // Three blocks at half-max no longer fits: refuse.
        assert_eq!(s.accrued(102), None);
    }

    #[test]
    fn a_signed_stream_round_trips_exactly() {
        let w = wallet();
        let owner = w.address().unwrap();
        let mut s = stream_for(owner);
        s.keys = Auth::keys_for(&w).unwrap();
        let msg = s.signing_hash();
        s.sigs = Auth::sigs_for(&w, &msg).unwrap();
        s.verify(NET).expect("valid stream verifies");
        let bytes = s.serialize();
        let back = PaymentStream::deserialize(&bytes).expect("decode");
        assert_eq!(back, s, "encode → decode must be the exact inverse");
        assert_eq!(back.signing_hash(), s.signing_hash());
        assert_eq!(back.serialize(), bytes, "encoding must be canonical");
    }
}
