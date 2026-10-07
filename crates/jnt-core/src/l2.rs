//! Layer-2 transaction types. Decision D3, `docs/decisions.md`.
//!
//! Jounit's L2 is the verified-work marketplace: a submitter posts a compute
//! task with a locked payment, a worker claims and runs it, and settlement
//! releases the payment against a verdict. These five payload types are the
//! protocol vocabulary for that loop.
//!
//! Scope, stated precisely because it is easy to over-read: these are *payload*
//! types. Phase 2 defines them, validates them and fee-routes them; wiring them
//! into an L1 block is Phase 6 (`memory.md` C). Nothing here touches L1
//! consensus, the L1 fee floor, the block wire format, or any existing vector.
//!
//! Encoding discipline, matching the rest of `jnt-core`:
//! - Every payload is canonically encodable: `serialize`/`from_reader` are exact
//!   inverses, and every length prefix is bounded before it drives an
//!   allocation.
//! - Authorization payloads commit to an explicit actor address and a signature
//!   bundle over a domain-separated signing hash. The hash covers the key bundle
//!   but not the signature bundle, exactly as the L1 `sighash` does.
//! - `Settle` has no single signer: its authorization is a validator-quorum BLS
//!   aggregate, reusing the M5 `ValidatorSet`/`BlsVerifier` machinery. The
//!   aggregate covers the same domain-separated hash, so a settle decision
//!   cannot be replayed at another task or verdict.
//!
//! Fees are the flat D3 schedule (`params::FEE_TX_*`). They are charged on a
//! path of their own through `fees::split_flat_fee`, which keeps the M1 50/50
//! burn/PSCB invariant and leaves the L1 `base_fee * gas_used` floor untouched.

use crate::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Address, Hash};
use crate::params::{
    FEE_TX_CLAIM_TASK_SAT, FEE_TX_DISPUTE_SAT, FEE_TX_POST_TASK_SAT, FEE_TX_SETTLE_SAT,
    FEE_TX_SUBMIT_RESULT_SAT,
};
use crate::ser::{Reader, Writer};
use crate::sig::{Bundle, Component, SCHEME_SECP256K1_ECDSA, SCHEME_SECP256K1_SCHNORR};
use crate::wallet::Wallet;

// ---------------------------------------------------------------------------
// Domain tags and wire type codes
// ---------------------------------------------------------------------------

/// `jounit/l2/...` construction tags, frozen like `hash.rs`'s. A changed
/// preimage needs a new tag rather than a reused one.
pub const DOM_L2_POST: &[u8] = b"jounit/l2/post/v1";
pub const DOM_L2_CLAIM: &[u8] = b"jounit/l2/claim/v1";
pub const DOM_L2_SUBMIT: &[u8] = b"jounit/l2/submit/v1";
pub const DOM_L2_DISPUTE: &[u8] = b"jounit/l2/dispute/v1";
pub const DOM_L2_SETTLE: &[u8] = b"jounit/l2/settle/v1";
pub const DOM_L2_TXID: &[u8] = b"jounit/l2/txid/v1";
/// Verified Work Certificate identity (SPEC.md §17.3). Derives a certificate id
/// from its canonical encoding; a different preimage needs a new tag.
pub const DOM_L2_VWC: &[u8] = b"jounit/l2/vwc/v1";

/// Wire type codes. Deliberately `0x10`-based: L1 uses `0` and `1`, and leaving a
/// clear gap means an L1 `tx_type` this build does not know is rejected as an
/// unknown *L1* type rather than silently read as an L2 one.
pub const L2_TX_POST: u8 = 0x10;
pub const L2_TX_CLAIM: u8 = 0x11;
pub const L2_TX_SUBMIT: u8 = 0x12;
pub const L2_TX_DISPUTE: u8 = 0x13;
pub const L2_TX_SETTLE: u8 = 0x14;

/// Largest settle signer bitmap accepted, in bytes (512 validators). `TopN = 21`
/// is the decided committee size, so this is a generous structural cap whose only
/// job is to stop a length prefix from driving an allocation.
pub const MAX_SIGNER_BITMAP_BYTES: usize = 64;

/// The `vwc_hash` value used before Verified Work Certificates exist (Phase 4):
/// the validated result hash for `Correct`, the challenger's counter-result for
/// `Fraudulent`, and all-zero for `Expired`.
pub const VWC_HASH_EXPIRED: Hash = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L2TxType {
    PostTask,
    ClaimTask,
    SubmitResult,
    Dispute,
    Settle,
}

impl L2TxType {
    pub fn to_wire(self) -> u8 {
        match self {
            L2TxType::PostTask => L2_TX_POST,
            L2TxType::ClaimTask => L2_TX_CLAIM,
            L2TxType::SubmitResult => L2_TX_SUBMIT,
            L2TxType::Dispute => L2_TX_DISPUTE,
            L2TxType::Settle => L2_TX_SETTLE,
        }
    }

    pub fn from_wire(b: u8) -> Result<Self> {
        match b {
            L2_TX_POST => Ok(L2TxType::PostTask),
            L2_TX_CLAIM => Ok(L2TxType::ClaimTask),
            L2_TX_SUBMIT => Ok(L2TxType::SubmitResult),
            L2_TX_DISPUTE => Ok(L2TxType::Dispute),
            L2_TX_SETTLE => Ok(L2TxType::Settle),
            _ => Err(Error::Malformed("unknown L2 transaction type")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            L2TxType::PostTask => "PostTask",
            L2TxType::ClaimTask => "ClaimTask",
            L2TxType::SubmitResult => "SubmitResult",
            L2TxType::Dispute => "Dispute",
            L2TxType::Settle => "Settle",
        }
    }

    /// The D3 flat fee for this type, in satoshis.
    pub fn fee_sat(self) -> u64 {
        match self {
            L2TxType::PostTask => FEE_TX_POST_TASK_SAT,
            L2TxType::ClaimTask => FEE_TX_CLAIM_TASK_SAT,
            L2TxType::SubmitResult => FEE_TX_SUBMIT_RESULT_SAT,
            L2TxType::Dispute => FEE_TX_DISPUTE_SAT,
            L2TxType::Settle => FEE_TX_SETTLE_SAT,
        }
    }
}

/// The settlement verdict a validator quorum signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Verdict {
    /// The worker's submitted result is correct. Payment releases to the worker.
    #[default]
    Correct,
    /// The challenger's counter-result is correct. The worker's deposit is
    /// slashed through M2.
    Fraudulent,
    /// The task lapsed. The submitter is refunded; the worker's deposit, if any,
    /// is burned in full (no vest — a smaller penalty than a fraud slash).
    Expired,
}

impl Verdict {
    pub fn to_wire(self) -> u8 {
        match self {
            Verdict::Correct => 0,
            Verdict::Fraudulent => 1,
            Verdict::Expired => 2,
        }
    }

    pub fn from_wire(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Verdict::Correct),
            1 => Ok(Verdict::Fraudulent),
            2 => Ok(Verdict::Expired),
            _ => Err(Error::Malformed("unknown settlement verdict")),
        }
    }
}

// ---------------------------------------------------------------------------
// Authorization bundle
// ---------------------------------------------------------------------------

/// A signed actor identity: a public-key bundle and the matching signature
/// bundle over the payload's signing hash.
///
/// The shape mirrors an L1 input, and for the same two reasons recorded in
/// `sig.rs`: every component must verify, and the address commits to the whole
/// key bundle so a hybrid key set cannot be swapped for a single-scheme one.
/// Newly built authorizations are hybrid (ECDSA + Schnorr), so an L2 actor's
/// address is the same as the address their L1 wallet funds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Auth {
    pub keys: Bundle,
    pub sigs: Bundle,
}

impl Auth {
    /// The hybrid key bundle for `wallet`. Its address is [`Wallet::address`],
    /// identical to the wallet's L1 funding address.
    pub fn keys_for(wallet: &Wallet) -> Result<Bundle> {
        Ok(Bundle {
            components: vec![
                Component::new(SCHEME_SECP256K1_ECDSA, wallet.pubkey()?.to_vec()),
                Component::new(SCHEME_SECP256K1_SCHNORR, wallet.schnorr_pubkey()?.to_vec()),
            ],
        })
    }

    /// The hybrid signature bundle for `wallet` over `msg`.
    pub fn sigs_for(wallet: &Wallet, msg: &Hash) -> Result<Bundle> {
        Ok(Bundle {
            components: vec![
                Component::new(SCHEME_SECP256K1_ECDSA, wallet.sign_digest(msg)?.to_vec()),
                Component::new(SCHEME_SECP256K1_SCHNORR, wallet.sign_schnorr(msg)?.to_vec()),
            ],
        })
    }

    /// Sign `msg` as a hybrid bundle from `wallet`.
    pub fn sign(wallet: &Wallet, msg: &Hash) -> Result<Self> {
        Ok(Auth {
            keys: Self::keys_for(wallet)?,
            sigs: Self::sigs_for(wallet, msg)?,
        })
    }

    /// The address this authorization acts as.
    pub fn address(&self) -> Result<Address> {
        self.keys.address()
    }

    /// Verify the signature bundle against the key bundle over `msg`.
    pub fn verify(&self, msg: &Hash) -> Result<()> {
        crate::sig::verify_bundle(&self.sigs, &self.keys, msg)
    }

    /// Check the signature *and* that it acts as `actor`.
    pub fn verify_as(&self, actor: &Address, msg: &Hash) -> Result<()> {
        if &self.address()? != actor {
            return Err(Error::WrongAddress);
        }
        self.verify(msg)
    }

    fn write_full(&self, w: &mut Writer) {
        w.raw(&self.keys.to_bytes());
        w.raw(&self.sigs.to_bytes());
    }

    fn write_body(&self, w: &mut Writer) {
        w.raw(&self.keys.to_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Auth {
            keys: Bundle::from_reader(r)?,
            sigs: Bundle::from_reader(r)?,
        })
    }
}

/// Task id derived from the posting actor, a nonce, and the task hash.
///
/// Deterministic and unique per `(submitter, nonce, task)`. The nonce is what
/// makes two otherwise identical posts distinct; the submitter is bound in so a
/// third party cannot repost another actor's task under a colliding id.
pub fn derive_task_id(submitter: &Address, nonce: u64, task_hash: &Hash) -> Hash {
    let mut w = Writer::new();
    w.fixed(submitter).u64le(nonce).fixed(task_hash);
    sha256_dom(DOM_L2_POST, &[w.as_slice()])
}

// ---------------------------------------------------------------------------
// PostTask
// ---------------------------------------------------------------------------

/// Locks `payment_sat` from `submitter` until the task settles or expires, and
/// publishes the M3 compute envelope on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostTaskPayload {
    pub submitter: Address,
    pub auth: Auth,
    /// Must equal [`PostTaskPayload::derived_task_id`]; validated on admission so
    /// an actor cannot choose an arbitrary (or colliding) id.
    pub task_id: Hash,
    pub payment_sat: u64,
    /// Per-submitter sequence number, part of the task id derivation.
    pub nonce: u64,
    pub deadline_height: u64,
    pub compute_task: ComputeTask,
}

impl PostTaskPayload {
    /// Build and hybrid-sign a post. `task_id` is derived, never supplied.
    pub fn build(
        wallet: &Wallet,
        nonce: u64,
        payment_sat: u64,
        deadline_height: u64,
        compute_task: ComputeTask,
    ) -> Result<Self> {
        let submitter = wallet.address()?;
        let mut p = PostTaskPayload {
            submitter,
            auth: Auth::default(),
            task_id: [0u8; 32],
            payment_sat,
            nonce,
            deadline_height,
            compute_task,
        };
        p.task_id = p.derived_task_id();
        // Sign with the key bundle already in place; only the signature half is
        // excluded from the hash.
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn derived_task_id(&self) -> Hash {
        derive_task_id(&self.submitter, self.nonce, &self.compute_task.task_hash())
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_POST, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.submitter, &self.signing_hash())
    }

    /// The signing preimage: everything but the signature bundle.
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.submitter);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .u64le(self.payment_sat)
            .u64le(self.nonce)
            .u64le(self.deadline_height)
            .raw(&self.compute_task.serialize());
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let submitter: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let payment_sat = r.u64le()?;
        let nonce = r.u64le()?;
        let deadline_height = r.u64le()?;
        let compute_task = ComputeTask::from_reader(r)?;
        Ok(PostTaskPayload {
            submitter,
            auth,
            task_id,
            payment_sat,
            nonce,
            deadline_height,
            compute_task,
        })
    }
}

// ---------------------------------------------------------------------------
// ClaimTask
// ---------------------------------------------------------------------------

/// Reserves an open task for `worker` and locks `worker_deposit_sat`, which is
/// burned or slashed if the worker never delivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTaskPayload {
    pub worker: Address,
    pub auth: Auth,
    pub task_id: Hash,
    pub backend: ComputeBackend,
    pub worker_deposit_sat: u64,
}

impl ClaimTaskPayload {
    pub fn build(
        wallet: &Wallet,
        task_id: Hash,
        backend: ComputeBackend,
        worker_deposit_sat: u64,
    ) -> Result<Self> {
        let mut p = ClaimTaskPayload {
            worker: wallet.address()?,
            auth: Auth::default(),
            task_id,
            backend,
            worker_deposit_sat,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_CLAIM, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.worker, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.worker);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .u8(self.backend.to_wire())
            .u64le(self.worker_deposit_sat);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let worker: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let backend = ComputeBackend::from_wire(r.u8()?);
        let worker_deposit_sat = r.u64le()?;
        Ok(ClaimTaskPayload {
            worker,
            auth,
            task_id,
            backend,
            worker_deposit_sat,
        })
    }
}

// ---------------------------------------------------------------------------
// SubmitResult
// ---------------------------------------------------------------------------

/// Publishes the worker's result hash and M3 attestation, opening the dispute
/// window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitResultPayload {
    pub worker: Address,
    pub auth: Auth,
    pub task_id: Hash,
    pub result_hash: Hash,
    pub attestation: ComputeAttestation,
}

impl SubmitResultPayload {
    pub fn build(wallet: &Wallet, task_id: Hash, attestation: ComputeAttestation) -> Result<Self> {
        let mut p = SubmitResultPayload {
            worker: wallet.address()?,
            auth: Auth::default(),
            task_id,
            result_hash: attestation.result_hash,
            attestation,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_SUBMIT, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.worker, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.worker);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .fixed(&self.result_hash)
            .raw(&self.attestation.serialize());
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let worker: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let result_hash = r.fixed()?;
        let attestation = ComputeAttestation::from_reader(r)?;
        Ok(SubmitResultPayload {
            worker,
            auth,
            task_id,
            result_hash,
            attestation,
        })
    }
}

// ---------------------------------------------------------------------------
// Dispute
// ---------------------------------------------------------------------------

/// Challenges a submitted result. `challenger` locks a deposit that is burned if
/// the challenge fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputePayload {
    pub challenger: Address,
    pub auth: Auth,
    pub task_id: Hash,
    pub counter_result: Hash,
    pub counter_attestation: ComputeAttestation,
    pub challenge_deposit_sat: u64,
}

impl DisputePayload {
    pub fn build(
        wallet: &Wallet,
        task_id: Hash,
        counter_result: Hash,
        counter_attestation: ComputeAttestation,
        challenge_deposit_sat: u64,
    ) -> Result<Self> {
        let mut p = DisputePayload {
            challenger: wallet.address()?,
            auth: Auth::default(),
            task_id,
            counter_result,
            counter_attestation,
            challenge_deposit_sat,
        };
        p.auth.keys = Auth::keys_for(wallet)?;
        let msg = p.signing_hash();
        p.auth.sigs = Auth::sigs_for(wallet, &msg)?;
        Ok(p)
    }

    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_L2_DISPUTE, &[&self.body()])
    }

    pub fn verify_auth(&self) -> Result<()> {
        self.auth.verify_as(&self.challenger, &self.signing_hash())
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, false);
        w.into_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w, true);
        w.into_vec()
    }

    fn encode(&self, w: &mut Writer, with_sigs: bool) {
        w.fixed(&self.challenger);
        if with_sigs {
            self.auth.write_full(w);
        } else {
            self.auth.write_body(w);
        }
        w.fixed(&self.task_id)
            .fixed(&self.counter_result)
            .raw(&self.counter_attestation.serialize())
            .u64le(self.challenge_deposit_sat);
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let challenger: Address = r.fixed()?;
        let auth = Auth::read(r)?;
        let task_id = r.fixed()?;
        let counter_result = r.fixed()?;
        let counter_attestation = ComputeAttestation::from_reader(r)?;
        let challenge_deposit_sat = r.u64le()?;
        Ok(DisputePayload {
            challenger,
            auth,
            task_id,
            counter_result,
            counter_attestation,
            challenge_deposit_sat,
        })
    }
}

// ---------------------------------------------------------------------------
// Settle
// ---------------------------------------------------------------------------

/// The validator quorum's settlement decision. Not user-facing: it is produced
/// by the arbitrator set (the M5 committee) and authorized by its BLS aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlePayload {
    pub task_id: Hash,
    pub verdict: Verdict,
    /// The hash the verdict settles on — see [`VWC_HASH_EXPIRED`] for the
    /// pre-VWC convention.
    pub vwc_hash: Hash,
    /// BLS12-381 G2 aggregate signature over [`SettlePayload::signing_hash`].
    pub bls_sig: [u8; 96],
    /// One bit per validator (LSB = index 0) in the epoch's sorted set.
    pub signer_bitmap: Vec<u8>,
    /// Number of validators that signed. Must agree with the bitmap.
    pub signer_count: u32,
}

impl SettlePayload {
    pub fn signing_hash(&self) -> Hash {
        // Covers the decision only: not the signature, not the bitmap, not the
        // count. Those are evidence *of* the decision.
        let mut w = Writer::new();
        w.fixed(&self.task_id)
            .u8(self.verdict.to_wire())
            .fixed(&self.vwc_hash);
        sha256_dom(DOM_L2_SETTLE, &[w.as_slice()])
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&self.task_id)
            .u8(self.verdict.to_wire())
            .fixed(&self.vwc_hash)
            .raw(&self.bls_sig);
        w.u32le(self.signer_bitmap.len() as u32)
            .raw(&self.signer_bitmap)
            .u32le(self.signer_count);
        w.into_vec()
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let task_id = r.fixed()?;
        let verdict = Verdict::from_wire(r.u8()?)?;
        let vwc_hash = r.fixed()?;
        let bls_sig: [u8; 96] = r.fixed()?;
        let n = r.u32le()? as usize;
        if n > MAX_SIGNER_BITMAP_BYTES {
            return Err(Error::Malformed("signer bitmap over cap"));
        }
        if n > r.remaining() {
            return Err(Error::Malformed("signer bitmap exceeds buffer"));
        }
        let signer_bitmap = r.fixed_slice(n)?.to_vec();
        let signer_count = r.u32le()?;
        Ok(SettlePayload {
            task_id,
            verdict,
            vwc_hash,
            bls_sig,
            signer_bitmap,
            signer_count,
        })
    }
}

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Payload {
    Post(PostTaskPayload),
    Claim(ClaimTaskPayload),
    Submit(SubmitResultPayload),
    Dispute(DisputePayload),
    Settle(SettlePayload),
}

impl L2Payload {
    pub fn tx_type(&self) -> L2TxType {
        match self {
            L2Payload::Post(_) => L2TxType::PostTask,
            L2Payload::Claim(_) => L2TxType::ClaimTask,
            L2Payload::Submit(_) => L2TxType::SubmitResult,
            L2Payload::Dispute(_) => L2TxType::Dispute,
            L2Payload::Settle(_) => L2TxType::Settle,
        }
    }

    /// The verified actor for an authorization payload, or `None` for `Settle`,
    /// whose authorization is the BLS quorum rather than a single key.
    pub fn actor(&self) -> Option<Address> {
        match self {
            L2Payload::Post(p) => Some(p.submitter),
            L2Payload::Claim(p) => Some(p.worker),
            L2Payload::Submit(p) => Some(p.worker),
            L2Payload::Dispute(p) => Some(p.challenger),
            L2Payload::Settle(_) => None,
        }
    }

    pub fn signing_hash(&self) -> Hash {
        match self {
            L2Payload::Post(p) => p.signing_hash(),
            L2Payload::Claim(p) => p.signing_hash(),
            L2Payload::Submit(p) => p.signing_hash(),
            L2Payload::Dispute(p) => p.signing_hash(),
            L2Payload::Settle(p) => p.signing_hash(),
        }
    }

    /// Verify a single-actor authorization. `Settle` returns `Ok(())`: it carries
    /// no single signature, and its quorum check lives with the L2 state machine.
    pub fn verify_auth(&self) -> Result<()> {
        match self {
            L2Payload::Post(p) => p.verify_auth(),
            L2Payload::Claim(p) => p.verify_auth(),
            L2Payload::Submit(p) => p.verify_auth(),
            L2Payload::Dispute(p) => p.verify_auth(),
            L2Payload::Settle(_) => Ok(()),
        }
    }

    fn serialize_payload(&self) -> Vec<u8> {
        match self {
            L2Payload::Post(p) => p.serialize(),
            L2Payload::Claim(p) => p.serialize(),
            L2Payload::Submit(p) => p.serialize(),
            L2Payload::Dispute(p) => p.serialize(),
            L2Payload::Settle(p) => p.serialize(),
        }
    }

    fn from_reader(t: L2TxType, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match t {
            L2TxType::PostTask => L2Payload::Post(PostTaskPayload::from_reader(r)?),
            L2TxType::ClaimTask => L2Payload::Claim(ClaimTaskPayload::from_reader(r)?),
            L2TxType::SubmitResult => L2Payload::Submit(SubmitResultPayload::from_reader(r)?),
            L2TxType::Dispute => L2Payload::Dispute(DisputePayload::from_reader(r)?),
            L2TxType::Settle => L2Payload::Settle(SettlePayload::from_reader(r)?),
        })
    }
}

/// A versioned envelope around an L2 payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Transaction {
    pub version: u32,
    pub payload: L2Payload,
}

impl L2Transaction {
    pub const VERSION: u32 = 1;

    pub fn new(payload: L2Payload) -> Self {
        L2Transaction {
            version: Self::VERSION,
            payload,
        }
    }

    pub fn tx_type(&self) -> L2TxType {
        self.payload.tx_type()
    }

    pub fn fee_sat(&self) -> u64 {
        self.tx_type().fee_sat()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 + 1 + 64);
        w.u32le(self.version)
            .u8(self.tx_type().to_wire())
            .raw(&self.payload.serialize_payload());
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u32le()?;
        let t = L2TxType::from_wire(r.u8()?)?;
        let payload = L2Payload::from_reader(t, &mut r)?;
        r.expect_end()?;
        Ok(L2Transaction { version, payload })
    }

    /// Unique transaction id, used for replay protection.
    pub fn txid(&self) -> Hash {
        sha256_dom(DOM_L2_TXID, &[&self.serialize()])
    }
}

/// Serde identity of an L2 transaction is its **canonical binary encoding**
/// (Decision 6).
///
/// This exists so a whole `Block` can still be serialized, which the node's
/// chain export needs. Representing the JSON form as the binary bytes keeps a
/// single authority for what an L2 transaction is: the same encoding `txid`,
/// the signing hashes and the block-commitment path already use. A
/// field-by-field serde form would be a second encoding to keep in step with
/// the first — exactly the drift §15's canonical-encoding rule exists to
/// prevent. It also means an L2 payload stored in JSON is decoded through
/// `L2Transaction::deserialize`, so its bounds and validation apply there too.
impl serde::Serialize for L2Transaction {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.serialize()))
    }
}

impl<'de> serde::Deserialize<'de> for L2Transaction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        // Fully qualified: this module has its own `Result` alias and its own
        // `Error`, and both would otherwise shadow what serde's trait wants.
        let s = <String as serde::Deserialize>::deserialize(d)?;
        let bytes =
            hex::decode(&s).map_err(|e| <D::Error as serde::de::Error>::custom(e.to_string()))?;
        // Go through the canonical decoder, so a JSON-supplied L2 transaction
        // is held to exactly the rules a wire-supplied one is.
        L2Transaction::deserialize(&bytes).map_err(<D::Error as serde::de::Error>::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(seed: u8) -> Wallet {
        Wallet::from_private_key_bytes(&[seed; 32], "l2-test").unwrap()
    }

    fn task(submit_height: u64, expiry: u64) -> ComputeTask {
        ComputeTask {
            task_id: [0x11u8; 32],
            ir_hash: [0x22u8; 32],
            input_hash: [0x33u8; 32],
            required_memory_bytes: 4 * 1024 * 1024,
            backend_hint: ComputeBackend::Gpu,
            reward_sat: 1_000_000,
            expiry_height: expiry,
            submit_height,
        }
    }

    fn post(seed: u8, nonce: u64, deadline: u64) -> PostTaskPayload {
        PostTaskPayload::build(&wallet(seed), nonce, 5_000_000, deadline, task(1, deadline))
            .unwrap()
    }

    fn attest(w: &Wallet, task_id: Hash, result: Hash) -> ComputeAttestation {
        let mut a = ComputeAttestation {
            task_id,
            result_hash: result,
            backend: ComputeBackend::Gpu,
            worker_address: w.address().unwrap(),
            attest_height: 10,
            signature: vec![],
        };
        a.signature = w.sign_digest(&a.attest_hash()).unwrap().to_vec();
        a
    }

    // --- wire codes -----------------------------------------------------

    #[test]
    fn type_codes_round_trip_and_are_distinct_from_l1() {
        for t in [
            L2TxType::PostTask,
            L2TxType::ClaimTask,
            L2TxType::SubmitResult,
            L2TxType::Dispute,
            L2TxType::Settle,
        ] {
            assert_eq!(L2TxType::from_wire(t.to_wire()).unwrap(), t);
            assert!(t.to_wire() >= 0x10, "L2 codes must not collide with L1");
            assert!(!t.name().is_empty());
        }
        assert!(L2TxType::from_wire(0).is_err(), "L1 STANDARD is not L2");
        assert!(L2TxType::from_wire(0x99).is_err());
        assert!(Verdict::from_wire(3).is_err());
    }

    #[test]
    fn fee_mapping_is_the_decided_d3_schedule() {
        assert_eq!(L2TxType::PostTask.fee_sat(), 5_000);
        assert_eq!(L2TxType::ClaimTask.fee_sat(), 2_000);
        assert_eq!(L2TxType::SubmitResult.fee_sat(), 2_000);
        assert_eq!(L2TxType::Dispute.fee_sat(), 10_000);
        assert_eq!(L2TxType::Settle.fee_sat(), 20_000);
    }

    // --- task id --------------------------------------------------------

    #[test]
    fn task_id_binds_submitter_nonce_and_task() {
        let w = wallet(1);
        let t = task(1, 100);
        let submitter = w.address().unwrap();
        let a = derive_task_id(&submitter, 1, &t.task_hash());
        assert_eq!(a, derive_task_id(&submitter, 1, &t.task_hash()));
        assert_ne!(a, derive_task_id(&submitter, 2, &t.task_hash()));
        assert_ne!(
            a,
            derive_task_id(&wallet(2).address().unwrap(), 1, &t.task_hash())
        );
        let mut t2 = t.clone();
        t2.reward_sat += 1;
        assert_ne!(a, derive_task_id(&submitter, 1, &t2.task_hash()));
    }

    #[test]
    fn a_built_post_derives_and_signs_consistently() {
        let p = post(3, 7, 50);
        assert_eq!(p.task_id, p.derived_task_id());
        assert_eq!(p.submitter, wallet(3).address().unwrap());
        p.verify_auth().unwrap();
    }

    // --- signing hash coverage -----------------------------------------

    #[test]
    fn signing_hash_covers_every_consensus_field() {
        let base = post(4, 1, 100);
        let mut changed = base.clone();
        changed.payment_sat += 1;
        assert_ne!(base.signing_hash(), changed.signing_hash());

        let mut changed = base.clone();
        changed.deadline_height += 1;
        assert_ne!(base.signing_hash(), changed.signing_hash());

        let mut changed = base.clone();
        changed.submitter = [9u8; 20];
        assert_ne!(base.signing_hash(), changed.signing_hash());

        let mut changed = base.clone();
        changed.compute_task.reward_sat += 1;
        assert_ne!(base.signing_hash(), changed.signing_hash());
    }

    #[test]
    fn signing_hash_excludes_the_signature_but_includes_the_keys() {
        // Exactly the L1 sighash discipline: re-signing must not change the
        // message, but a swapped key bundle must.
        let base = post(5, 1, 100);
        let mut resigned = base.clone();
        resigned.auth.sigs = Auth::sign(&wallet(5), &base.signing_hash()).unwrap().sigs;
        assert_eq!(base.signing_hash(), resigned.signing_hash());

        let mut rekeyed = base.clone();
        rekeyed.auth.keys = Auth::sign(&wallet(6), &[0u8; 32]).unwrap().keys;
        assert_ne!(base.signing_hash(), rekeyed.signing_hash());
    }

    #[test]
    fn a_tampered_payload_fails_authorization() {
        let mut p = post(6, 1, 100);
        p.payment_sat += 1; // signature no longer matches
        assert!(p.verify_auth().is_err());

        // Signing as one wallet while claiming another actor's address is
        // rejected as a wrong-address case, not a signature failure.
        let w = wallet(7);
        let mut q = post(8, 1, 100);
        let msg = {
            q.submitter = w.address().unwrap();
            q.auth.keys = Auth::sign(&w, &[0u8; 32]).unwrap().keys;
            q.signing_hash()
        };
        q.auth.sigs = Auth::sign(&w, &msg).unwrap().sigs;
        assert!(q.verify_auth().is_ok());
        q.submitter = wallet(9).address().unwrap();
        assert!(matches!(q.verify_auth(), Err(Error::WrongAddress)));
    }

    // --- round trips ----------------------------------------------------

    #[test]
    fn every_payload_round_trips_and_ids_are_stable() {
        let w = wallet(10);
        let p = post(10, 1, 100);
        let t = p.task_id;
        let result = [0xAAu8; 32];
        let att = attest(&w, t, result);
        let payloads = vec![
            L2Payload::Post(p.clone()),
            L2Payload::Claim(ClaimTaskPayload::build(&w, t, ComputeBackend::Cpu, 1_000).unwrap()),
            L2Payload::Submit(SubmitResultPayload::build(&w, t, att.clone()).unwrap()),
            L2Payload::Dispute(
                DisputePayload::build(&w, t, [0xBBu8; 32], att.clone(), 2_000).unwrap(),
            ),
            L2Payload::Settle(SettlePayload {
                task_id: t,
                verdict: Verdict::Correct,
                vwc_hash: result,
                bls_sig: [0x7Fu8; 96],
                signer_bitmap: vec![0b0000_0111],
                signer_count: 3,
            }),
        ];
        for payload in payloads {
            let tx = L2Transaction::new(payload);
            let bytes = tx.serialize();
            let back = L2Transaction::deserialize(&bytes).unwrap();
            assert_eq!(back, tx, "{} did not round-trip", tx.tx_type().name());
            assert_eq!(back.txid(), tx.txid());
            assert_eq!(back.tx_type(), tx.tx_type());
            tx.payload.verify_auth().unwrap();
        }
    }

    #[test]
    fn deserialize_rejects_trailing_bytes_and_unknown_types() {
        let tx = L2Transaction::new(L2Payload::Claim(
            ClaimTaskPayload::build(&wallet(11), [1u8; 32], ComputeBackend::Npu, 1).unwrap(),
        ));
        let mut bytes = tx.serialize();
        bytes.push(0);
        assert!(matches!(
            L2Transaction::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));

        let mut bad = tx.serialize();
        bad[4] = 0x42; // overwrite the type byte
        assert!(L2Transaction::deserialize(&bad).is_err());
    }

    #[test]
    fn settle_hash_covers_the_verdict_and_task_not_the_evidence() {
        let base = SettlePayload {
            task_id: [1u8; 32],
            verdict: Verdict::Correct,
            vwc_hash: [2u8; 32],
            bls_sig: [0u8; 96],
            signer_bitmap: vec![],
            signer_count: 0,
        };
        let mut other_verdict = base.clone();
        other_verdict.verdict = Verdict::Fraudulent;
        assert_ne!(base.signing_hash(), other_verdict.signing_hash());

        let mut other_task = base.clone();
        other_task.task_id = [3u8; 32];
        assert_ne!(base.signing_hash(), other_task.signing_hash());

        // Evidence fields are not part of the signed decision.
        let mut other_sig = base.clone();
        other_sig.bls_sig = [9u8; 96];
        other_sig.signer_bitmap = vec![0xFF];
        other_sig.signer_count = 8;
        assert_eq!(base.signing_hash(), other_sig.signing_hash());
    }

    #[test]
    fn a_settle_bitmap_prefix_is_bounded_before_allocating() {
        // Declares 1 GiB of bitmap with nothing behind it.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[1u8; 32]); // task_id
        bytes.push(0); // verdict
        bytes.extend_from_slice(&[0u8; 32]); // vwc_hash
        bytes.extend_from_slice(&[0u8; 96]); // bls sig
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // bitmap len
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            SettlePayload::from_reader(&mut r),
            Err(Error::Malformed(_))
        ));
    }
}
