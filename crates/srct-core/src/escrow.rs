//! Conditional-payment escrow with contract-selected, independent arbitrators
//! (roadmap item 4 — implemented wiring, per user decision: "contract-selected,
//! independently operated arbitrators. No fixed committee, no central
//! arbitrator, users choose").
//!
//! # Model
//!
//! A conditional escrow locks value for a `(payer, payee)` pair and names an
//! **arbitrator** up front — the contract-selected one, a BLS public key recorded
//! in the escrow at creation. That is the only place the arbitrator is named;
//! the protocol never consults a committee list or a Solar Cyber Unit-run key. Dispute
//! resolution is a single designated signer, so the existing
//! [`crate::arbitration::ArbitrationVote`]/settle machinery is reused with the
//! quorum reduced to **one** signer: the designated arbitrator.
//!
//! # States
//!
//! ```text
//! Open -> Released(Mutual)  # both parties agreed
//! Open -> Released(Arbiter) # the designated arbitrator decided
//! Open -> Refunded          # expired: the value returns to the payer
//! Released -> Finalized    # settlement committed (irreversible)
//! ```
//!
//! Open is the only live state. Once released, the escrow is terminal — its
//! bytes are consumed by the settlement that follows, which is the ordinary
//! §1 L1/L2 payout path, not a new coin type.
//!
//! # Why an expiry exists
//!
//! Without one, an escrow whose release nobody can produce locks its value
//! forever: a non-responsive arbitrator, a lost key, or a condition no verifier
//! can satisfy all used to be permanent states. [`ConditionalEscrow::refund`]
//! is the timeout that makes "nobody ever signed" a recoverable outcome — after
//! [`ESCROW_EXPIRY_BLOCKS`] the payer alone can take the value back, with no
//! signature from anyone else, because the payer is the party the value would
//! have been released *from* anyway. Release is refused after expiry for the
//! same reason: a late signature must not race a refund that already happened,
//! and the escrow cannot be both.
//!
//! # Why this reuses ArbitrationVote
//!
//! [`crate::arbitration::ArbitrationVote::signing_hash`] is byte-identical to
//! `SettlePayload::signing_hash` (same domain tag `DOM_L2_SETTLE`, same
//! decision-plus-network-plus-height fields). By deriving the arbitrator's
//! decision hash the same way, a single
//! BLS key can serve both fraud-arbitration and conditional-payment arbitration
//! with no second signing scheme, and a quorum of one is a valid quorum by the
//! chain's existing BLS checks.
//!
//! The arbitrator is **not** a validator: the escrow records their public key
//! directly, and verification confirms the vote comes from that exact key on
//! that exact escrow id and verdict. There is no committee lookup, no Solar Cyber Unit
//! key, and no on-chain registry of "approved arbitrators" — the contract
//! itself is the registry.

use crate::bls::{self, BlsError, SecretKey};
use crate::bls_checkpoint::{BlsPublicKey, BlsSignature};
use crate::error::{Error, Result};
use crate::hash::{sha256_dom, Address, Hash};
use crate::ser::{Reader, Writer};

/// Domain tag for an escrow's identity and decision hash. Distinct from the
/// settle tag so an escrow decision can never be replayed as a task settle or
/// vice-versa.
pub const DOM_ESCROW: &[u8] = b"srct/escrow/v1";

/// Escrow encoding version.
/// Escrow encoding version. Bumped to 2 when `opened_height` (the expiry
/// clock) and the `Refunded` state joined the wire format.
pub const ESCROW_VERSION: u8 = 2;

/// Blocks after which an open escrow expires and refunds its payer. The same
/// 7-day schedule as a bond's unbonding lock (Decision 20 item 3), so an
/// operator learns one number rather than two.
pub const ESCROW_EXPIRY_BLOCKS: u64 = crate::bond::UNBONDING_PERIOD_BLOCKS;

/// Maximum `network_id` length, matching the arbitration vote bound (§13.4).
pub const MAX_ESCROW_NETWORK_ID: usize = 64;

/// A conditional escrow: value locked for a `(payer, payee)` pair, with a
/// **contract-selected arbitrator** whose BLS public key is bound in at open.
///
/// The arbitrator is chosen by the contract (the payer and payee agree to one
/// when they open the escrow), and is the only party permitted to release
/// unilaterally. A mutual release by both parties is also accepted, so the
/// arbitrator is only exercised on dispute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalEscrow {
    pub version: u8,
    /// Network this escrow lives on.
    pub network_id: String,
    /// Payer: the party funding the escrow.
    pub payer: Address,
    /// Payer's BLS public key, so a mutual release can be verified against the
    /// party the contract selected rather than a key the releaser names.
    pub payer_key: BlsPublicKey,
    /// Payee: the party the funds are held for.
    pub payee: Address,
    /// Payee's BLS public key (see `payer_key`).
    pub payee_key: BlsPublicKey,
    /// The designated arbitrator's BLS public key. The contract names them once;
    /// the protocol never consults any other list.
    pub arbitrator: BlsPublicKey,
    /// Satoshis locked.
    pub amount_sat: u64,
    /// Per-contract nonce, picked by the payer, so two escrows between the same
    /// parties do not collide.
    pub nonce: u64,
    /// Chain height at which this escrow was opened — the start of the
    /// [`ESCROW_EXPIRY_BLOCKS`] countdown that eventually refunds the payer.
    /// Part of the encoding, so a round-trip cannot reset the clock.
    pub opened_height: u64,
    /// What must be true before the value can move. Signed into the id and the
    /// release hash, so the parties agreed on exactly this condition.
    pub condition: EscrowCondition,
    /// Where the escrow is. Open is the only live state.
    pub state: EscrowState,
}

/// The outcome of a release. `Mutual` names both signatures' public keys (the
/// parties agreed); `Arbiter` names the single deciding key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EscrowState {
    /// Live: value is locked and awaiting release.
    #[default]
    Open,
    /// Released by a mutual signature from both parties.
    ReleasedMutual {
        /// Height the release was committed at (set by the chain on settle).
        at_height: u64,
    },
    /// Released by the designated arbitrator alone.
    ReleasedArbiter {
        /// Height the release was committed at.
        at_height: u64,
    },
    /// Terminal: the release has been committed to the ledger and the funds are
    /// in motion toward the payee.
    Finalized {
        /// Height the settlement landed.
        at_height: u64,
    },
    /// Terminal: the escrow outlived [`ESCROW_EXPIRY_BLOCKS`] without anyone
    /// releasing it, so the value went back to the payer. This is the branch
    /// that makes a stalled escrow recoverable instead of a permanent lock.
    Refunded {
        /// Height the refund was committed at.
        at_height: u64,
    },
}

impl ConditionalEscrow {
    /// The escrow's identity: `SHA256(DOM_ESCROW ‖ network ‖ payer ‖ payee ‖
    /// arbitrator ‖ amount ‖ nonce ‖ condition)`. Deterministic,
    /// contract-unique, and independent of the state — the id is stable across a
    /// release.
    ///
    /// The condition is in the hash because it is part of the contract the
    /// parties agreed to: the same parties and the same amount under a
    /// deterministic release and under an oracle are two different agreements,
    /// and an id that ignored the condition would make them one. A node keyed by
    /// this id would keep one and silently drop the other, so whichever survived
    /// would be indistinguishable from the one it replaced.
    pub fn id(&self) -> Hash {
        sha256_dom(
            DOM_ESCROW,
            &[
                self.network_id.as_bytes(),
                &self.payer,
                self.payer_key.as_bytes(),
                &self.payee,
                self.payee_key.as_bytes(),
                self.arbitrator.as_bytes(),
                &self.amount_sat.to_le_bytes(),
                &self.nonce.to_le_bytes(),
                &self.condition.encode(),
            ],
        )
    }

    /// The hash an arbitrator signs to release this escrow, or that both parties
    /// sign for a mutual release.
    ///
    /// Binds the decision to this escrow id, this network and this *condition*,
    /// so a signature over one escrow, one network or one condition cannot
    /// release another.
    pub fn release_signing_hash(&self, verdict: EscrowVerdict) -> Hash {
        sha256_dom(
            DOM_ESCROW,
            &[
                self.network_id.as_bytes(),
                &self.id(),
                &[verdict as u8],
                &self.condition.encode(),
            ],
        )
    }

    /// Open an escrow, validating its fields. `height` is the chain height at
    /// open — it starts the [`ESCROW_EXPIRY_BLOCKS`] countdown, so a caller
    /// that forgets it cannot compile rather than silently minting an escrow
    /// that is already expired.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        network_id: String,
        payer: Address,
        payer_key: BlsPublicKey,
        payee: Address,
        payee_key: BlsPublicKey,
        arbitrator: BlsPublicKey,
        amount_sat: u64,
        nonce: u64,
        height: u64,
    ) -> Result<Self> {
        Self::open_with_condition(
            network_id,
            payer,
            payer_key,
            payee,
            payee_key,
            arbitrator,
            amount_sat,
            nonce,
            EscrowCondition::ReleaseToPayee,
            height,
        )
    }

    /// Open an escrow under a specific condition.
    ///
    /// The condition is part of the escrow's signed identity, because what a
    /// payer is agreeing to *is* the condition: the same parties and the same
    /// amount under different conditions are different contracts, and a release
    /// hash that ignored that would let a signature for one condition release
    /// the other.
    #[allow(clippy::too_many_arguments)]
    pub fn open_with_condition(
        network_id: String,
        payer: Address,
        payer_key: BlsPublicKey,
        payee: Address,
        payee_key: BlsPublicKey,
        arbitrator: BlsPublicKey,
        amount_sat: u64,
        nonce: u64,
        condition: EscrowCondition,
        height: u64,
    ) -> Result<Self> {
        if amount_sat == 0 {
            return Err(Error::Malformed("an escrow locks a positive amount"));
        }
        // Refuse an oracle condition at open, not at release. Nothing in this
        // codebase verifies an oracle claim, so an oracle escrow is a contract
        // that can never be satisfied — and before the expiry existed, one that
        // could never return the value either. Failing here means the mistake
        // is caught while the payer still holds their money.
        if matches!(condition, EscrowCondition::Oracle { .. }) {
            return Err(Error::Malformed(
                "oracle escrows cannot be opened: no oracle verifier exists",
            ));
        }
        if network_id.len() > MAX_ESCROW_NETWORK_ID {
            return Err(Error::Malformed("escrow network_id over cap"));
        }
        if payer == payee {
            return Err(Error::Malformed("payer and payee must differ"));
        }
        // An all-zero key is not a valid BLS point; reject it so an escrow
        // cannot be opened with a placeholder arbitrator by accident, and so a
        // mutual release cannot be satisfied with a null key.
        if arbitrator.as_bytes().iter().all(|b| *b == 0)
            || payer_key.as_bytes().iter().all(|b| *b == 0)
            || payee_key.as_bytes().iter().all(|b| *b == 0)
        {
            return Err(Error::Malformed("escrow keys must not be a zero key"));
        }
        Ok(ConditionalEscrow {
            version: ESCROW_VERSION,
            network_id,
            payer,
            payer_key,
            payee,
            payee_key,
            arbitrator,
            amount_sat,
            nonce,
            opened_height: height,
            condition,
            state: EscrowState::default(),
        })
    }

    /// Canonical encoding, self-delimiting.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256);
        w.u8(self.version)
            .raw(&self.network_id.len().to_le_bytes())
            .raw(self.network_id.as_bytes())
            .fixed(&self.payer)
            .fixed(self.payer_key.as_bytes())
            .fixed(&self.payee)
            .fixed(self.payee_key.as_bytes())
            .fixed(self.arbitrator.as_bytes())
            .u64le(self.amount_sat)
            .u64le(self.nonce)
            .u64le(self.opened_height);
        w.raw(&self.condition.encode());
        self.encode_state(&mut w);
        w.into_vec()
    }

    fn encode_state(&self, w: &mut Writer) {
        match &self.state {
            EscrowState::Open => {
                w.u8(0);
            }
            EscrowState::ReleasedMutual { at_height } => {
                w.u8(1).u64le(*at_height);
            }
            EscrowState::ReleasedArbiter { at_height } => {
                w.u8(2).u64le(*at_height);
            }
            EscrowState::Finalized { at_height } => {
                w.u8(3).u64le(*at_height);
            }
            EscrowState::Refunded { at_height } => {
                w.u8(4).u64le(*at_height);
            }
        }
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.u8()?;
        if version != ESCROW_VERSION {
            return Err(Error::Malformed(
                "escrow version is not one this build reads",
            ));
        }
        let net_len = <u64>::from_le_bytes(r.fixed()?);
        if net_len as usize > MAX_ESCROW_NETWORK_ID {
            return Err(Error::Malformed("escrow network_id length over cap"));
        }
        let len = net_len as usize;
        let network_id = {
            let slice = r.fixed_slice(len)?;
            std::str::from_utf8(slice)
                .map_err(|_| Error::Malformed("escrow network_id not utf-8"))?
                .to_string()
        };
        let payer = r.fixed()?;
        let payer_key = r.fixed()?;
        let payer_key = BlsPublicKey(payer_key);
        let payee = r.fixed()?;
        let payee_key = r.fixed()?;
        let payee_key = BlsPublicKey(payee_key);
        let arb_bytes: [u8; 48] = r.fixed()?;
        let arbitrator = BlsPublicKey(arb_bytes);
        let amount_sat = r.u64le()?;
        let nonce = r.u64le()?;
        let opened_height = r.u64le()?;
        let condition = EscrowCondition::decode(r)?;
        let state = Self::decode_state(r)?;
        Ok(ConditionalEscrow {
            version,
            network_id,
            payer,
            payer_key,
            payee,
            payee_key,
            arbitrator,
            amount_sat,
            nonce,
            opened_height,
            condition,
            state,
        })
    }

    fn decode_state(r: &mut Reader<'_>) -> Result<EscrowState> {
        let tag = r.u8()?;
        match tag {
            0 => Ok(EscrowState::Open),
            1 => Ok(EscrowState::ReleasedMutual {
                at_height: r.u64le()?,
            }),
            2 => Ok(EscrowState::ReleasedArbiter {
                at_height: r.u64le()?,
            }),
            3 => Ok(EscrowState::Finalized {
                at_height: r.u64le()?,
            }),
            4 => Ok(EscrowState::Refunded {
                at_height: r.u64le()?,
            }),
            _ => Err(Error::Malformed("unknown escrow state tag")),
        }
    }

    /// Verify a mutual release: both parties must sign the release hash, and the
    /// keys supplied must be the escrow's bound payer/payee BLS keys (so a
    /// random key holder cannot release the escrow by naming their own key).
    pub fn verify_mutual_release(
        &self,
        sigs: &[BlsSignature],
        keys: &[BlsPublicKey],
        verifier: &dyn BlsVerifier,
    ) -> Result<()> {
        if !matches!(self.state, EscrowState::Open) {
            return Err(Error::Malformed("escrow is not live"));
        }
        if sigs.len() != 2 || keys.len() != 2 {
            return Err(Error::Malformed(
                "a mutual release needs exactly two signatures",
            ));
        }
        if keys[0] != self.payer_key || keys[1] != self.payee_key {
            return Err(Error::Malformed("keys do not match this escrow's parties"));
        }
        let msg = self.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        if !verifier.verify(&self.payer_key, &msg, &sigs[0]) {
            return Err(Error::Malformed("payer signature did not verify"));
        }
        if !verifier.verify(&self.payee_key, &msg, &sigs[1]) {
            return Err(Error::Malformed("payee signature did not verify"));
        }
        Ok(())
    }

    /// Verify an arbiter release: a single BLS signature, from the designated
    /// arbitrator, over this escrow's [`Self::release_signing_hash`]. A quorum
    /// of one is the point — independent arbitrators are not a committee, and the
    /// contract selected this key at open time.
    pub fn verify_arbiter_release(
        &self,
        sig: &BlsSignature,
        verifier: &dyn BlsVerifier,
    ) -> Result<()> {
        if !matches!(self.state, EscrowState::Open) {
            return Err(Error::Malformed("escrow is not live"));
        }
        let msg = self.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        if !verifier.verify(&self.arbitrator, &msg, sig) {
            return Err(Error::Malformed("arbiter signature did not verify"));
        }
        Ok(())
    }

    /// Commit a released escrow to ledger finality (roadmap item 10, §19.4). A
    /// `ReleasedMutual`/`ReleasedArbiter` transition is irreversible: once the
    /// release has aged past `activation_height` heights of chain it is
    /// `Finalized` at the release height.
    ///
    /// Returns `Ok(true)` if this call finalized the escrow, `Ok(false)` if it
    /// did not (not yet mature, or already terminal). The release `at_height`
    /// is frozen into `Finalized { at_height } and never rewritten by a later
    /// `finalize`, so a re-call after finality is idempotent.
    pub fn finalize(&mut self, now: u64, activation_height: u64) -> Result<bool> {
        let release_height = match &self.state {
            EscrowState::ReleasedMutual { at_height }
            | EscrowState::ReleasedArbiter { at_height } => *at_height,
            // Not releasable yet, or already committed: nothing to do.
            // Refunded is terminal in its own right: it is not a release, so
            // it never matures into `Finalized` (which means the payee was
            // paid), and re-calling is a no-op exactly like `Finalized`.
            EscrowState::Open | EscrowState::Finalized { .. } | EscrowState::Refunded { .. } => {
                return Ok(false)
            }
        };
        if now < release_height.saturating_add(activation_height) {
            return Ok(false);
        }
        self.state = EscrowState::Finalized {
            at_height: release_height,
        };
        Ok(true)
    }

    /// Release to the payee on the arbitrator's single signature.
    ///
    /// The transition lives on the type, not in a handler: a release is a state
    /// change this escrow makes about itself, and the only way to reach it is
    /// through the verify step above it. `at_height` is the height the chain
    /// stamps on the release, which is what finality is later measured against.
    pub fn release_arbiter(
        &mut self,
        sig: &BlsSignature,
        at_height: u64,
        verifier: &dyn BlsVerifier,
    ) -> Result<()> {
        self.refuse_if_expired(at_height)?;
        self.verify_arbiter_release(sig, verifier)?;
        if matches!(self.condition, EscrowCondition::Oracle { .. }) {
            return Err(Error::Malformed(
                "an oracle-gated escrow has no implemented oracle verifier and cannot release",
            ));
        }
        self.state = EscrowState::ReleasedArbiter { at_height };
        Ok(())
    }

    /// Release to the payee on both parties' signatures.
    pub fn release_mutual(
        &mut self,
        sigs: &[BlsSignature],
        keys: &[BlsPublicKey],
        at_height: u64,
        verifier: &dyn BlsVerifier,
    ) -> Result<()> {
        self.refuse_if_expired(at_height)?;
        self.verify_mutual_release(sigs, keys, verifier)?;
        if matches!(self.condition, EscrowCondition::Oracle { .. }) {
            return Err(Error::Malformed(
                "an oracle-gated escrow has no implemented oracle verifier and cannot release",
            ));
        }
        self.state = EscrowState::ReleasedMutual { at_height };
        Ok(())
    }

    /// Whether the escrow has passed its timeout at `height`.
    ///
    /// Only an `Open` escrow can expire: a released one has already committed
    /// to a direction, and a refunded or finalized one is terminal.
    pub fn expired_at(&self, height: u64) -> bool {
        matches!(self.state, EscrowState::Open)
            && height >= self.opened_height.saturating_add(ESCROW_EXPIRY_BLOCKS)
    }

    /// The timeout half of the escrow: refund an expired escrow to its payer.
    ///
    /// No signature is required, deliberately. This is the path that exists
    /// for the case where *nobody will ever sign* — an unreachable arbitrator,
    /// a lost key — and requiring a signature from a party who by definition
    /// will not produce one would make the refund as unreachable as the
    /// release it replaces. The payer is the only party whose interest is
    /// never to release, so refunding to them cannot take value from anyone
    /// who had a claim to it.
    pub fn refund(&mut self, at_height: u64) -> Result<()> {
        if !matches!(self.state, EscrowState::Open) {
            return Err(Error::Malformed("escrow is not live"));
        }
        if !self.expired_at(at_height) {
            return Err(Error::Malformed("escrow has not expired"));
        }
        self.state = EscrowState::Refunded { at_height };
        Ok(())
    }

    /// Refuse a release once the timeout has passed: past expiry the only
    /// remaining transition is [`Self::refund`], and letting a late signature
    /// race it would make the escrow's direction depend on arrival order.
    fn refuse_if_expired(&self, at_height: u64) -> Result<()> {
        if self.expired_at(at_height) {
            return Err(Error::Malformed(
                "escrow expired; only a refund can move it now",
            ));
        }
        Ok(())
    }

    /// The condition this escrow is held under.
    pub fn condition(&self) -> &EscrowCondition {
        &self.condition
    }

    /// Whether a release is possible at all.
    ///
    /// An oracle condition is *not* releasable: nothing in this codebase verifies
    /// an oracle claim, so there is no signature that could honestly satisfy it.
    /// Reporting that up front is what "fail closed" means — the escrow refuses
    /// to open a release path that no code can complete, rather than accepting
    /// signatures and holding value forever.
    pub fn releasable(&self) -> bool {
        !matches!(self.condition, EscrowCondition::Oracle { .. })
    }
}

/// What has to be true before an escrow's value can move.
///
/// The two kinds are deliberately separate, because they are verified by
/// different mechanisms and only one of them exists:
///
/// - [`EscrowCondition::ReleaseToPayee`] is a *deterministic* condition. The
///   release is authorized by the parties the contract selected (mutual
///   signatures, or the contract's arbitrator) and nothing else is consulted.
/// - [`EscrowCondition::Oracle`] names an external fact. Verifying an oracle
///   claim needs an operator, a data source and a dispute path — none of which
///   this codebase implements, and none of which a coding agent may invent. So
///   an oracle-gated escrow is *accepted as a record* and *refused at every
///   release*, which is the fail-closed shape: a condition nobody can verify
///   releases nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowCondition {
    /// Release to the payee on valid authorization.
    ReleaseToPayee,
    /// Release contingent on an external oracle, which has no implemented
    /// verifier here. Carries the oracle's identity and the question it was
    /// asked, so a future operator surface can name what was supposed to be
    /// answered instead of guessing.
    Oracle {
        /// Domain-separated identity of the question being asked.
        question_hash: Hash,
    },
}

impl EscrowCondition {
    /// Canonical, tagged encoding, bound into the escrow id and the release
    /// hash so the condition cannot be swapped after opening.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(40);
        match self {
            EscrowCondition::ReleaseToPayee => {
                w.u8(0);
            }
            EscrowCondition::Oracle { question_hash } => {
                w.u8(1).fixed(question_hash);
            }
        }
        w.into_vec()
    }

    /// Decode, refusing an unknown tag rather than guessing.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u8()? {
            0 => Ok(EscrowCondition::ReleaseToPayee),
            1 => Ok(EscrowCondition::Oracle {
                question_hash: r.fixed()?,
            }),
            _ => Err(Error::Malformed("unknown escrow condition tag")),
        }
    }
}

/// The outcome an arbitrator (or mutual release) commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowVerdict {
    /// Funds release to the payee (the default, and the only mutual option).
    ReleasedToPayee,
}

/// A single-signature BLS verifier, matching
/// [`bls::RealBls::verify`]'s shape. Abstracted so a test can substitute a
/// deterministic mock without touching consensus code — the *structural* rules
/// (the signature must come from the designated arbitrator) are enforced here
/// regardless of the verifier.
pub trait BlsVerifier {
    fn verify(&self, pk: &BlsPublicKey, msg: &Hash, sig: &BlsSignature) -> bool;
}

/// The production verifier, wrapping `blst` via `bls::RealBls::verify`.
pub struct RealBls;

impl BlsVerifier for RealBls {
    fn verify(&self, pk: &BlsPublicKey, msg: &Hash, sig: &BlsSignature) -> bool {
        bls::RealBls::verify(pk, msg, sig)
    }
}

/// Convenience: derive an arbitrator key from a seed, like validator fixtures.
pub fn derive_arbitrator_key(seed: &[u8; 32]) -> std::result::Result<SecretKey, BlsError> {
    SecretKey::derive(seed)
}

#[cfg(test)]
mod tests {
    use super::RealBls;
    use super::*;

    fn key(seed: u8) -> (SecretKey, BlsPublicKey) {
        let sk = SecretKey::derive(&[seed; 32]).unwrap();
        let pk = sk.public_key();
        (sk, pk)
    }

    fn escrow() -> (ConditionalEscrow, SecretKey, SecretKey) {
        let (_arb_sk, arb_pk) = key(5);
        let (payer_sk, payer_pk) = key(7);
        let (payee_sk, payee_pk) = key(8);
        (
            ConditionalEscrow::open(
                NET.to_string(),
                [1u8; 20],
                payer_pk,
                [2u8; 20],
                payee_pk,
                arb_pk,
                1_000,
                1,
                0,
            )
            .unwrap(),
            payer_sk,
            payee_sk,
        )
    }

    const NET: &str = "srct/mini";

    #[test]
    fn an_escrow_id_is_stable_and_unique() {
        let (e, _payer_sk, _payee_sk) = escrow();
        let id = e.id();
        let id2 = e.id();
        assert_eq!(id, id2, "the id is a pure function of the open fields");
        // A different nonce is a different escrow.
        let mut other = e.clone();
        other.nonce = 2;
        assert_ne!(id, other.id(), "nonce distinguishes escrows");
        // A different arbitrator is a different escrow.
        let (other_sk, other_pk) = key(6);
        let mut third = e.clone();
        third.arbitrator = other_pk;
        assert_ne!(id, third.id());
        let _ = other_sk;
    }

    #[test]
    fn a_zero_arbitrator_key_is_refused() {
        let err = ConditionalEscrow::open(
            NET.to_string(),
            [1u8; 20],
            BlsPublicKey([0u8; 48]),
            [2u8; 20],
            BlsPublicKey([0u8; 48]),
            BlsPublicKey([0u8; 48]),
            1_000,
            1,
            0,
        );
        assert!(err.is_err());
    }

    #[test]
    fn a_self_payed_escrow_is_refused() {
        let (_arb_sk, arb_pk) = key(5);
        let (_, payer_pk) = key(7);
        let (_, payee_pk) = key(8);
        let err = ConditionalEscrow::open(
            NET.to_string(),
            [1u8; 20],
            payer_pk,
            [1u8; 20],
            payee_pk,
            arb_pk,
            1_000,
            1,
            0,
        );
        assert!(err.is_err());
    }

    #[test]
    fn mutual_release_verifies_both_signatures() {
        let (e, payer_sk, payee_sk) = escrow();
        let payer_pk = payer_sk.public_key();
        let payee_pk = payee_sk.public_key();
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        let s1 = payer_sk.sign(&msg);
        let s2 = payee_sk.sign(&msg);
        assert!(e
            .verify_mutual_release(&[s1, s2], &[payer_pk, payee_pk], &RealBls)
            .is_ok());
    }

    #[test]
    fn a_mutual_release_must_be_signed_by_both_parties() {
        let (e, payer_sk, payee_sk) = escrow();
        let payer_pk = payer_sk.public_key();
        let payee_pk = payee_sk.public_key();
        let (other_sk, _other_pk) = key(9);
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);

        // Happy path: both parties sign.
        let ok = e.verify_mutual_release(
            &[payer_sk.sign(&msg), payee_sk.sign(&msg)],
            &[payer_pk, payee_pk],
            &RealBls,
        );
        assert!(ok.is_ok(), "a genuine mutual release must verify");

        // A release signed by a non-payee in the payee slot: the key still
        // matches the escrow (so the key-binding check passes), but the sig
        // itself won't verify under the payee's key, so it is refused.
        let third_party = e.verify_mutual_release(
            &[payer_sk.sign(&msg), other_sk.sign(&msg)],
            &[payer_pk, payee_pk],
            &RealBls,
        );
        assert!(
            third_party.is_err(),
            "a non-payee signature must not satisfy mutual release"
        );

        // Three signatures are rejected outright by the arity rule.
        let three = e.verify_mutual_release(
            &[
                payer_sk.sign(&msg),
                other_sk.sign(&msg),
                payee_sk.sign(&msg),
            ],
            &[payer_pk, payee_pk, payee_pk],
            &RealBls,
        );
        assert!(
            three.is_err(),
            "a release without exactly two sigs must refuse"
        );

        // And naming a key that is not this escrow's party is refused before
        // any pairing runs.
        let wrong_key = e.verify_mutual_release(
            &[payer_sk.sign(&msg), payee_sk.sign(&msg)],
            &[_other_pk, _other_pk],
            &RealBls,
        );
        assert!(wrong_key.is_err(), "a non-party key must not release");
    }

    #[test]
    fn encode_decode_round_trips() {
        let (e, _p, _payee) = escrow();
        let bytes = e.encode();
        let mut r = crate::ser::Reader::new(&bytes);
        let d = ConditionalEscrow::decode(&mut r).unwrap();
        assert_eq!(e, d);
        // The id must not change after a round trip.
        assert_eq!(e.id(), d.id());
    }

    #[test]
    fn an_arbiter_release_from_a_non_designated_key_is_refused() {
        let (e, _payer_sk, _payee_sk) = escrow();
        let (arb_sk, _arb_pk) = key(5);
        let (non_arb_sk, _non_arb_pk) = key(9);
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        let sig = non_arb_sk.sign(&msg);

        // A signature from the designated arbitrator verifies under real BLS.
        let good = e.verify_arbiter_release(&arb_sk.sign(&msg), &RealBls);
        assert!(
            good.is_ok(),
            "the designated arbitrator must be able to release"
        );

        // A signature from any other key fails the pairing: the escrow binds the
        // arbitrator's public key at open time, and the wrong key's signature
        // cannot satisfy it.
        let bad = e.verify_arbiter_release(&sig, &RealBls);
        assert!(bad.is_err(), "a non-designated signer must be refused");
    }

    #[test]
    fn finalize_idempotently_lands_a_matured_release_at_the_release_height() {
        // A release with no activation window commits at its own height.
        let (mut e, _p, _payee) = escrow();
        let h = 10;
        e.state = EscrowState::ReleasedArbiter { at_height: h };

        assert!(e.finalize(h, 0).unwrap(), "finalizes at the release height");
        assert!(
            matches!(e.state, EscrowState::Finalized { at_height } if at_height == h),
            "finalized height stamps the release height, not now"
        );
        // Idempotent: a second call on a Finalized state is a no-op.
        assert!(!e.finalize(h + 5, 0).unwrap(), "already final");

        // A window defers finalization until maturity.
        let mut e2 = e.clone();
        e2.state = EscrowState::ReleasedMutual { at_height: 20 };
        assert!(
            !e2.finalize(20, 20).unwrap(),
            "not mature at release height"
        );
        assert!(
            !e2.finalize(20 + 20 - 1, 20).unwrap(),
            "one block short of the window is not final"
        );
        assert!(e2.finalize(20 + 20, 20).unwrap(), "matured at window end");
        assert!(matches!(e2.state, EscrowState::Finalized { at_height: 20 }));

        // Open is never finalizable.
        let (mut e3, ..) = escrow();
        assert!(
            !e3.finalize(1_000, 0).unwrap(),
            "open escrow does not finalize"
        );
    }
}

#[cfg(test)]
mod escrow_condition_tests {
    use super::*;
    use crate::bls::SecretKey;

    /// A real key, and the escrow opened with its public keys, so a release
    /// signature is verifiable rather than decorative.
    fn escrow_with_keys(
        condition: EscrowCondition,
    ) -> (ConditionalEscrow, SecretKey, SecretKey, SecretKey) {
        let payer_sk = SecretKey::from_scalar(&[11u8; 32]).unwrap();
        let payee_sk = SecretKey::from_scalar(&[22u8; 32]).unwrap();
        let arb_sk = SecretKey::from_scalar(&[33u8; 32]).unwrap();
        let e = ConditionalEscrow::open_with_condition(
            "srct/mini".into(),
            [1u8; 20],
            payer_sk.public_key(),
            [2u8; 20],
            payee_sk.public_key(),
            arb_sk.public_key(),
            1_000,
            7,
            condition,
            0,
        )
        .unwrap();
        (e, payer_sk, payee_sk, arb_sk)
    }

    fn sign(key: &SecretKey, msg: &Hash) -> BlsSignature {
        key.sign(msg)
    }

    fn plain() -> EscrowCondition {
        EscrowCondition::ReleaseToPayee
    }

    #[test]
    fn the_condition_round_trips_through_the_codec() {
        let (e, ..) = escrow_with_keys(plain());
        assert!(e.releasable(), "the default condition is releasable");
        let bytes = e.encode();
        let mut r = Reader::new(&bytes);
        let back = ConditionalEscrow::decode(&mut r).unwrap();
        assert_eq!(back, e, "the condition is part of the escrow's identity");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn an_oracle_gated_escrow_cannot_even_be_opened() {
        // There is no implemented oracle verifier in this codebase, so there is
        // no honest signature for an oracle condition. The refusal moved from
        // release time to open time: an escrow that accepts a condition nobody
        // can satisfy is one that holds the payer's value until the timeout,
        // and the payer should learn about the dead end while they still have
        // the money in hand.
        // Drive the constructor directly: `escrow_with_keys` unwraps, and a
        // refusal is exactly what this asserts.
        let payer_sk = SecretKey::from_scalar(&[11u8; 32]).unwrap();
        let payee_sk = SecretKey::from_scalar(&[22u8; 32]).unwrap();
        let arb_sk = SecretKey::from_scalar(&[33u8; 32]).unwrap();
        let opened = ConditionalEscrow::open_with_condition(
            "srct/mini".into(),
            [1u8; 20],
            payer_sk.public_key(),
            [2u8; 20],
            payee_sk.public_key(),
            arb_sk.public_key(),
            1_000,
            7,
            EscrowCondition::Oracle {
                question_hash: [9u8; 32],
            },
            0,
        );
        assert!(
            matches!(opened, Err(Error::Malformed(msg)) if msg.contains("oracle")),
            "an oracle escrow must be refused at open, got {opened:?}"
        );
    }

    #[test]
    fn the_release_hash_binds_the_condition_and_the_network() {
        // A signature is a decision about *something*. If the condition or the
        // network were not in the hash, one signature would release an escrow
        // with the same parties and amount under a different condition.
        let (plain_escrow, ..) = escrow_with_keys(plain());
        // A record *decoded* from the wire can still name an oracle condition
        // (opening one is refused, parsing is not), so the release hash must
        // keep distinguishing them.
        let mut oracle = plain_escrow.clone();
        oracle.condition = EscrowCondition::Oracle {
            question_hash: [4u8; 32],
        };
        assert!(!oracle.releasable(), "no verifier exists");
        assert!(
            matches!(oracle.state, EscrowState::Open),
            "mutating the condition does not change the state"
        );
        assert_ne!(
            plain_escrow.release_signing_hash(EscrowVerdict::ReleasedToPayee),
            oracle.release_signing_hash(EscrowVerdict::ReleasedToPayee),
            "the same parties under different conditions must not be releasable by one signature"
        );
        let other_net = ConditionalEscrow::open_with_condition(
            "srct/other".into(),
            [1u8; 20],
            plain_escrow.payer_key,
            [2u8; 20],
            plain_escrow.payee_key,
            plain_escrow.arbitrator,
            1_000,
            7,
            plain(),
            0,
        )
        .unwrap();
        assert_ne!(
            plain_escrow.release_signing_hash(EscrowVerdict::ReleasedToPayee),
            other_net.release_signing_hash(EscrowVerdict::ReleasedToPayee),
            "a release must be scoped to its network"
        );
    }

    #[test]
    fn a_release_signature_is_not_valid_for_another_escrow() {
        // Cross-escrow replay: the arbitrator's signature over one escrow must
        // not release a different one.
        let (a, _, _, arb) = escrow_with_keys(plain());
        let (b, _, _, _) = escrow_with_keys_other_nonce();
        let mut target = b.clone();
        let msg = a.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        let err = target
            .release_arbiter(&sign(&arb, &msg), 10, &RealBls)
            .unwrap_err();
        assert!(err.to_string().contains("arbiter"), "{err}");
        assert!(matches!(target.state, EscrowState::Open));
    }

    fn escrow_with_keys_other_nonce() -> (ConditionalEscrow, SecretKey, SecretKey, SecretKey) {
        let payer_sk = SecretKey::from_scalar(&[11u8; 32]).unwrap();
        let payee_sk = SecretKey::from_scalar(&[22u8; 32]).unwrap();
        let arb_sk = SecretKey::from_scalar(&[33u8; 32]).unwrap();
        let e = ConditionalEscrow::open(
            "srct/mini".into(),
            [1u8; 20],
            payer_sk.public_key(),
            [2u8; 20],
            payee_sk.public_key(),
            arb_sk.public_key(),
            1_000,
            8,
            0,
        )
        .unwrap();
        (e, payer_sk, payee_sk, arb_sk)
    }

    #[test]
    fn a_second_release_is_refused() {
        let (e, _, _, arb) = escrow_with_keys(plain());
        let mut once = e.clone();
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        once.release_arbiter(&sign(&arb, &msg), 10, &RealBls)
            .unwrap();
        assert!(matches!(
            once.state,
            EscrowState::ReleasedArbiter { at_height: 10 }
        ));
        // A second release of a released escrow is refused, not re-applied.
        let err = once
            .release_arbiter(&sign(&arb, &msg), 10, &RealBls)
            .unwrap_err();
        assert!(err.to_string().contains("not live"), "{err}");
    }

    #[test]
    fn a_released_escrow_cannot_be_mutually_released() {
        let (e, payer, payee, arb) = escrow_with_keys(plain());
        let mut once = e.clone();
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        once.release_arbiter(&sign(&arb, &msg), 5, &RealBls)
            .unwrap();
        let err = once
            .release_mutual(
                &[sign(&payer, &msg), sign(&payee, &msg)],
                &[e.payer_key, e.payee_key],
                6,
                &RealBls,
            )
            .unwrap_err();
        assert!(err.to_string().contains("not live"), "{err}");
    }

    #[test]
    fn a_mutual_release_with_one_signature_is_refused() {
        // One-sided mutual release: the payee cannot unilaterally release by
        // signing alone, and the payer must sign too.
        let (e, payer, _, _) = escrow_with_keys(plain());
        let mut escrow = e.clone();
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        let err = escrow
            .release_mutual(&[sign(&payer, &msg)], &[e.payer_key], 1, &RealBls)
            .unwrap_err();
        assert!(err.to_string().contains("two signatures"), "{err}");
        assert!(matches!(escrow.state, EscrowState::Open));
    }

    #[test]
    fn an_open_escrow_refunds_the_payer_once_the_timeout_passes() {
        // `escrow_with_keys` opens at height 0, so the timeout lands exactly
        // at ESCROW_EXPIRY_BLOCKS.
        let (e, ..) = escrow_with_keys(plain());
        let mut escrow = e.clone();
        let deadline = ESCROW_EXPIRY_BLOCKS;

        assert!(
            !escrow.expired_at(deadline - 1),
            "one block short of the timeout is still live"
        );
        assert!(
            matches!(escrow.refund(deadline - 1), Err(Error::Malformed(m)) if m.contains("not expired")),
            "a live escrow must not refund"
        );

        assert!(escrow.expired_at(deadline), "the timeout is exact");
        escrow.refund(deadline).unwrap();
        assert!(matches!(
            escrow.state,
            EscrowState::Refunded { at_height } if at_height == deadline
        ));
        // Terminal: no second refund, and the state survives the codec so a
        // restart cannot forget that the value already went back.
        assert!(escrow.refund(deadline + 1).is_err());
        let bytes = escrow.encode();
        let mut r = Reader::new(&bytes);
        assert_eq!(
            ConditionalEscrow::decode(&mut r).unwrap(),
            escrow,
            "a refunded escrow and its expiry clock survive a round trip"
        );
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn a_release_after_expiry_is_refused_so_the_refund_cannot_be_raced() {
        let (e, payer, payee, arb) = escrow_with_keys(plain());
        let mut escrow = e.clone();
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        let deadline = ESCROW_EXPIRY_BLOCKS;

        // At the timeout, even a perfect arbitrator signature is refused by
        // name: the escrow's direction must not depend on which of the two
        // transitions a node happens to see first.
        let err = escrow
            .release_arbiter(&sign(&arb, &msg), deadline, &RealBls)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        assert!(
            matches!(escrow.state, EscrowState::Open),
            "a refused release changes nothing"
        );
        // The mutual path is the same rule, not a second one.
        let err = escrow
            .release_mutual(
                &[sign(&payer, &msg), sign(&payee, &msg)],
                &[e.payer_key, e.payee_key],
                deadline + 1,
                &RealBls,
            )
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        assert!(matches!(escrow.state, EscrowState::Open));

        // Which leaves the refund as the only move left.
        escrow.refund(deadline + 1).unwrap();
        assert!(matches!(escrow.state, EscrowState::Refunded { .. }));
    }

    #[test]
    fn finality_gates_finalization_and_is_idempotent() {
        let (e, _, _, arb) = escrow_with_keys(plain());
        let mut escrow = e.clone();
        let msg = e.release_signing_hash(EscrowVerdict::ReleasedToPayee);
        escrow
            .release_arbiter(&sign(&arb, &msg), 100, &RealBls)
            .unwrap();

        // Inside the finality window the release is not yet final.
        assert!(!escrow.finalize(149, 50).unwrap(), "not mature yet");
        assert!(matches!(escrow.state, EscrowState::ReleasedArbiter { .. }));

        // At the boundary it finalizes, frozen at the release height.
        assert!(escrow.finalize(150, 50).unwrap());
        assert!(matches!(
            escrow.state,
            EscrowState::Finalized { at_height: 100 }
        ));
        // And again: idempotent, no rewrite of the landing height.
        assert!(!escrow.finalize(500, 50).unwrap());
        assert!(matches!(
            escrow.state,
            EscrowState::Finalized { at_height: 100 }
        ));
    }
}
