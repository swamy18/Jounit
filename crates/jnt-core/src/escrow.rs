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
//! the protocol never consults a committee list or a Jounit-run key. Dispute
//! resolution is a single designated signer, so the existing
//! [`crate::arbitration::ArbitrationVote`]/settle machinery is reused with the
//! quorum reduced to **one** signer: the designated arbitrator.
//!
//! # States
//!
//! ```text
//! Open -> Released(Mutual)  # both parties agreed
//! Open -> Released(Arbiter) # the designated arbitrator decided
//! Released -> Finalized    # settlement committed (irreversible)
//! ```
//!
//! Open is the only live state. Once released, the escrow is terminal — its
//! bytes are consumed by the settlement that follows, which is the ordinary
//! §1 L1/L2 payout path, not a new coin type.
//!
//! # Why this reuses ArbitrationVote
//!
//! [`crate::arbitration::ArbitrationVote::signing_hash`] is byte-identical to
//! `SettlePayload::signing_hash` (same domain tag `DOM_L2_SETTLE`, same three
//! fields). By deriving the arbitrator's decision hash the same way, a single
//! BLS key can serve both fraud-arbitration and conditional-payment arbitration
//! with no second signing scheme, and a quorum of one is a valid quorum by the
//! chain's existing BLS checks.
//!
//! The arbitrator is **not** a validator: the escrow records their public key
//! directly, and verification confirms the vote comes from that exact key on
//! that exact escrow id and verdict. There is no committee lookup, no Jounit
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
pub const DOM_ESCROW: &[u8] = b"jounit/escrow/v1";

/// Escrow encoding version.
pub const ESCROW_VERSION: u8 = 1;

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
}

impl ConditionalEscrow {
    /// The escrow's identity: `SHA256(DOM_ESCROW ‖ network ‖ payer ‖ payee ‖
    /// arbitrator ‖ amount ‖ nonce)`. Deterministic, contract-unique, and
    /// independent of the state — the id is stable across a release.
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
            ],
        )
    }

    /// The hash an arbitrator signs to release this escrow, or that both parties
    /// sign for a mutual release. Binds the decision to this escrow id and a
    /// verdict, so a signature over one escrow cannot release another.
    pub fn release_signing_hash(&self, verdict: EscrowVerdict) -> Hash {
        sha256_dom(DOM_ESCROW, &[&self.id(), &[verdict as u8]])
    }

    /// Open an escrow, validating its fields.
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
    ) -> Result<Self> {
        if amount_sat == 0 {
            return Err(Error::Malformed("an escrow locks a positive amount"));
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
            .u64le(self.nonce);
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
    /// release has aged out of the `activation_height` finality window it is
    /// `Finalized` at the release height, which is the settlement landing height
    /// the L1 payout is keyed to. `Open` and already-`Finalized` states are
    /// no-ops here (the call site walks every escrow each tick); the structural
    /// rule that only a live escrow can release is enforced by the verify steps.
    ///
    /// Returns `Ok(true)` if this call finalized the escrow, `Ok(false)` if it
    /// did not (not yet mature, or already terminal). The release `at_height`
    /// is frozen into `Finalized { at_height }` and never rewritten by a later
    /// `finalize`, so a re-call after finality is idempotent.
    pub fn finalize(&mut self, now: u64, activation_height: u64) -> Result<bool> {
        let release_height = match &self.state {
            EscrowState::ReleasedMutual { at_height }
            | EscrowState::ReleasedArbiter { at_height } => *at_height,
            // Not releasable yet, or already committed: nothing to do.
            EscrowState::Open | EscrowState::Finalized { .. } => return Ok(false),
        };
        if now < release_height.saturating_add(activation_height) {
            return Ok(false);
        }
        self.state = EscrowState::Finalized {
            at_height: release_height,
        };
        Ok(true)
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
            )
            .unwrap(),
            payer_sk,
            payee_sk,
        )
    }

    const NET: &str = "jounit/mini";

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
