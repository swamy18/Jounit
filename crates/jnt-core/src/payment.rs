//! The canonical machine/agent payment format (roadmap item 11).
//!
//! A `MachinePayment` is the single, canonical primitive that connects the
//! pieces Decision 16 already shipped — agent identity, `SpendPolicy` and
//! `Authorization` — to an actual JNT payment. It is **not** a currency, a
//! ledger or an authorization engine: it moves no coin by itself. The coin
//! still moves through the ordinary §1 UTXO transaction (or the L2 task
//! escrow); this object is the signed, offline-verifiable statement
//! *"I, this payer, pay this recipient this amount for this service, under
//! this policy, once, before this height."*
//!
//! # What it binds
//!
//! One domain-separated signing hash (`jounit/machine-payment/v1`) covers a
//! bounded canonical body of:
//!
//! - payer identity (`payer`, an ordinary §1 address) and **payer type**
//!   (`Human`, `Machine` or `Service`),
//! - agent identity (`agent_id`, re-derived on every verification — a payment
//!   cannot claim another identity),
//! - recipient, optional service identity tag, amount and fee,
//! - nonce (anti-replay), governing policy hash, expiration height,
//! - the payment/transaction reference (request id or chain txid).
//!
//! The signature bundles (`keys` + `sigs`) follow the same hybrid-bundle rule
//! as an L1 input and as `l2::Auth`: every component must verify, and
//! `keys.address()` must equal `payer`, so a payment cannot be *signed* by
//! anyone other than the identity it *names*.
//!
//! # Fail-closed rules (locked)
//!
//! - a machine or service payer **must** carry a non-zero `policy_hash` —
//!   an autonomous actor without a governing policy is refused
//!   (`PaymentError::PolicyRequired`); only a `Human` payer may omit it;
//! - `amount_sat == 0` and `expires_at_height == 0` are refused: no immortal,
//!   no meaningless payments;
//! - verification is network-bound: a `jounit/mini` payment presented on
//!   `jounit/testnet` fails by name;
//! - decoding is bounded (network id ≤ 64 bytes, bundle caps from `sig.rs`)
//!   and `deserialize` is the exact inverse of `serialize`;
//! - every ambiguity refuses. Nothing here resolves in the spender's favour.
//!
//! # Relationship to the authorization engine
//!
//! `linked_to(&Authorization)` checks that a payment says exactly what its
//! authorization granted — same policy, agent, recipient, amount, service and
//! nonce. The *budget* rules (per-transaction limit, tumbling cumulative
//! window, nonce monotonicity) stay in `agent::PolicyBook`, which is the one
//! authorization engine. This module does not reimplement any of them.

use crate::agent::{derive_agent_id, AgentId, AgentRole, Authorization};
use crate::error::Error;
use crate::hash::{sha256_dom, Address, Hash};
use crate::l2::Auth;
use crate::ser::{Reader, Writer};
use crate::sig::Bundle;
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use std::fmt;

/// Payment encoding version. A future format MUST use a new value.
pub const PAYMENT_VERSION: u8 = 1;
/// Domain tag for the payment signing hash.
pub const DOM_MACHINE_PAYMENT: &[u8] = b"jounit/machine-payment/v1";
/// Longest accepted network id (bytes), same bound the policy layer uses.
pub const MAX_PAYMENT_NETWORK_ID_LEN: usize = 64;
/// Default cap on the replay tracker, so a caller cannot grow state forever.
pub const DEFAULT_MAX_TRACKED_PAYMENTS: usize = 4096;

/// Why a payment was refused. Named and `PartialEq`, so callers (and tests)
/// can assert the exact clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError {
    /// Bytes could not be decoded as a payment.
    Malformed(&'static str),
    /// `version` is not [`PAYMENT_VERSION`].
    UnsupportedVersion(u8),
    /// `network_id` is empty.
    EmptyNetworkId,
    /// `network_id` exceeds [`MAX_PAYMENT_NETWORK_ID_LEN`].
    NetworkIdTooLong(usize),
    /// `amount_sat == 0`.
    ZeroAmount,
    /// `expires_at_height == 0`: a payment that never expires is refused.
    NoExpiry,
    /// `agent_id` is not `derive_agent_id(network_id, payer_type, payer)`.
    IdentityMismatch,
    /// A machine/service payer without a governing policy is refused.
    PolicyRequired,
    /// Payment is for another network (network binding).
    WrongNetwork { expected: String, got: String },
    /// The height reached `expires_at_height` (exclusive).
    Expired { expires_at: u64, height: u64 },
    /// The signing keys do not derive the address the payment names.
    SignerNotPayer { signer: Address, payer: Address },
    /// A signature component did not verify.
    SignatureInvalid(&'static str),
    /// An arithmetic bound would overflow.
    Overflow,
    /// The replay tracker is at capacity and refuses a new payment.
    TrackerFull { cap: usize },
    /// This exact payment was already accepted (replay / duplicate).
    AlreadySeen,
    /// Payment does not say what its authorization granted.
    NotLinkedToAuthorization(&'static str),
    /// A batch contains payments from different payers (one signer, one
    /// settlement).
    MixedPayers,
}

impl fmt::Display for PaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentError::Malformed(w) => write!(f, "malformed payment bytes: {w}"),
            PaymentError::UnsupportedVersion(v) => write!(f, "unsupported payment version {v}"),
            PaymentError::EmptyNetworkId => write!(f, "payment network id is empty"),
            PaymentError::NetworkIdTooLong(n) => write!(
                f,
                "payment network id is {n} bytes, cap {MAX_PAYMENT_NETWORK_ID_LEN}"
            ),
            PaymentError::ZeroAmount => write!(f, "payment amount is zero"),
            PaymentError::NoExpiry => write!(f, "payment never expires"),
            PaymentError::IdentityMismatch => {
                write!(
                    f,
                    "agent id is not derived from payer type, payer and network"
                )
            }
            PaymentError::PolicyRequired => {
                write!(
                    f,
                    "a machine/service payment must name its governing policy"
                )
            }
            PaymentError::WrongNetwork { expected, got } => {
                write!(
                    f,
                    "payment is for network {expected}, checked against {got}"
                )
            }
            PaymentError::Expired { expires_at, height } => {
                write!(f, "payment expired at {expires_at}, checked at {height}")
            }
            PaymentError::SignerNotPayer { signer, payer } => write!(
                f,
                "signing keys address {:02x?} is not payer {payer:02x?}",
                signer
            ),
            PaymentError::SignatureInvalid(w) => write!(f, "payment signature invalid: {w}"),
            PaymentError::Overflow => write!(f, "arithmetic overflow in payment"),
            PaymentError::TrackerFull { cap } => {
                write!(f, "payment tracker is full ({cap} payments)")
            }
            PaymentError::AlreadySeen => write!(f, "payment was already accepted"),
            PaymentError::NotLinkedToAuthorization(w) => {
                write!(f, "payment does not match its authorization: {w}")
            }
            PaymentError::MixedPayers => {
                write!(f, "batch contains payments from different payers")
            }
        }
    }
}

impl std::error::Error for PaymentError {}

impl From<Error> for PaymentError {
    fn from(e: Error) -> Self {
        match e {
            Error::Malformed(w) => PaymentError::Malformed(w),
            Error::WrongAddress => PaymentError::SignatureInvalid("signer address mismatch"),
            _ => PaymentError::SignatureInvalid("signature bundle rejected"),
        }
    }
}

/// The canonical machine/agent payment. Deterministic, self-contained, and
/// verifiable offline with public material only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachinePayment {
    pub version: u8,
    /// Network binding, ≤ [`MAX_PAYMENT_NETWORK_ID_LEN`] bytes.
    pub network_id: String,
    /// Who is paying: human wallet, machine wallet, or service.
    pub payer_type: AgentRole,
    /// Payer's ordinary §1 address — the address the signature must match.
    pub payer: Address,
    /// `derive_agent_id(network_id, payer_type, payer)`, re-derived on verify.
    pub agent_id: AgentId,
    /// Who gets paid.
    pub recipient: Address,
    /// Service identity tag, when the payment buys a service.
    pub service: Option<[u8; 32]>,
    /// Amount in satoshis (one economy: the same JNT, the same ledger).
    pub amount_sat: u64,
    /// Fee the payer declares for the settlement carrying this payment.
    pub fee_sat: u64,
    /// Strictly-per-policy anti-replay counter (mirrors the authorization).
    pub nonce: u64,
    /// Governing `SpendPolicy::hash()`. Zero only for human, policy-less pays.
    pub policy_hash: Hash,
    /// Last height at which this payment is acceptable (exclusive).
    pub expires_at_height: u64,
    /// Payment/transaction reference: the payment request id it settles, or
    /// a chain txid when one is known at signing time. Zero means "unbound
    /// intent" and is permitted: binding is the settlement layer's job.
    pub reference: Hash,
    /// Public keys of the payer (hybrid bundle, same shape as an L1 input).
    pub keys: Bundle,
    /// Signatures of the payer over [`MachinePayment::signing_hash`].
    pub sigs: Bundle,
}

impl MachinePayment {
    /// The canonical body: every consensus-relevant field, no signatures.
    /// Both the signing hash and the exact inverse encode/decode run through
    /// this one encoding, so there is exactly one byte string per payment.
    pub fn body(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(192);
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
        w.u64le(self.amount_sat)
            .u64le(self.fee_sat)
            .u64le(self.nonce)
            .fixed(&self.policy_hash)
            .u64le(self.expires_at_height)
            .fixed(&self.reference);
        w.into_vec()
    }

    /// Domain-separated hash of the body. This is what the payer signs and
    /// what a service checks; it doubles as the payment's **id**.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_MACHINE_PAYMENT, &[&self.body()])
    }

    /// Canonical wire encoding: `body ‖ keys ‖ sigs`. Deterministic and
    /// self-delimiting; `deserialize` is its exact inverse.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.keys.to_bytes());
        out.extend_from_slice(&self.sigs.to_bytes());
        out
    }

    /// Bounded decode. Declared vector counts are checked against the caps
    /// *and* the bytes actually remaining before anything is allocated, and
    /// the structural rules run before the caller sees the object.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PaymentError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| PaymentError::Malformed("version"))?;
        if version != PAYMENT_VERSION {
            return Err(PaymentError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| PaymentError::Malformed("network len"))? as usize;
        if net_len == 0 {
            return Err(PaymentError::EmptyNetworkId);
        }
        if net_len > MAX_PAYMENT_NETWORK_ID_LEN {
            return Err(PaymentError::NetworkIdTooLong(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| PaymentError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| PaymentError::Malformed("network id is not utf-8"))?
            .to_string();
        let payer_type_raw = r.u8().map_err(|_| PaymentError::Malformed("payer type"))?;
        let payer_type = AgentRole::from_u8(payer_type_raw)
            .ok_or(PaymentError::Malformed("payer type out of range"))?;
        let payer = r
            .fixed::<20>()
            .map_err(|_| PaymentError::Malformed("payer"))?;
        let agent_id = r
            .fixed::<20>()
            .map_err(|_| PaymentError::Malformed("agent id"))?;
        let recipient = r
            .fixed::<20>()
            .map_err(|_| PaymentError::Malformed("recipient"))?;
        let svc_flag = r
            .u8()
            .map_err(|_| PaymentError::Malformed("service flag"))?;
        let service = match svc_flag {
            0 => None,
            1 => Some(
                r.fixed::<32>()
                    .map_err(|_| PaymentError::Malformed("service tag"))?,
            ),
            _ => return Err(PaymentError::Malformed("service flag not 0 or 1")),
        };
        let amount_sat = r.u64le().map_err(|_| PaymentError::Malformed("amount"))?;
        let fee_sat = r.u64le().map_err(|_| PaymentError::Malformed("fee"))?;
        let nonce = r.u64le().map_err(|_| PaymentError::Malformed("nonce"))?;
        let policy_hash = r
            .fixed::<32>()
            .map_err(|_| PaymentError::Malformed("policy hash"))?;
        let expires_at_height = r
            .u64le()
            .map_err(|_| PaymentError::Malformed("expires_at"))?;
        let reference = r
            .fixed::<32>()
            .map_err(|_| PaymentError::Malformed("reference"))?;

        let keys = Bundle::from_reader(&mut r).map_err(PaymentError::from)?;
        let sigs = Bundle::from_reader(&mut r).map_err(PaymentError::from)?;
        r.expect_end()
            .map_err(|_| PaymentError::Malformed("trailing bytes"))?;

        let payment = MachinePayment {
            version,
            network_id,
            payer_type,
            payer,
            agent_id,
            recipient,
            service,
            amount_sat,
            fee_sat,
            nonce,
            policy_hash,
            expires_at_height,
            reference,
            keys,
            sigs,
        };
        payment.validate()?;
        Ok(payment)
    }

    /// Structural self-consistency. Separate from signature verification so a
    /// payment can be rejected before any crypto work.
    pub fn validate(&self) -> Result<(), PaymentError> {
        if self.version != PAYMENT_VERSION {
            return Err(PaymentError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() {
            return Err(PaymentError::EmptyNetworkId);
        }
        if self.network_id.len() > MAX_PAYMENT_NETWORK_ID_LEN {
            return Err(PaymentError::NetworkIdTooLong(self.network_id.len()));
        }
        if self.amount_sat == 0 {
            return Err(PaymentError::ZeroAmount);
        }
        if self.expires_at_height == 0 {
            return Err(PaymentError::NoExpiry);
        }
        // Identity binding: the payment cannot name another identity.
        let expected = derive_agent_id(&self.network_id, self.payer_type, &self.payer);
        if expected != self.agent_id {
            return Err(PaymentError::IdentityMismatch);
        }
        // Autonomous actors must be policy-governed; humans may pay directly.
        if self.payer_type != AgentRole::Human && self.policy_hash == [0u8; 32] {
            return Err(PaymentError::PolicyRequired);
        }
        Ok(())
    }

    /// Offline verification: structure, network binding, expiration at
    /// `height`, signer-address binding and every signature component.
    /// Public material only — no policy, no network access, no private key.
    pub fn verify(&self, network_id: &str, height: u64) -> Result<(), PaymentError> {
        if self.network_id != network_id {
            return Err(PaymentError::WrongNetwork {
                expected: self.network_id.clone(),
                got: network_id.to_string(),
            });
        }
        self.validate()?;
        if height >= self.expires_at_height {
            return Err(PaymentError::Expired {
                expires_at: self.expires_at_height,
                height,
            });
        }
        let signer = self.keys.address()?;
        if signer != self.payer {
            return Err(PaymentError::SignerNotPayer {
                signer,
                payer: self.payer,
            });
        }
        let msg = self.signing_hash();
        crate::sig::verify_bundle(&self.sigs, &self.keys, &msg)?;
        Ok(())
    }

    /// Bind a payment to the authorization that granted it: same policy,
    /// agent, owner, recipient, amount, service and nonce. This is the seam
    /// between Decision 16's engine and the payment; the budget rules that
    /// produced the authorization stay in `PolicyBook`.
    pub fn linked_to(&self, auth: &Authorization) -> Result<(), PaymentError> {
        if self.policy_hash != auth.policy_hash {
            return Err(PaymentError::NotLinkedToAuthorization("policy hash"));
        }
        if self.agent_id != auth.agent_id {
            return Err(PaymentError::NotLinkedToAuthorization("agent id"));
        }
        if self.payer != auth.owner {
            return Err(PaymentError::NotLinkedToAuthorization("payer/owner"));
        }
        if self.recipient != auth.recipient {
            return Err(PaymentError::NotLinkedToAuthorization("recipient"));
        }
        if self.amount_sat != auth.amount_sat {
            return Err(PaymentError::NotLinkedToAuthorization("amount"));
        }
        if self.service != auth.service {
            return Err(PaymentError::NotLinkedToAuthorization("service"));
        }
        if self.nonce != auth.nonce {
            return Err(PaymentError::NotLinkedToAuthorization("nonce"));
        }
        Ok(())
    }

    /// `amount + fee`, or `None` on overflow.
    pub fn total_sat(&self) -> Option<u64> {
        self.amount_sat.checked_add(self.fee_sat)
    }
}

/// Build the unsigned payment body for an authorization, then sign it with
/// the payer's wallet. The wallet is passed in, never stored: nothing in this
/// module reads, persists or emits a private key.
pub fn build_signed_payment(
    wallet: &Wallet,
    auth: &Authorization,
    network_id: &str,
    payer_type: AgentRole,
    fee_sat: u64,
    expires_at_height: u64,
    reference: Hash,
) -> Result<MachinePayment, PaymentError> {
    let payer = wallet.address()?;
    let mut payment = MachinePayment {
        version: PAYMENT_VERSION,
        network_id: network_id.to_string(),
        payer_type,
        payer,
        agent_id: auth.agent_id,
        recipient: auth.recipient,
        service: auth.service,
        amount_sat: auth.amount_sat,
        fee_sat,
        nonce: auth.nonce,
        policy_hash: auth.policy_hash,
        expires_at_height,
        reference,
        keys: Auth::keys_for(wallet)?,
        sigs: Bundle::default(),
    };
    // The authorization's owner must be the payer: a machine cannot spend a
    // policy that belongs to someone else's identity. Checked before structural
    // validation so the refusal names the real cause.
    if payment.payer != auth.owner {
        return Err(PaymentError::NotLinkedToAuthorization("payer/owner"));
    }
    payment.validate()?;
    let msg = payment.signing_hash();
    payment.sigs = Auth::sigs_for(wallet, &msg)?;
    payment.verify(network_id, expires_at_height.saturating_sub(1))?;
    payment.linked_to(auth)?;
    Ok(payment)
}

/// Everything but the key that builds a direct (policy-less) payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPaymentSpec {
    pub network_id: String,
    pub recipient: Address,
    pub service: Option<[u8; 32]>,
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub nonce: u64,
    pub expires_at_height: u64,
    pub reference: Hash,
}

/// Build a direct, policy-less payment — the human → machine/service path.
///
/// Machine and service payers cannot use this to route around their policy:
/// the payer type is fixed to `Human` here, and a session against a
/// policy-governed request refuses a payment whose `policy_hash` disagrees
/// with the request's (see `service::Session::verify`).
pub fn build_direct_payment(
    wallet: &Wallet,
    spec: DirectPaymentSpec,
) -> Result<MachinePayment, PaymentError> {
    let payer = wallet.address()?;
    let mut payment = MachinePayment {
        version: PAYMENT_VERSION,
        network_id: spec.network_id.clone(),
        payer_type: AgentRole::Human,
        payer,
        agent_id: derive_agent_id(&spec.network_id, AgentRole::Human, &payer),
        recipient: spec.recipient,
        service: spec.service,
        amount_sat: spec.amount_sat,
        fee_sat: spec.fee_sat,
        nonce: spec.nonce,
        policy_hash: [0u8; 32],
        expires_at_height: spec.expires_at_height,
        reference: spec.reference,
        keys: Auth::keys_for(wallet)?,
        sigs: Bundle::default(),
    };
    payment.validate()?;
    let msg = payment.signing_hash();
    payment.sigs = Auth::sigs_for(wallet, &msg)?;
    payment.verify(&spec.network_id, spec.expires_at_height.saturating_sub(1))?;
    Ok(payment)
}

/// Bounded replay tracker: the exact payment id (`signing_hash`) may be
/// accepted once. A re-submitted payment — identical bytes or a re-signed
/// copy of the same body — hashes to the same id and is refused by name.
///
/// Deliberately a cap-with-refusal structure, like `PolicyBook`: a full
/// tracker refuses rather than evicts, because evicting would reopen the
/// replay window it exists to close. The expiry height is the second line of
/// defence: ids only need to be remembered while their payment is live, and
/// an operator may prune entries whose payment has expired (see
/// [`PaymentTracker::prune_expired`]).
#[derive(Debug, Clone)]
pub struct PaymentTracker {
    seen: BTreeMap<Hash, u64>,
    max_payments: usize,
}

impl Default for PaymentTracker {
    fn default() -> Self {
        PaymentTracker::with_capacity(DEFAULT_MAX_TRACKED_PAYMENTS)
    }
}

impl PaymentTracker {
    pub fn with_capacity(max_payments: usize) -> Self {
        PaymentTracker {
            seen: BTreeMap::new(),
            max_payments,
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Record a payment id, refusing an exact replay.
    pub fn observe(&mut self, id: &Hash, expires_at: u64) -> Result<(), PaymentError> {
        if self.seen.contains_key(id) {
            return Err(PaymentError::AlreadySeen);
        }
        if self.seen.len() >= self.max_payments {
            return Err(PaymentError::TrackerFull {
                cap: self.max_payments,
            });
        }
        self.seen.insert(*id, expires_at);
        Ok(())
    }

    /// Convenience: verify a payment completely and record it once.
    pub fn accept(
        &mut self,
        payment: &MachinePayment,
        network_id: &str,
        height: u64,
    ) -> Result<Hash, PaymentError> {
        payment.verify(network_id, height)?;
        let id = payment.signing_hash();
        self.observe(&id, payment.expires_at_height)?;
        Ok(id)
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.seen.contains_key(id)
    }

    /// Drop ids whose payments have expired at `height`. This is the only
    /// removal path: it can never forget a payment that could still replay.
    pub fn prune_expired(&mut self, height: u64) -> usize {
        let before = self.seen.len();
        self.seen.retain(|_, expires_at| *expires_at > height);
        before - self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{AuthorizationRequest, PolicyBook, SpendPolicy, POLICY_VERSION};

    const NET: &str = "jounit/testnet";

    fn wallet() -> Wallet {
        Wallet::new_random("payer")
    }

    fn policy_for(owner: Address) -> SpendPolicy {
        SpendPolicy {
            version: POLICY_VERSION,
            network_id: NET.to_string(),
            agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
            owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 600,
            window_blocks: 10,
            cumulative_max_sat: 1_000,
            allowed_recipients: vec![[1u8; 20]],
            allowed_services: vec![[9u8; 32]],
            not_before_height: 0,
            expires_at_height: 10_000,
            revoked: false,
        }
    }

    fn grant(wallet: &Wallet, amount: u64, nonce: u64) -> Authorization {
        let owner = wallet.address().unwrap();
        let p = policy_for(owner);
        let mut book = PolicyBook::default();
        let req = AuthorizationRequest {
            agent_id: p.agent_id,
            recipient: [1u8; 20],
            amount_sat: amount,
            service: Some([9u8; 32]),
            height: 10,
            nonce,
        };
        book.authorize(&p, NET, &req).expect("in-policy grant")
    }

    #[test]
    fn a_signed_payment_round_trips_exactly() {
        let w = wallet();
        let auth = grant(&w, 250, 1);
        let pay = build_signed_payment(&w, &auth, NET, AgentRole::Machine, 2_000, 9_000, [3u8; 32])
            .expect("payment must build");
        let bytes = pay.serialize();
        let back = MachinePayment::deserialize(&bytes).expect("decode");
        assert_eq!(back, pay, "encode → decode must be the exact inverse");
        assert_eq!(back.signing_hash(), pay.signing_hash());
        assert_eq!(back.serialize(), bytes, "encoding must be canonical");
    }

    #[test]
    fn verification_is_offline_and_rejects_every_mutation() {
        let w = wallet();
        let auth = grant(&w, 250, 1);
        let pay = build_signed_payment(&w, &auth, NET, AgentRole::Machine, 2_000, 9_000, [3u8; 32])
            .unwrap();
        pay.verify(NET, 100).expect("valid payment verifies");

        let mut wrong_net = pay.clone();
        wrong_net.network_id = "jounit/mini".into();
        assert!(matches!(
            wrong_net.verify(NET, 100),
            Err(PaymentError::WrongNetwork { .. })
        ));

        let mut wrong_recipient = pay.clone();
        wrong_recipient.recipient = [5u8; 20];
        assert!(matches!(
            wrong_recipient.verify(NET, 100),
            Err(PaymentError::SignatureInvalid(_))
        ));

        let mut amount_up = pay.clone();
        amount_up.amount_sat = 100_000;
        assert!(amount_up.verify(NET, 100).is_err());

        let mut no_expiry = pay.clone();
        no_expiry.expires_at_height = 0;
        assert_eq!(no_expiry.verify(NET, 100), Err(PaymentError::NoExpiry));

        assert_eq!(
            pay.verify(NET, 9_000),
            Err(PaymentError::Expired {
                expires_at: 9_000,
                height: 9_000
            })
        );
    }

    #[test]
    fn a_machine_payment_without_a_policy_is_refused() {
        let w = wallet();
        let owner = w.address().unwrap();
        let p = policy_for(owner);
        let pay = MachinePayment {
            version: PAYMENT_VERSION,
            network_id: NET.into(),
            payer_type: AgentRole::Machine,
            payer: owner,
            agent_id: p.agent_id,
            recipient: [1u8; 20],
            service: Some([9u8; 32]),
            amount_sat: 10,
            fee_sat: 0,
            nonce: 1,
            policy_hash: [0u8; 32],
            expires_at_height: 500,
            reference: [0u8; 32],
            keys: Auth::keys_for(&w).unwrap(),
            sigs: Bundle::default(),
        };
        assert_eq!(pay.validate(), Err(PaymentError::PolicyRequired));
    }

    #[test]
    fn a_human_payer_needs_no_policy_but_still_re_derives() {
        let w = wallet();
        let owner = w.address().unwrap();
        let mut pay = MachinePayment {
            version: PAYMENT_VERSION,
            network_id: NET.into(),
            payer_type: AgentRole::Human,
            payer: owner,
            agent_id: derive_agent_id(NET, AgentRole::Human, &owner),
            recipient: [1u8; 20],
            service: None,
            amount_sat: 10,
            fee_sat: 0,
            nonce: 0,
            policy_hash: [0u8; 32],
            expires_at_height: 500,
            reference: [0u8; 32],
            keys: Auth::keys_for(&w).unwrap(),
            sigs: Bundle::default(),
        };
        pay.validate().expect("human payment is structurally valid");

        pay.agent_id = derive_agent_id(NET, AgentRole::Machine, &owner);
        assert_eq!(pay.validate(), Err(PaymentError::IdentityMismatch));
    }

    #[test]
    fn the_tracker_refuses_exact_replays_and_prunes_only_expired_ids() {
        let w = wallet();
        let auth = grant(&w, 250, 1);
        let pay =
            build_signed_payment(&w, &auth, NET, AgentRole::Machine, 0, 500, [0u8; 32]).unwrap();
        let mut t = PaymentTracker::default();
        t.accept(&pay, NET, 10).expect("first acceptance");
        assert_eq!(t.accept(&pay, NET, 11), Err(PaymentError::AlreadySeen));

        // Pruning before expiry removes nothing.
        assert_eq!(t.prune_expired(499), 0);
        // At expiry the id drops and the slot frees.
        assert_eq!(t.prune_expired(500), 1);
        assert!(
            t.accept(&pay, NET, 501).is_err(),
            "an expired payment must not be re-accepted even after pruning"
        );
    }

    #[test]
    fn a_payment_built_by_another_key_does_not_link() {
        let w = wallet();
        let auth = grant(&w, 250, 1);
        let w2 = Wallet::new_random("attacker");
        // Attacker cannot build a linked payment: owner check fires first.
        let err = build_signed_payment(&w2, &auth, NET, AgentRole::Machine, 0, 9_000, [0u8; 32])
            .unwrap_err();
        assert_eq!(err, PaymentError::NotLinkedToAuthorization("payer/owner"));
    }
}
