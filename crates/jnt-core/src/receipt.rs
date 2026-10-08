//! Generic service/payment receipts (roadmap item 12).
//!
//! A `ServiceReceipt` is the reusable, cryptographically bound acknowledgement
//! that a service was performed and (through `payment_id`) that a payment
//! exists for it. It is deliberately **not** a VWC: VWC (`jnt-l2/src/vwc.rs`)
//! stays the specialized, quorum-signed verified-work certificate for L2 task
//! settlement. A receipt is the general case that works for
//! **Human → Service**, **Machine → Service**, **Agent → Agent** and
//! **Machine → Machine** payments — any completed exchange of JNT for work,
//! compute, data or access.
//!
//! # What it binds
//!
//! Two domain-separated hashes run over one bounded canonical body:
//!
//! - `signing_hash` (`jounit/service-receipt/v1`) — what the issuing
//!   recipient/service signs;
//! - `receipt_id` (`jounit/receipt-id/v1`) — the deterministic receipt id a
//!   verifier uses as the lookup/dedup key.
//!
//! The body carries: network + version, payer (address, role and re-derived
//! agent identity), recipient, optional service id, amount, `payment_id`,
//! `request_id`, optional `result_hash`, and an optional block anchor
//! (height + block hash). Every field is inside both hashes, so altering any
//! of them breaks the signature *and* changes the id — a forged receipt with a
//! different amount is a different receipt that does not bind to the payment.
//!
//! # Replay-safe semantics
//!
//! The id is content-addressed, so replaying an identical receipt is an
//! idempotent re-presentation of the same fact, and replaying a *modified*
//! one produces a different id. [`ReceiptBook`] turns both into fail-closed
//! behaviour: an identical receipt is recognised (`Duplicate`), a second,
//! *different* receipt for the same `payment_id` is refused by name
//! (`PaymentConflict`) — a service cannot issue two contradicting receipts
//! for one payment. The book is bounded like every other structure in this
//! repository: full refuses, it does not evict.
//!
//! # Offline verification
//!
//! `verify` needs only the receipt bytes, the expected network and public key
//! material: no chain, no node, no private key. `verify_binding` then checks
//! it against the `MachinePayment` it claims, field by field.

use crate::agent::{derive_agent_id, AgentId, AgentRole};
use crate::hash::{sha256_dom, Address, Hash};
use crate::payment::MachinePayment;
use crate::ser::{Reader, Writer};
use crate::sig::Bundle;
use crate::wallet::Wallet;
use std::collections::BTreeMap;
use std::fmt;

/// Receipt encoding version. A future format MUST use a new value.
pub const RECEIPT_VERSION: u8 = 1;
/// Domain tag for the receipt signing hash.
pub const DOM_SERVICE_RECEIPT: &[u8] = b"jounit/service-receipt/v1";
/// Domain tag for the deterministic receipt id.
pub const DOM_RECEIPT_ID: &[u8] = b"jounit/receipt-id/v1";
/// Longest accepted network id (bytes).
pub const MAX_RECEIPT_NETWORK_ID_LEN: usize = 64;
/// Default cap on stored receipts.
pub const DEFAULT_MAX_RECEIPTS: usize = 4096;

/// Why a receipt was refused. Named and `PartialEq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// Bytes could not be decoded as a receipt.
    Malformed(&'static str),
    /// `version` is not [`RECEIPT_VERSION`].
    UnsupportedVersion(u8),
    /// `network_id` is empty.
    EmptyNetworkId,
    /// `network_id` exceeds [`MAX_RECEIPT_NETWORK_ID_LEN`].
    NetworkIdTooLong(usize),
    /// `amount_sat == 0`.
    ZeroAmount,
    /// `payment_id` is zero: a receipt must bind to a payment.
    NoPaymentId,
    /// `request_id` is zero: a receipt must bind to a request/intent.
    NoRequestId,
    /// `agent_id` is not `derive_agent_id(network_id, payer_role, payer)`.
    IdentityMismatch,
    /// Receipt is for another network (network binding).
    WrongNetwork { expected: String, got: String },
    /// The issuing keys do not derive the recipient address.
    IssuerNotRecipient { issuer: Address, recipient: Address },
    /// A signature component did not verify.
    SignatureInvalid(&'static str),
    /// Receipt does not say what its payment says.
    NotBoundToPayment(&'static str),
    /// A different receipt for this payment id already exists.
    PaymentConflict { existing: Hash },
    /// The receipt book is at capacity and refuses rather than evict.
    BookFull { cap: usize },
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptError::Malformed(w) => write!(f, "malformed receipt bytes: {w}"),
            ReceiptError::UnsupportedVersion(v) => write!(f, "unsupported receipt version {v}"),
            ReceiptError::EmptyNetworkId => write!(f, "receipt network id is empty"),
            ReceiptError::NetworkIdTooLong(n) => write!(
                f,
                "receipt network id is {n} bytes, cap {MAX_RECEIPT_NETWORK_ID_LEN}"
            ),
            ReceiptError::ZeroAmount => write!(f, "receipt amount is zero"),
            ReceiptError::NoPaymentId => write!(f, "receipt does not bind to a payment"),
            ReceiptError::NoRequestId => write!(f, "receipt does not bind to a request"),
            ReceiptError::IdentityMismatch => {
                write!(
                    f,
                    "agent id is not derived from payer role, payer and network"
                )
            }
            ReceiptError::WrongNetwork { expected, got } => {
                write!(
                    f,
                    "receipt is for network {expected}, checked against {got}"
                )
            }
            ReceiptError::IssuerNotRecipient { issuer, recipient } => write!(
                f,
                "issuer keys address {issuer:02x?} is not recipient {recipient:02x?}"
            ),
            ReceiptError::SignatureInvalid(w) => write!(f, "receipt signature invalid: {w}"),
            ReceiptError::NotBoundToPayment(w) => {
                write!(f, "receipt does not match its payment: {w}")
            }
            ReceiptError::PaymentConflict { existing } => write!(
                f,
                "another receipt {} already claims this payment",
                hex::encode(existing)
            ),
            ReceiptError::BookFull { cap } => write!(f, "receipt book is full ({cap} receipts)"),
        }
    }
}

impl std::error::Error for ReceiptError {}

impl From<crate::error::Error> for ReceiptError {
    fn from(e: crate::error::Error) -> Self {
        match e {
            crate::error::Error::Malformed(w) => ReceiptError::Malformed(w),
            crate::error::Error::WrongAddress => ReceiptError::SignatureInvalid("address mismatch"),
            _ => ReceiptError::SignatureInvalid("signature bundle rejected"),
        }
    }
}

/// Where the receipt's settlement is anchored on-chain (optional): a height
/// and the canonical block hash at that height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptAnchor {
    pub height: u64,
    pub block_hash: Hash,
}

/// The canonical service receipt. Verifiable offline; tamper-evident;
/// content-addressed by [`ServiceReceipt::receipt_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceReceipt {
    pub version: u8,
    /// Network binding, ≤ [`MAX_RECEIPT_NETWORK_ID_LEN`] bytes.
    pub network_id: String,
    /// Who paid.
    pub payer: Address,
    /// The payer's role, so the agent identity re-derives on any verifier.
    pub payer_role: AgentRole,
    /// `derive_agent_id(network_id, payer_role, payer)`.
    pub agent_id: AgentId,
    /// Who received the payment — also the issuer of this receipt.
    pub recipient: Address,
    /// Service identity tag, when the exchange names a service.
    pub service_id: Option<[u8; 32]>,
    /// Amount paid, in satoshis.
    pub amount_sat: u64,
    /// The payment this receipt acknowledges: a `MachinePayment::signing_hash`
    /// or an L1/L2 settlement txid. Never zero.
    pub payment_id: Hash,
    /// The request/intent this settles (payment request id, task id, order).
    /// Never zero.
    pub request_id: Hash,
    /// Hash of the delivered result, when the service produced one.
    pub result_hash: Option<Hash>,
    /// Block reference, when the settlement is anchored.
    pub anchor: Option<ReceiptAnchor>,
    /// Issuer keys (must derive `recipient`).
    pub keys: Bundle,
    /// Issuer signatures over [`ServiceReceipt::signing_hash`].
    pub sigs: Bundle,
}

impl ServiceReceipt {
    /// The canonical body: every field, no signatures. One byte string per
    /// receipt; both hashes and the exact inverse encode/decode use it.
    pub fn body(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(224);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.payer)
            .u8(self.payer_role.as_u8())
            .fixed(&self.agent_id)
            .fixed(&self.recipient);
        match &self.service_id {
            Some(tag) => {
                w.u8(1).fixed(tag);
            }
            None => {
                w.u8(0);
            }
        }
        w.u64le(self.amount_sat)
            .fixed(&self.payment_id)
            .fixed(&self.request_id);
        match &self.result_hash {
            Some(h) => {
                w.u8(1).fixed(h);
            }
            None => {
                w.u8(0);
            }
        }
        match &self.anchor {
            Some(a) => {
                w.u8(1).u64le(a.height).fixed(&a.block_hash);
            }
            None => {
                w.u8(0);
            }
        }
        w.into_vec()
    }

    /// Domain-separated hash of the body: what the issuer signs.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_SERVICE_RECEIPT, &[&self.body()])
    }

    /// The deterministic receipt id: content-addressed, independent of the
    /// signature bytes, so two verifiers always compute the same id.
    pub fn receipt_id(&self) -> Hash {
        sha256_dom(DOM_RECEIPT_ID, &[&self.body()])
    }

    /// Canonical wire encoding: `body ‖ keys ‖ sigs`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.keys.to_bytes());
        out.extend_from_slice(&self.sigs.to_bytes());
        out
    }

    /// Bounded decode; the exact inverse of [`ServiceReceipt::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| ReceiptError::Malformed("version"))?;
        if version != RECEIPT_VERSION {
            return Err(ReceiptError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| ReceiptError::Malformed("network len"))? as usize;
        if net_len == 0 {
            return Err(ReceiptError::EmptyNetworkId);
        }
        if net_len > MAX_RECEIPT_NETWORK_ID_LEN {
            return Err(ReceiptError::NetworkIdTooLong(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| ReceiptError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| ReceiptError::Malformed("network id is not utf-8"))?
            .to_string();
        let payer = r
            .fixed::<20>()
            .map_err(|_| ReceiptError::Malformed("payer"))?;
        let payer_role_raw = r.u8().map_err(|_| ReceiptError::Malformed("payer role"))?;
        let payer_role = AgentRole::from_u8(payer_role_raw)
            .ok_or(ReceiptError::Malformed("payer role out of range"))?;
        let agent_id = r
            .fixed::<20>()
            .map_err(|_| ReceiptError::Malformed("agent id"))?;
        let recipient = r
            .fixed::<20>()
            .map_err(|_| ReceiptError::Malformed("recipient"))?;
        let svc_flag = r
            .u8()
            .map_err(|_| ReceiptError::Malformed("service flag"))?;
        let service_id = match svc_flag {
            0 => None,
            1 => Some(
                r.fixed::<32>()
                    .map_err(|_| ReceiptError::Malformed("service id"))?,
            ),
            _ => return Err(ReceiptError::Malformed("service flag not 0 or 1")),
        };
        let amount_sat = r.u64le().map_err(|_| ReceiptError::Malformed("amount"))?;
        let payment_id = r
            .fixed::<32>()
            .map_err(|_| ReceiptError::Malformed("payment id"))?;
        let request_id = r
            .fixed::<32>()
            .map_err(|_| ReceiptError::Malformed("request id"))?;
        let result_flag = r.u8().map_err(|_| ReceiptError::Malformed("result flag"))?;
        let result_hash = match result_flag {
            0 => None,
            1 => Some(
                r.fixed::<32>()
                    .map_err(|_| ReceiptError::Malformed("result hash"))?,
            ),
            _ => return Err(ReceiptError::Malformed("result flag not 0 or 1")),
        };
        let anchor_flag = r.u8().map_err(|_| ReceiptError::Malformed("anchor flag"))?;
        let anchor = match anchor_flag {
            0 => None,
            1 => {
                let height = r
                    .u64le()
                    .map_err(|_| ReceiptError::Malformed("anchor height"))?;
                let block_hash = r
                    .fixed::<32>()
                    .map_err(|_| ReceiptError::Malformed("anchor block"))?;
                Some(ReceiptAnchor { height, block_hash })
            }
            _ => return Err(ReceiptError::Malformed("anchor flag not 0 or 1")),
        };
        let keys = Bundle::from_reader(&mut r).map_err(ReceiptError::from)?;
        let sigs = Bundle::from_reader(&mut r).map_err(ReceiptError::from)?;
        r.expect_end()
            .map_err(|_| ReceiptError::Malformed("trailing bytes"))?;

        let receipt = ServiceReceipt {
            version,
            network_id,
            payer,
            payer_role,
            agent_id,
            recipient,
            service_id,
            amount_sat,
            payment_id,
            request_id,
            result_hash,
            anchor,
            keys,
            sigs,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Structural self-consistency, separate from signature verification.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.version != RECEIPT_VERSION {
            return Err(ReceiptError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() {
            return Err(ReceiptError::EmptyNetworkId);
        }
        if self.network_id.len() > MAX_RECEIPT_NETWORK_ID_LEN {
            return Err(ReceiptError::NetworkIdTooLong(self.network_id.len()));
        }
        if self.amount_sat == 0 {
            return Err(ReceiptError::ZeroAmount);
        }
        if self.payment_id == [0u8; 32] {
            return Err(ReceiptError::NoPaymentId);
        }
        if self.request_id == [0u8; 32] {
            return Err(ReceiptError::NoRequestId);
        }
        let expected = derive_agent_id(&self.network_id, self.payer_role, &self.payer);
        if expected != self.agent_id {
            return Err(ReceiptError::IdentityMismatch);
        }
        Ok(())
    }

    /// Offline verification: structure, network binding, issuer-address
    /// binding and every signature component. Public material only.
    pub fn verify(&self, network_id: &str) -> Result<(), ReceiptError> {
        if self.network_id != network_id {
            return Err(ReceiptError::WrongNetwork {
                expected: self.network_id.clone(),
                got: network_id.to_string(),
            });
        }
        self.validate()?;
        let issuer = self.keys.address()?;
        if issuer != self.recipient {
            return Err(ReceiptError::IssuerNotRecipient {
                issuer,
                recipient: self.recipient,
            });
        }
        let msg = self.signing_hash();
        crate::sig::verify_bundle(&self.sigs, &self.keys, &msg)?;
        Ok(())
    }

    /// Bind the receipt to the payment it claims: same network, payer,
    /// recipient, amount, service, agent identity — and the payment's own id.
    pub fn verify_binding(&self, payment: &MachinePayment) -> Result<(), ReceiptError> {
        if self.payment_id != payment.signing_hash() {
            return Err(ReceiptError::NotBoundToPayment("payment id"));
        }
        if self.network_id != payment.network_id {
            return Err(ReceiptError::NotBoundToPayment("network"));
        }
        if self.payer != payment.payer {
            return Err(ReceiptError::NotBoundToPayment("payer"));
        }
        if self.recipient != payment.recipient {
            return Err(ReceiptError::NotBoundToPayment("recipient"));
        }
        if self.amount_sat != payment.amount_sat {
            return Err(ReceiptError::NotBoundToPayment("amount"));
        }
        if self.service_id != payment.service {
            return Err(ReceiptError::NotBoundToPayment("service"));
        }
        if self.agent_id != payment.agent_id {
            return Err(ReceiptError::NotBoundToPayment("agent id"));
        }
        Ok(())
    }
}

/// Sign a receipt as its issuer (the recipient wallet). The wallet is passed
/// in and never stored; this module holds no key material of its own.
pub fn sign_receipt(receipt: &mut ServiceReceipt, wallet: &Wallet) -> Result<(), ReceiptError> {
    let addr = wallet.address()?;
    if addr != receipt.recipient {
        return Err(ReceiptError::IssuerNotRecipient {
            issuer: addr,
            recipient: receipt.recipient,
        });
    }
    receipt.keys = crate::l2::Auth::keys_for(wallet)?;
    let msg = receipt.signing_hash();
    receipt.sigs = crate::l2::Auth::sigs_for(wallet, &msg)?;
    Ok(())
}

/// Outcome of inserting a receipt into a [`ReceiptBook`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptOutcome {
    /// First time this receipt id was seen.
    Inserted,
    /// The exact same receipt was presented again — idempotent, not an error.
    Duplicate,
}

/// Bounded store of receipts with replay-safe semantics: keyed by receipt id
/// for lookup, indexed by payment id so one payment can never carry two
/// contradicting receipts, and by request id for task/order lookups.
#[derive(Debug, Clone)]
pub struct ReceiptBook {
    by_id: BTreeMap<Hash, ServiceReceipt>,
    by_payment: BTreeMap<Hash, Hash>,
    by_request: BTreeMap<Hash, Hash>,
    max_receipts: usize,
}

impl Default for ReceiptBook {
    fn default() -> Self {
        ReceiptBook::with_capacity(DEFAULT_MAX_RECEIPTS)
    }
}

impl ReceiptBook {
    pub fn with_capacity(max_receipts: usize) -> Self {
        ReceiptBook {
            by_id: BTreeMap::new(),
            by_payment: BTreeMap::new(),
            by_request: BTreeMap::new(),
            max_receipts,
        }
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Verify (against `network_id`) and store. An identical receipt is a
    /// `Duplicate`; a *different* receipt claiming the same payment is
    /// refused by name; a full book refuses rather than evicts.
    pub fn accept(
        &mut self,
        receipt: &ServiceReceipt,
        network_id: &str,
    ) -> Result<ReceiptOutcome, ReceiptError> {
        receipt.verify(network_id)?;
        let id = receipt.receipt_id();
        if self.by_id.contains_key(&id) {
            return Ok(ReceiptOutcome::Duplicate);
        }
        match self.by_payment.get(&receipt.payment_id) {
            Some(existing) if *existing != id => {
                return Err(ReceiptError::PaymentConflict {
                    existing: *existing,
                });
            }
            // Same payment already mapped to this very id: impossible here
            // (the `by_id` check above would have returned `Duplicate`), but
            // never panic over bookkeeping — fall through and re-store.
            Some(_) => {}
            None => {}
        }
        if self.by_id.len() >= self.max_receipts {
            return Err(ReceiptError::BookFull {
                cap: self.max_receipts,
            });
        }
        self.by_payment.insert(receipt.payment_id, id);
        self.by_request.insert(receipt.request_id, id);
        self.by_id.insert(id, receipt.clone());
        Ok(ReceiptOutcome::Inserted)
    }

    pub fn by_receipt_id(&self, id: &Hash) -> Option<&ServiceReceipt> {
        self.by_id.get(id)
    }

    pub fn by_payment_id(&self, payment_id: &Hash) -> Option<&ServiceReceipt> {
        self.by_payment
            .get(payment_id)
            .and_then(|id| self.by_id.get(id))
    }

    pub fn by_request_id(&self, request_id: &Hash) -> Option<&ServiceReceipt> {
        self.by_request
            .get(request_id)
            .and_then(|id| self.by_id.get(id))
    }
}

/// True when two receipts claim the same payment but disagree on content —
/// the contradicting-receipt case a verifier must treat as fail-closed.
pub fn receipts_conflict(a: &ServiceReceipt, b: &ServiceReceipt) -> bool {
    a.payment_id == b.payment_id && a.receipt_id() != b.receipt_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2::Auth;

    const NET: &str = "jounit/testnet";

    fn issuer() -> Wallet {
        // Deterministic so every helper sees the same issuer address.
        Wallet::from_private_key_bytes(&[11u8; 32], "service-issuer").expect("valid key")
    }

    fn payment_like() -> MachinePayment {
        let mut p = MachinePayment {
            version: crate::payment::PAYMENT_VERSION,
            network_id: NET.into(),
            payer_type: AgentRole::Machine,
            payer: [7u8; 20],
            agent_id: derive_agent_id(NET, AgentRole::Machine, &[7u8; 20]),
            recipient: issuer().address().expect("issuer address"),
            service: Some([9u8; 32]),
            amount_sat: 500,
            fee_sat: 2_000,
            nonce: 4,
            policy_hash: [3u8; 32],
            expires_at_height: 900,
            reference: [4u8; 32],
            keys: Bundle::default(),
            sigs: Bundle::default(),
        };
        p.keys = Auth::keys_for(&issuer()).unwrap();
        p
    }

    fn receipt_for(payment: &MachinePayment) -> ServiceReceipt {
        let mut r = ServiceReceipt {
            version: RECEIPT_VERSION,
            network_id: NET.into(),
            payer: payment.payer,
            payer_role: payment.payer_type,
            agent_id: payment.agent_id,
            recipient: payment.recipient,
            service_id: payment.service,
            amount_sat: payment.amount_sat,
            payment_id: payment.signing_hash(),
            request_id: [5u8; 32],
            result_hash: Some([6u8; 32]),
            anchor: Some(ReceiptAnchor {
                height: 42,
                block_hash: [8u8; 32],
            }),
            keys: Bundle::default(),
            sigs: Bundle::default(),
        };
        sign_receipt(&mut r, &issuer()).expect("issuer signs");
        r
    }

    #[test]
    fn a_receipt_round_trips_and_ids_are_deterministic() {
        let pay = payment_like();
        let r = receipt_for(&pay);
        let bytes = r.serialize();
        let back = ServiceReceipt::deserialize(&bytes).expect("decode");
        assert_eq!(back, r, "encode → decode must be the exact inverse");
        assert_eq!(back.serialize(), bytes, "encoding must be canonical");
        assert_eq!(back.receipt_id(), r.receipt_id());
        assert_eq!(back.signing_hash(), r.signing_hash());
    }

    #[test]
    fn a_receipt_verifies_offline_and_binds_to_its_payment() {
        let pay = payment_like();
        let r = receipt_for(&pay);
        r.verify(NET).expect("valid receipt verifies");
        r.verify_binding(&pay).expect("receipt binds to payment");
        assert_eq!(
            r.verify("jounit/mini"),
            Err(ReceiptError::WrongNetwork {
                expected: NET.into(),
                got: "jounit/mini".into(),
            })
        );
    }

    #[test]
    fn every_mutation_breaks_signature_or_binding() {
        let pay = payment_like();
        let r = receipt_for(&pay);

        let mut amount = r.clone();
        amount.amount_sat = 1;
        assert!(amount.verify(NET).is_err(), "altered amount verified");
        assert_ne!(amount.receipt_id(), r.receipt_id(), "id must change");

        let mut service = r.clone();
        service.service_id = None;
        assert!(service.verify(NET).is_err(), "altered service verified");

        let mut payment = r.clone();
        payment.payment_id = [0xEE; 32];
        assert!(payment.verify(NET).is_err(), "altered payment verified");
        assert!(payment.verify_binding(&pay).is_err());

        let mut other_net = r.clone();
        other_net.network_id = "jounit/mini".into();
        assert!(other_net.verify(NET).is_err(), "wrong network verified");

        // Issuer substitution: someone else's keys cannot impersonate the
        // recipient.
        let mut forged = r.clone();
        let attacker = Wallet::new_random("attacker");
        sign_receipt(&mut forged, &attacker).expect_err("non-recipient refused");
        forged.keys = Auth::keys_for(&attacker).unwrap();
        let msg = forged.signing_hash();
        forged.sigs = Auth::sigs_for(&attacker, &msg).unwrap();
        assert!(matches!(
            forged.verify(NET),
            Err(ReceiptError::IssuerNotRecipient { .. })
        ));
    }

    #[test]
    fn the_book_is_idempotent_and_refuses_contradicting_receipts() {
        let pay = payment_like();
        let r = receipt_for(&pay);
        let mut book = ReceiptBook::default();
        assert_eq!(book.accept(&r, NET).unwrap(), ReceiptOutcome::Inserted);
        assert_eq!(book.accept(&r, NET).unwrap(), ReceiptOutcome::Duplicate);

        // A second, different receipt for the same payment: refused.
        let mut conflicting = r.clone();
        conflicting.amount_sat = 1;
        sign_receipt(&mut conflicting, &issuer()).unwrap();
        assert_eq!(
            book.accept(&conflicting, NET),
            Err(ReceiptError::PaymentConflict {
                existing: r.receipt_id()
            })
        );
        assert!(receipts_conflict(&r, &conflicting));

        // Lookup paths.
        assert!(book.by_receipt_id(&r.receipt_id()).is_some());
        assert!(book.by_payment_id(&r.payment_id).is_some());
        assert!(book.by_request_id(&r.request_id).is_some());
    }

    #[test]
    fn a_full_book_refuses_instead_of_evicting() {
        let mut book = ReceiptBook::with_capacity(1);
        let pay = payment_like();
        let r = receipt_for(&pay);
        book.accept(&r, NET).unwrap();

        let mut other = receipt_for(&pay);
        other.request_id = [9u8; 32];
        other.payment_id = [2u8; 32];
        sign_receipt(&mut other, &issuer()).unwrap();
        assert_eq!(
            book.accept(&other, NET),
            Err(ReceiptError::BookFull { cap: 1 })
        );
        assert_eq!(book.len(), 1, "a refusal must not mutate the book");
    }

    #[test]
    fn truncated_or_lying_encodings_are_refused() {
        let pay = payment_like();
        let r = receipt_for(&pay);
        let bytes = r.serialize();
        assert!(ServiceReceipt::deserialize(&bytes[..bytes.len() - 1]).is_err());
        assert!(ServiceReceipt::deserialize(&[&bytes[..], &[0u8]].concat()).is_err());

        // A declared network-id length far beyond the buffer.
        let mut lying = bytes.clone();
        lying[1] = 0xFF;
        lying[2] = 0xFF;
        assert!(matches!(
            ServiceReceipt::deserialize(&lying),
            Err(ReceiptError::NetworkIdTooLong(_)) | Err(ReceiptError::Malformed(_))
        ));
    }
}
