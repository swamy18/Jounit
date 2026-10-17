//! Machine / AI-agent identity and reusable authorization policies.
//!
//! Roadmap items 3 (machine wallets), 4 (agent identity), 6 (autonomous
//! payments) and 10 (spending limits / authorization).
//!
//! # What this module is
//!
//! A **pure, deterministic policy layer**. It answers exactly one question:
//! *may this agent, at this height, spend this much to this recipient, under
//! this policy?* Everything it needs is in the arguments, so two nodes (or a
//! wallet and a service) reaching the same inputs reach the same answer with no
//! clock, no randomness and no I/O.
//!
//! # What this module is not
//!
//! - **It never touches secret keys.** Nothing here signs; a policy is signed
//!   by its owner with the existing §1 scheme and verified with
//!   [`verify_authorization`], which takes public key bundles only. A leaked
//!   `SpendPolicy` discloses the *rules*, never the key.
//! - **It changes no consensus rule.** No block, transaction, UTXO, supply or
//!   finality rule is touched. This is a library the node, the wallet and the
//!   worker SDK can all call; until a future decision wires it into
//!   `submit_at`, it cannot by itself move a coin.
//! - **It does not introduce a second currency.** `owner` is an ordinary §1
//!   address, so machine and human balances live in the same UTXO set under the
//!   same issuance schedule (roadmap item 18).
//!
//! # Fail-closed rules (locked)
//!
//! Every refusal is a named [`PolicyError`], and every ambiguous case refuses:
//!
//! - an **empty** recipient list authorizes **nothing** (not "anything");
//! - an **empty** service list authorizes **no** service-tagged payment;
//! - a nonce must **strictly increase**, so an authorization cannot be replayed;
//! - a height below the policy's own window start refuses (time cannot run
//!   backwards inside a policy);
//! - cumulative spend is bounded **per window**, and the window rolls over only
//!   forward, so "many small payments" cannot bypass the per-transaction limit.
//!
//! # Windows
//!
//! The cumulative window is **tumbling**, not sliding: it starts at the height
//! of the first authorization and resets after `window_blocks`. Tumbling is
//! chosen because it is trivially reproducible from `(window_start, height)`
//! alone — a sliding window would need the full authorization history, which is
//! unbounded state and therefore a resource-exhaustion surface.

use crate::hash::{sha256_dom, Address, Hash};
use crate::ser::{Reader, Writer};
use std::collections::BTreeMap;
use std::fmt;

/// A machine or agent identity: 20 bytes, derived (never assigned).
pub type AgentId = [u8; 20];

/// Policy encoding version. A future format MUST use a new value.
///
/// Version 2 adds the delegation link: `parent_agent_id`, the field that makes a
/// policy a child of another. A version-1 policy has no such field, so its bytes
/// decode into a policy with no parent — which is not what they are, and MUST be
/// refused rather than reinterpreted. The version moved rather than the meaning.
pub const POLICY_VERSION: u8 = 2;

/// Longest accepted network id (bytes). Bounded so a policy cannot be a blob.
pub const MAX_NETWORK_ID_LEN: usize = 64;
/// Most recipients one policy may name.
pub const MAX_POLICY_RECIPIENTS: usize = 64;
/// Most service tags one policy may name.
pub const MAX_POLICY_SERVICES: usize = 64;
/// Default cap on tracked policies, so a caller cannot grow state without bound.
pub const DEFAULT_MAX_POLICIES: usize = 1024;

/// Domain tag for agent identity derivation.
pub const DOM_AGENT_ID: &[u8] = b"jounit/agent-id/v1";
/// Domain tag for sub-agent identity derivation: a delegate derives from its
/// parent, never from the funds it is trusted with.
pub const DOM_AGENT_ID_SUB: &[u8] = b"jounit/agent-id/sub/v1";
/// Domain tag for the policy signing hash.
pub const DOM_AGENT_POLICY: &[u8] = b"jounit/agent-policy/v1";
/// Domain tag for the authorization signing hash.
pub const DOM_AGENT_AUTH: &[u8] = b"jounit/agent-auth/v1";

/// What kind of actor the identity belongs to.
///
/// The role separates a machine identity from the human address that owns the
/// same key material, without creating a second address space: both are derived
/// from one `owner` address, and only the *identity* differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgentRole {
    /// A human-controlled wallet.
    Human = 0,
    /// A machine/device wallet spending under a policy.
    Machine = 1,
    /// A service identity that receives payments.
    Service = 2,
}

impl AgentRole {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Total, so a hostile byte can never be silently coerced.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AgentRole::Human),
            1 => Some(AgentRole::Machine),
            2 => Some(AgentRole::Service),
            _ => None,
        }
    }
}

/// The canonical agent identity: deterministic, network-bound, role-separated
/// and cryptographically owned by `owner`.
///
/// ```
/// # use jnt_core::agent::{derive_agent_id, AgentRole};
/// let owner = [7u8; 20];
/// let a = derive_agent_id("jounit/testnet", AgentRole::Machine, &owner);
/// let b = derive_agent_id("jounit/testnet", AgentRole::Machine, &owner);
/// assert_eq!(a, b, "identity must be deterministic");
/// let c = derive_agent_id("jounit/mini", AgentRole::Machine, &owner);
/// assert_ne!(a, c, "identity must be network-bound");
/// ```
pub fn derive_agent_id(network_id: &str, role: AgentRole, owner: &Address) -> AgentId {
    let h = sha256_dom(
        DOM_AGENT_ID,
        &[network_id.as_bytes(), &[role.as_u8()], owner],
    );
    let mut id = [0u8; 20];
    id.copy_from_slice(&h[..20]);
    id
}

/// The delegated agent identity: derived from the **parent**, never from the
/// funds the delegate is trusted with.
///
/// This is the sharp edge the roadmap called out. A sub-agent holds no value and
/// has no owner of its own, so deriving its id from an owner (as
/// [`derive_agent_id`] does) would either fail or — worse — let a delegate
/// re-derive the *root's* id by presenting the root's owner. Deriving from the
/// parent agent id makes the chain structural instead of promissory: a delegate
/// is named by its delegate chain, so it cannot be any agent it is not a child
/// of.
///
/// The domain tag is new rather than shared, per the treatment `DOM_ADDR/v2`
/// received: two derivations over one tag are two meanings over one byte string,
/// and a collision between them would be an identity confusion, not a bug.
///
/// ```
/// # use jnt_core::agent::{derive_agent_id, derive_sub_agent_id, AgentRole};
/// let owner = [7u8; 20];
/// let root = derive_agent_id("jounit/testnet", AgentRole::Machine, &owner);
/// let sub = derive_sub_agent_id("jounit/testnet", &root, AgentRole::Machine);
/// assert_ne!(root, sub, "a delegate is not its parent");
/// // The same parent yields the same delegate, deterministically.
/// assert_eq!(
///     sub,
///     derive_sub_agent_id("jounit/testnet", &root, AgentRole::Machine)
/// );
/// // A different parent yields a different delegate: the chain is the identity.
/// let other_root = derive_agent_id("jounit/mini", AgentRole::Machine, &owner);
/// assert_ne!(
///     sub,
///     derive_sub_agent_id("jounit/mini", &other_root, AgentRole::Machine)
/// );
/// ```
pub fn derive_sub_agent_id(network_id: &str, parent: &AgentId, role: AgentRole) -> AgentId {
    let h = sha256_dom(
        DOM_AGENT_ID_SUB,
        &[network_id.as_bytes(), parent, &[role.as_u8()]],
    );
    let mut id = [0u8; 20];
    id.copy_from_slice(&h[..20]);
    id
}

/// Why an authorization was refused, or a policy was rejected. Named and
/// `PartialEq`, so a caller (and a test) can assert the exact clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Bytes could not be decoded as a policy.
    Malformed(&'static str),
    /// `version` is not [`POLICY_VERSION`].
    UnsupportedVersion(u8),
    /// `network_id` is empty.
    EmptyNetworkId,
    /// `network_id` exceeds [`MAX_NETWORK_ID_LEN`].
    NetworkIdTooLong(usize),
    /// More recipients than [`MAX_POLICY_RECIPIENTS`].
    TooManyRecipients { got: usize, cap: usize },
    /// More service tags than [`MAX_POLICY_SERVICES`].
    TooManyServices { got: usize, cap: usize },
    /// `expires_at_height <= not_before_height`, so the policy can never be used.
    ExpiryNotAfterStart { not_before: u64, expires_at: u64 },
    /// `per_tx_max_sat > cumulative_max_sat` — a policy no authorization can satisfy.
    PerTxAboveCumulative { per_tx: u64, cumulative: u64 },
    /// `per_tx_max_sat == 0`.
    ZeroPerTxLimit,
    /// `window_blocks == 0`.
    ZeroWindowBlocks,
    /// `agent_id` is not `derive_agent_id(network_id, role, owner)`.
    IdentityMismatch,
    /// Policy is for another network (network binding).
    WrongNetwork { expected: String, got: String },
    /// Request names a different agent than the policy.
    WrongAgent,
    /// Policy has been revoked.
    PolicyRevoked,
    /// Requested height is before `not_before_height`.
    NotYetValid { not_before: u64, height: u64 },
    /// Requested height reached `expires_at_height` (exclusive).
    PolicyExpired { expires_at: u64, height: u64 },
    /// Requested height is below the policy's own window start.
    HeightWentBackwards { window_start: u64, height: u64 },
    /// Amount of zero is never authorized.
    ZeroAmount,
    /// Amount above `per_tx_max_sat`.
    PerTxLimitExceeded { amount: u64, limit: u64 },
    /// Window spend plus this amount would exceed `cumulative_max_sat`.
    CumulativeLimitExceeded { requested: u64, limit: u64 },
    /// Recipient is not on the allow list (which may be empty = nothing).
    RecipientNotAllowed,
    /// The payment carries a service tag the policy does not allow, or the
    /// policy allows no service payments at all.
    ServiceNotAllowed,
    /// `nonce` did not strictly increase, so this authorization is a replay.
    NonceNotIncreasing { nonce: u64, last_nonce: u64 },
    /// An arithmetic bound would overflow.
    Overflow,
    /// The policy book is at capacity and refuses a new policy rather than grow.
    PolicyBookFull { cap: usize },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Malformed(w) => write!(f, "malformed policy bytes: {w}"),
            PolicyError::UnsupportedVersion(v) => write!(f, "unsupported policy version {v}"),
            PolicyError::EmptyNetworkId => write!(f, "policy network id is empty"),
            PolicyError::NetworkIdTooLong(n) => {
                write!(
                    f,
                    "policy network id is {n} bytes, cap {MAX_NETWORK_ID_LEN}"
                )
            }
            PolicyError::TooManyRecipients { got, cap } => {
                write!(f, "policy names {got} recipients, cap {cap}")
            }
            PolicyError::TooManyServices { got, cap } => {
                write!(f, "policy names {got} services, cap {cap}")
            }
            PolicyError::ExpiryNotAfterStart {
                not_before,
                expires_at,
            } => write!(
                f,
                "policy expires at {expires_at}, not after start {not_before}"
            ),
            PolicyError::PerTxAboveCumulative { per_tx, cumulative } => write!(
                f,
                "per-tx limit {per_tx} exceeds cumulative limit {cumulative}"
            ),
            PolicyError::ZeroPerTxLimit => write!(f, "policy per-tx limit is zero"),
            PolicyError::ZeroWindowBlocks => write!(f, "policy window is zero blocks"),
            PolicyError::IdentityMismatch => {
                write!(f, "agent id is not derived from owner, role and network")
            }
            PolicyError::WrongNetwork { expected, got } => {
                write!(f, "policy is for network {expected}, request for {got}")
            }
            PolicyError::WrongAgent => write!(f, "authorization names another agent"),
            PolicyError::PolicyRevoked => write!(f, "policy is revoked"),
            PolicyError::NotYetValid { not_before, height } => write!(
                f,
                "policy not valid until {not_before}, request at {height}"
            ),
            PolicyError::PolicyExpired { expires_at, height } => {
                write!(f, "policy expired at {expires_at}, request at {height}")
            }
            PolicyError::HeightWentBackwards {
                window_start,
                height,
            } => write!(
                f,
                "request height {height} is below window start {window_start}"
            ),
            PolicyError::ZeroAmount => write!(f, "amount is zero"),
            PolicyError::PerTxLimitExceeded { amount, limit } => {
                write!(f, "amount {amount} exceeds per-tx limit {limit}")
            }
            PolicyError::CumulativeLimitExceeded { requested, limit } => write!(
                f,
                "window total {requested} would exceed cumulative limit {limit}"
            ),
            PolicyError::RecipientNotAllowed => write!(f, "recipient is not allowed"),
            PolicyError::ServiceNotAllowed => write!(f, "service is not allowed"),
            PolicyError::NonceNotIncreasing { nonce, last_nonce } => {
                write!(
                    f,
                    "nonce {nonce} is not greater than last used {last_nonce}"
                )
            }
            PolicyError::Overflow => write!(f, "arithmetic overflow in policy accounting"),
            PolicyError::PolicyBookFull { cap } => {
                write!(f, "policy book is full ({cap} policies)")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// A signed-by-the-owner spending policy for one agent identity.
///
/// The owner authorizes this once, offline; every later authorization is
/// checked against it without the owner being online. `signing_hash` covers
/// every field (asserted field-by-field in the test suite), so a policy cannot
/// be widened after it was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendPolicy {
    pub version: u8,
    pub network_id: String,
    pub agent_id: AgentId,
    pub owner: Address,
    pub role: AgentRole,
    /// Largest single payment this policy authorizes.
    pub per_tx_max_sat: u64,
    /// Length of the tumbling cumulative window.
    pub window_blocks: u64,
    /// Most an agent may spend inside one window.
    pub cumulative_max_sat: u64,
    /// Exhaustive allow list. Empty means **nothing** is allowed.
    pub allowed_recipients: Vec<Address>,
    /// Exhaustive service allow list. Empty means **no service** payment.
    pub allowed_services: Vec<[u8; 32]>,
    /// First height at which the policy is usable.
    pub not_before_height: u64,
    /// Height at which the policy stops being usable (exclusive).
    pub expires_at_height: u64,
    /// Owner-initiated emergency kill switch.
    pub revoked: bool,
    /// The parent this policy was delegated from, or `None` for a root policy
    /// (one whose owner authorized it directly).
    ///
    /// This is the delegation link, and it lives **inside** the policy rather
    /// than beside it: a link held in a separate table can be added to a policy
    /// that never had one, which is precisely the widening delegation must
    /// refuse. With the link in the signed bytes, a child policy is a child
    /// because the bytes say so.
    pub parent_agent_id: Option<AgentId>,
}

impl SpendPolicy {
    /// The policy hash every state entry is keyed by.
    pub fn hash(&self) -> Hash {
        self.signing_hash()
    }

    /// Domain-separated hash of the canonical encoding. This is what the owner
    /// signs, and what a machine presents alongside an authorization.
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_AGENT_POLICY, &[&self.serialize()])
    }

    /// Canonical, bounded encoding. Deterministic and self-delimiting.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
        w.u8(self.version)
            .u16le(self.network_id.len() as u16)
            .raw(self.network_id.as_bytes())
            .fixed(&self.agent_id)
            .fixed(&self.owner)
            .u8(self.role.as_u8())
            .u64le(self.per_tx_max_sat)
            .u64le(self.window_blocks)
            .u64le(self.cumulative_max_sat)
            .u16le(self.allowed_recipients.len() as u16);
        for r in &self.allowed_recipients {
            w.fixed(r);
        }
        w.u16le(self.allowed_services.len() as u16);
        for s in &self.allowed_services {
            w.fixed(s);
        }
        w.u64le(self.not_before_height)
            .u64le(self.expires_at_height)
            .u8(u8::from(self.revoked));
        match &self.parent_agent_id {
            Some(parent) => {
                w.u8(1).fixed(parent);
            }
            None => {
                w.u8(0);
            }
        }
        w.into_vec()
    }

    /// Decode, rejecting every structurally impossible policy.
    ///
    /// Declared vector counts are checked against both the cap and the bytes
    /// actually remaining before anything is allocated, so a four-byte lie
    /// cannot reserve a megabyte.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| PolicyError::Malformed("version"))?;
        if version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(version));
        }
        let net_len = r
            .u16le()
            .map_err(|_| PolicyError::Malformed("network len"))? as usize;
        if net_len == 0 {
            return Err(PolicyError::EmptyNetworkId);
        }
        if net_len > MAX_NETWORK_ID_LEN {
            return Err(PolicyError::NetworkIdTooLong(net_len));
        }
        let net_bytes = r
            .fixed_slice(net_len)
            .map_err(|_| PolicyError::Malformed("network id"))?;
        let network_id = std::str::from_utf8(net_bytes)
            .map_err(|_| PolicyError::Malformed("network id is not utf-8"))?
            .to_string();

        let agent_id = r
            .fixed::<20>()
            .map_err(|_| PolicyError::Malformed("agent id"))?;
        let owner = r
            .fixed::<20>()
            .map_err(|_| PolicyError::Malformed("owner"))?;
        let role_raw = r.u8().map_err(|_| PolicyError::Malformed("role"))?;
        let role =
            AgentRole::from_u8(role_raw).ok_or(PolicyError::Malformed("role out of range"))?;
        let per_tx_max_sat = r
            .u64le()
            .map_err(|_| PolicyError::Malformed("per-tx limit"))?;
        let window_blocks = r.u64le().map_err(|_| PolicyError::Malformed("window"))?;
        let cumulative_max_sat = r
            .u64le()
            .map_err(|_| PolicyError::Malformed("cumulative limit"))?;

        let n_rec = r
            .u16le()
            .map_err(|_| PolicyError::Malformed("recipient count"))? as usize;
        if n_rec > MAX_POLICY_RECIPIENTS {
            return Err(PolicyError::TooManyRecipients {
                got: n_rec,
                cap: MAX_POLICY_RECIPIENTS,
            });
        }
        // Bounded by the remaining bytes before allocating.
        if n_rec * 20 > r.remaining() {
            return Err(PolicyError::Malformed("recipient list longer than input"));
        }
        let mut allowed_recipients = Vec::with_capacity(n_rec);
        for _ in 0..n_rec {
            allowed_recipients.push(
                r.fixed::<20>()
                    .map_err(|_| PolicyError::Malformed("recipient"))?,
            );
        }

        let n_svc = r
            .u16le()
            .map_err(|_| PolicyError::Malformed("service count"))? as usize;
        if n_svc > MAX_POLICY_SERVICES {
            return Err(PolicyError::TooManyServices {
                got: n_svc,
                cap: MAX_POLICY_SERVICES,
            });
        }
        if n_svc * 32 > r.remaining() {
            return Err(PolicyError::Malformed("service list longer than input"));
        }
        let mut allowed_services = Vec::with_capacity(n_svc);
        for _ in 0..n_svc {
            allowed_services.push(
                r.fixed::<32>()
                    .map_err(|_| PolicyError::Malformed("service tag"))?,
            );
        }

        let not_before_height = r
            .u64le()
            .map_err(|_| PolicyError::Malformed("not_before"))?;
        let expires_at_height = r
            .u64le()
            .map_err(|_| PolicyError::Malformed("expires_at"))?;
        let revoked_raw = r.u8().map_err(|_| PolicyError::Malformed("revoked flag"))?;
        let revoked = match revoked_raw {
            0 => false,
            1 => true,
            _ => return Err(PolicyError::Malformed("revoked flag not 0 or 1")),
        };
        let parent_agent_id = match r.u8().map_err(|_| PolicyError::Malformed("parent link"))? {
            0 => None,
            1 => Some(
                r.fixed::<20>()
                    .map_err(|_| PolicyError::Malformed("parent agent id"))?,
            ),
            _ => return Err(PolicyError::Malformed("parent link tag not 0 or 1")),
        };
        r.expect_end()
            .map_err(|_| PolicyError::Malformed("trailing bytes"))?;

        let policy = SpendPolicy {
            version,
            network_id,
            agent_id,
            owner,
            role,
            per_tx_max_sat,
            window_blocks,
            cumulative_max_sat,
            allowed_recipients,
            allowed_services,
            not_before_height,
            expires_at_height,
            revoked,
            parent_agent_id,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Structural self-consistency. Separate from `authorize` so a policy can
    /// be rejected at the point it is accepted, not at the point it is used.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(self.version));
        }
        if self.network_id.is_empty() {
            return Err(PolicyError::EmptyNetworkId);
        }
        if self.network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(PolicyError::NetworkIdTooLong(self.network_id.len()));
        }
        if self.allowed_recipients.len() > MAX_POLICY_RECIPIENTS {
            return Err(PolicyError::TooManyRecipients {
                got: self.allowed_recipients.len(),
                cap: MAX_POLICY_RECIPIENTS,
            });
        }
        if self.allowed_services.len() > MAX_POLICY_SERVICES {
            return Err(PolicyError::TooManyServices {
                got: self.allowed_services.len(),
                cap: MAX_POLICY_SERVICES,
            });
        }
        if self.expires_at_height <= self.not_before_height {
            return Err(PolicyError::ExpiryNotAfterStart {
                not_before: self.not_before_height,
                expires_at: self.expires_at_height,
            });
        }
        if self.per_tx_max_sat == 0 {
            return Err(PolicyError::ZeroPerTxLimit);
        }
        if self.window_blocks == 0 {
            return Err(PolicyError::ZeroWindowBlocks);
        }
        if self.per_tx_max_sat > self.cumulative_max_sat {
            return Err(PolicyError::PerTxAboveCumulative {
                per_tx: self.per_tx_max_sat,
                cumulative: self.cumulative_max_sat,
            });
        }
        // Identity binding: the id must actually be this owner's, for this
        // network, in this role. A policy cannot claim someone else's agent.
        //
        // A child policy proves itself differently: its id derives from the
        // parent it names, not from the owner whose funds it spends. Without
        // that split, a sub-agent with no funds of its own would either fail to
        // derive or — if it derived from the root owner — could re-derive the
        // root's id and inherit the root's power by presenting the root's owner.
        let expected = match self.parent_agent_id {
            Some(parent) => derive_sub_agent_id(&self.network_id, &parent, self.role),
            None => derive_agent_id(&self.network_id, self.role, &self.owner),
        };
        if expected != self.agent_id {
            return Err(PolicyError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Per-policy spend accounting. Deterministic and cheap to re-derive, so a
/// restart rebuilds it by replaying the authorizations it accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyState {
    /// Height the current tumbling window started at.
    pub window_start_height: u64,
    /// Spend inside the current window.
    pub spent_in_window_sat: u64,
    /// Lifetime spend, for audit only (not a limit).
    pub total_spent_sat: u64,
    /// Highest nonce used so far. `0` means none used yet.
    pub last_nonce: u64,
    /// How many authorizations this policy has produced.
    pub authorizations: u64,
}

impl PolicyState {
    pub fn new(start_height: u64) -> Self {
        PolicyState {
            window_start_height: start_height,
            ..Default::default()
        }
    }
}

/// What an agent asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub agent_id: AgentId,
    pub recipient: Address,
    pub amount_sat: u64,
    /// Optional service tag; required when the policy allows services at all.
    pub service: Option<[u8; 32]>,
    /// The height the authorization is evaluated at.
    pub height: u64,
    /// Strictly increasing per policy; the anti-replay counter.
    pub nonce: u64,
}

/// A granted authorization — the thing a service (or a bridge) checks before
/// doing work. Offline-verifiable: see [`verify_authorization`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub version: u8,
    /// Which policy granted this.
    pub policy_hash: Hash,
    pub agent_id: AgentId,
    pub owner: Address,
    pub recipient: Address,
    pub amount_sat: u64,
    pub service: Option<[u8; 32]>,
    pub height: u64,
    pub nonce: u64,
}

impl Authorization {
    /// Domain-separated hash the owner signs (or a service checks).
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(DOM_AGENT_AUTH, &[&self.serialize()])
    }

    /// Canonical, bounded encoding.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(160);
        w.u8(self.version)
            .fixed(&self.policy_hash)
            .fixed(&self.agent_id)
            .fixed(&self.owner)
            .fixed(&self.recipient)
            .u64le(self.amount_sat);
        match &self.service {
            Some(tag) => {
                w.u8(1).fixed(tag);
            }
            None => {
                w.u8(0);
            }
        }
        w.u64le(self.height).u64le(self.nonce);
        w.into_vec()
    }

    /// Decode the canonical encoding produced by [`Authorization::serialize`].
    ///
    /// The exact inverse of `serialize`, so the bytes `/v1/authorize` returns
    /// can be consumed by the payment layer that produced them. Strict and
    /// fail-closed: a short buffer, an unknown version, a trailing byte or an
    /// out-of-range service tag is refused by name rather than partially read.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| PolicyError::Malformed("version"))?;
        if version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(version));
        }
        let policy_hash = r
            .fixed::<32>()
            .map_err(|_| PolicyError::Malformed("policy hash"))?;
        let agent_id = r
            .fixed::<20>()
            .map_err(|_| PolicyError::Malformed("agent id"))?;
        let owner = r
            .fixed::<20>()
            .map_err(|_| PolicyError::Malformed("owner"))?;
        let recipient = r
            .fixed::<20>()
            .map_err(|_| PolicyError::Malformed("recipient"))?;
        let amount_sat = r.u64le().map_err(|_| PolicyError::Malformed("amount"))?;
        let service = match r.u8().map_err(|_| PolicyError::Malformed("service tag"))? {
            0 => None,
            1 => Some(
                r.fixed::<32>()
                    .map_err(|_| PolicyError::Malformed("service id"))?,
            ),
            _ => return Err(PolicyError::Malformed("service tag out of range")),
        };
        let height = r.u64le().map_err(|_| PolicyError::Malformed("height"))?;
        let nonce = r.u64le().map_err(|_| PolicyError::Malformed("nonce"))?;
        r.expect_end()
            .map_err(|_| PolicyError::Malformed("trailing bytes"))?;
        Ok(Authorization {
            version,
            policy_hash,
            agent_id,
            owner,
            recipient,
            amount_sat,
            service,
            height,
            nonce,
        })
    }
}

/// Check an authorization's signature against public key bundles.
///
/// This is the offline path: the holder of the signed authorization presents
/// `sigs`/`keys` and any third party verifies without the network, without the
/// policy, and without any private key.
///
/// **The keys must be the owner's.** `keys.address()` is checked against
/// `auth.owner` before the signature is looked at, so a third party cannot
/// mint its own "authorization", sign it with its own key and hand over its
/// own public keys as evidence — the signature would verify while proving
/// nothing about the owner's grant. Without this binding, offline
/// verification was only as trustworthy as the caller's key hygiene; with it,
/// the object authenticates itself.
pub fn verify_authorization(
    sigs: &crate::sig::Bundle,
    keys: &crate::sig::Bundle,
    auth: &Authorization,
) -> Result<(), crate::error::Error> {
    if keys.address()? != auth.owner {
        return Err(crate::error::Error::WrongAddress);
    }
    let msg = auth.signing_hash();
    crate::sig::verify_bundle(sigs, keys, &msg)
}

/// Bounded set of policies the engine tracks, keyed by policy hash.
///
/// Keying by hash is what makes **rotation** safe: a rotated-in policy has a
/// different hash, so it starts with a fresh window and cannot inherit the
/// old policy's spend — and a rotated-out policy is refused because its owner
/// marks it revoked.
#[derive(Debug, Clone)]
pub struct PolicyBook {
    states: BTreeMap<Hash, PolicyState>,
    max_policies: usize,
}

impl Default for PolicyBook {
    fn default() -> Self {
        PolicyBook::with_capacity(DEFAULT_MAX_POLICIES)
    }
}

impl PolicyBook {
    pub fn with_capacity(max_policies: usize) -> Self {
        PolicyBook {
            states: BTreeMap::new(),
            max_policies,
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub fn state(&self, policy_hash: &Hash) -> Option<&PolicyState> {
        self.states.get(policy_hash)
    }

    /// Forget a policy's accounting (used when a policy is rotated out).
    pub fn forget(&mut self, policy_hash: &Hash) -> Option<PolicyState> {
        self.states.remove(policy_hash)
    }

    /// The one entry point. Validates the policy, checks every clause in a
    /// documented order, and only then commits the accounting.
    ///
    /// Nothing is mutated on any error path: a refused authorization leaves the
    /// state exactly as it was.
    pub fn authorize(
        &mut self,
        policy: &SpendPolicy,
        network_id: &str,
        req: &AuthorizationRequest,
    ) -> Result<Authorization, PolicyError> {
        // 1. the policy must be structurally sound at all
        policy.validate()?;

        // 2. network binding
        if policy.network_id != network_id {
            return Err(PolicyError::WrongNetwork {
                expected: policy.network_id.clone(),
                got: network_id.to_string(),
            });
        }

        // 3. the request must be about this agent
        if req.agent_id != policy.agent_id {
            return Err(PolicyError::WrongAgent);
        }

        // 4. kill switch
        if policy.revoked {
            return Err(PolicyError::PolicyRevoked);
        }

        // 5. validity window
        if req.height < policy.not_before_height {
            return Err(PolicyError::NotYetValid {
                not_before: policy.not_before_height,
                height: req.height,
            });
        }
        if req.height >= policy.expires_at_height {
            return Err(PolicyError::PolicyExpired {
                expires_at: policy.expires_at_height,
                height: req.height,
            });
        }

        // 6. amount sanity before any accounting
        if req.amount_sat == 0 {
            return Err(PolicyError::ZeroAmount);
        }
        if req.amount_sat > policy.per_tx_max_sat {
            return Err(PolicyError::PerTxLimitExceeded {
                amount: req.amount_sat,
                limit: policy.per_tx_max_sat,
            });
        }

        // 7. recipient allow list (empty = nothing)
        if !policy.allowed_recipients.contains(&req.recipient) {
            return Err(PolicyError::RecipientNotAllowed);
        }

        // 8. service allow list (empty = no service payments)
        match &req.service {
            None => {
                if !policy.allowed_services.is_empty() {
                    // A tagged policy does not authorize untagged spending:
                    // the tag is how the owner restricts *what* the money buys.
                    return Err(PolicyError::ServiceNotAllowed);
                }
            }
            Some(tag) => {
                if !policy.allowed_services.contains(tag) {
                    return Err(PolicyError::ServiceNotAllowed);
                }
            }
        }

        // 9. accounting, using the policy's own state. A policy not yet seen
        //    starts its window at the first authorization's height.
        let hash = policy.hash();
        if !self.states.contains_key(&hash) {
            if self.states.len() >= self.max_policies {
                return Err(PolicyError::PolicyBookFull {
                    cap: self.max_policies,
                });
            }
            self.states.insert(hash, PolicyState::new(req.height));
        }
        let state = self.states.get(&hash).copied().unwrap_or_default();

        // Timestamps cannot run backwards inside one policy.
        if req.height < state.window_start_height {
            return Err(PolicyError::HeightWentBackwards {
                window_start: state.window_start_height,
                height: req.height,
            });
        }

        // Anti-replay: strictly increasing nonce.
        if req.nonce <= state.last_nonce {
            return Err(PolicyError::NonceNotIncreasing {
                nonce: req.nonce,
                last_nonce: state.last_nonce,
            });
        }

        // Tumbling window rollover, forward only and overflow-safe.
        let window_end = state
            .window_start_height
            .checked_add(policy.window_blocks)
            .ok_or(PolicyError::Overflow)?;
        let (window_start, spent_in_window) = if req.height >= window_end {
            (req.height, 0u64)
        } else {
            (state.window_start_height, state.spent_in_window_sat)
        };

        // Cumulative limit for the window.
        let requested = spent_in_window
            .checked_add(req.amount_sat)
            .ok_or(PolicyError::Overflow)?;
        if requested > policy.cumulative_max_sat {
            return Err(PolicyError::CumulativeLimitExceeded {
                requested,
                limit: policy.cumulative_max_sat,
            });
        }

        // Commit.
        let total = state
            .total_spent_sat
            .checked_add(req.amount_sat)
            .ok_or(PolicyError::Overflow)?;
        let count = state
            .authorizations
            .checked_add(1)
            .ok_or(PolicyError::Overflow)?;
        self.states.insert(
            hash,
            PolicyState {
                window_start_height: window_start,
                spent_in_window_sat: requested,
                total_spent_sat: total,
                last_nonce: req.nonce,
                authorizations: count,
            },
        );

        Ok(Authorization {
            version: POLICY_VERSION,
            policy_hash: hash,
            agent_id: policy.agent_id,
            owner: policy.owner,
            recipient: req.recipient,
            amount_sat: req.amount_sat,
            service: req.service,
            height: req.height,
            nonce: req.nonce,
        })
    }
}

/// Largest entry count the policy-book codec will read back, and the largest
/// capacity it will restore. Checked before any allocation; real books are
/// capped at [`DEFAULT_MAX_POLICIES`].
const MAX_POLICY_BOOK_READ: usize = 1 << 20;

/// Restart recovery for the whole book: the per-policy accounting windows,
/// nonces and audit totals a node has already committed.
///
/// The book is node-local and non-consensus, but losing it loses every spent
/// nonce and every window's tally - after a restart the first replayed
/// authorization would look fresh. The encoding stores the book's own cap and
/// refuses to restore more entries than it allows.
impl PolicyBook {
    /// Canonical encoding of the whole book.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(16 + self.states.len() * 48);
        w.u64le(self.max_policies as u64);
        w.u32le(self.states.len() as u32);
        for (hash, state) in &self.states {
            w.fixed(hash)
                .u64le(state.window_start_height)
                .u64le(state.spent_in_window_sat)
                .u64le(state.total_spent_sat)
                .u64le(state.last_nonce)
                .u64le(state.authorizations);
        }
        w.into_vec()
    }

    /// Decode what [`PolicyBook::encode`] wrote. Bounded and fail-closed: a
    /// count above the book's own capacity, a duplicate policy hash, or
    /// trailing bytes produce an error rather than a half-built book.
    pub fn decode(r: &mut crate::ser::Reader<'_>) -> Result<Self, crate::error::Error> {
        use crate::error::Error;
        let max_raw = r.u64le()?;
        if max_raw > MAX_POLICY_BOOK_READ as u64 {
            return Err(Error::Malformed("policy book capacity over codec cap"));
        }
        let max = max_raw as usize;
        let count = r.u32le()? as usize;
        if count > max {
            return Err(Error::Malformed("policy count over book capacity"));
        }
        let mut book = PolicyBook::with_capacity(max);
        for _ in 0..count {
            let hash: crate::hash::Hash = r.fixed()?;
            let state = PolicyState {
                window_start_height: r.u64le()?,
                spent_in_window_sat: r.u64le()?,
                total_spent_sat: r.u64le()?,
                last_nonce: r.u64le()?,
                authorizations: r.u64le()?,
            };
            book.states.insert(hash, state);
        }
        if book.states.len() != count {
            return Err(Error::Malformed("duplicate policy hash in book"));
        }
        Ok(book)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Address {
        [7u8; 20]
    }

    fn policy(network: &str) -> SpendPolicy {
        let owner = owner();
        SpendPolicy {
            version: POLICY_VERSION,
            network_id: network.to_string(),
            agent_id: derive_agent_id(network, AgentRole::Machine, &owner),
            owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 600,
            window_blocks: 10,
            cumulative_max_sat: 1_000,
            allowed_recipients: vec![[1u8; 20], [2u8; 20]],
            allowed_services: Vec::new(),
            not_before_height: 0,
            expires_at_height: 1_000,
            revoked: false,
            parent_agent_id: None,
        }
    }

    fn req(
        agent: AgentId,
        to: Address,
        amount: u64,
        height: u64,
        nonce: u64,
    ) -> AuthorizationRequest {
        AuthorizationRequest {
            agent_id: agent,
            recipient: to,
            amount_sat: amount,
            service: None,
            height,
            nonce,
        }
    }

    #[test]
    fn a_well_formed_policy_round_trips_and_validates() {
        let p = policy("jounit/testnet");
        p.validate().expect("policy must validate");
        let bytes = p.serialize();
        assert_eq!(SpendPolicy::deserialize(&bytes).unwrap(), p);
    }

    #[test]
    fn the_policy_book_survives_restart_round_trip() {
        let p = policy("jounit/testnet");
        let mut book = PolicyBook::default();
        book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 400, 5, 1))
            .unwrap();

        let bytes = book.encode();
        let mut cursor = crate::ser::Reader::new(&bytes);
        let mut back = PolicyBook::decode(&mut cursor).expect("book decodes");
        assert!(cursor.is_done(), "decode must consume exactly its bytes");
        assert_eq!(back.encode(), bytes, "re-encode must be byte-identical");
        assert_eq!(back.len(), 1);
        let state = back.state(&p.hash()).expect("accounting restored");
        assert_eq!(state.last_nonce, 1);
        assert_eq!(state.spent_in_window_sat, 400);
        // The nonce is still spent: replaying the grant refuses after restart.
        assert!(back
            .authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 400, 5, 1))
            .is_err());

        // A count beyond the book's own capacity is refused before any read.
        let mut lying = bytes.clone();
        lying[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PolicyBook::decode(&mut crate::ser::Reader::new(&lying)).is_err());
    }

    #[test]
    fn many_small_payments_cannot_bypass_the_cumulative_limit() {
        let p = policy("jounit/testnet");
        let mut book = PolicyBook::default();
        // 400 + 400 = 800 <= 1000; the third would reach 1200.
        book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 400, 5, 1))
            .expect("first payment is inside the window");
        book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 400, 6, 2))
            .expect("second payment is inside the window");
        let err = book
            .authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 400, 7, 3))
            .unwrap_err();
        assert_eq!(
            err,
            PolicyError::CumulativeLimitExceeded {
                requested: 1_200,
                limit: 1_000
            }
        );
        // The refusal did not consume any of the budget.
        let st = book.state(&p.hash()).copied().unwrap();
        assert_eq!(st.spent_in_window_sat, 800);
    }

    #[test]
    fn the_window_rolls_forward_and_restores_the_budget() {
        let p = policy("jounit/testnet");
        let mut book = PolicyBook::default();
        book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 600, 5, 1))
            .unwrap();
        // still inside the window: 600 + 600 > 1000
        assert!(book
            .authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 600, 9, 2))
            .is_err());
        // height 15 is past 5 + 10, so the window resets
        book.authorize(
            &p,
            "jounit/testnet",
            &req(p.agent_id, [1u8; 20], 600, 15, 3),
        )
        .expect("a new window restores the budget");
        let st = book.state(&p.hash()).copied().unwrap();
        assert_eq!(st.window_start_height, 15);
        assert_eq!(st.spent_in_window_sat, 600);
        assert_eq!(st.total_spent_sat, 1_200);
    }

    #[test]
    fn empty_allow_lists_authorize_nothing() {
        let mut p = policy("jounit/testnet");
        p.allowed_recipients.clear();
        let mut book = PolicyBook::default();
        assert_eq!(
            book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 10, 5, 1))
                .unwrap_err(),
            PolicyError::RecipientNotAllowed
        );

        let mut q = policy("jounit/testnet");
        q.allowed_services = vec![[9u8; 32]];
        let mut book = PolicyBook::default();
        assert_eq!(
            book.authorize(&q, "jounit/testnet", &req(q.agent_id, [1u8; 20], 10, 5, 1))
                .unwrap_err(),
            PolicyError::ServiceNotAllowed
        );
        let mut tagged = req(q.agent_id, [1u8; 20], 10, 5, 1);
        tagged.service = Some([9u8; 32]);
        book.authorize(&q, "jounit/testnet", &tagged)
            .expect("the allowed service tag is authorized");
    }

    #[test]
    fn replay_and_non_monotonic_nonces_are_refused() {
        let p = policy("jounit/testnet");
        let mut book = PolicyBook::default();
        book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 10, 5, 7))
            .unwrap();
        assert_eq!(
            book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 10, 6, 7))
                .unwrap_err(),
            PolicyError::NonceNotIncreasing {
                nonce: 7,
                last_nonce: 7
            }
        );
        assert!(book
            .authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 10, 6, 6))
            .is_err());
    }

    #[test]
    fn identity_is_bound_to_owner_role_and_network() {
        let mut p = policy("jounit/testnet");
        p.agent_id = derive_agent_id("jounit/mini", AgentRole::Machine, &p.owner);
        assert_eq!(p.validate().unwrap_err(), PolicyError::IdentityMismatch);

        let mut q = policy("jounit/testnet");
        q.owner = [8u8; 20];
        assert_eq!(q.validate().unwrap_err(), PolicyError::IdentityMismatch);
    }

    #[test]
    fn revocation_and_network_mismatch_fail_closed() {
        let mut p = policy("jounit/testnet");
        p.revoked = true;
        let mut book = PolicyBook::default();
        assert_eq!(
            book.authorize(&p, "jounit/testnet", &req(p.agent_id, [1u8; 20], 10, 5, 1))
                .unwrap_err(),
            PolicyError::PolicyRevoked
        );

        let p = policy("jounit/testnet");
        assert!(matches!(
            book.authorize(&p, "jounit/mini", &req(p.agent_id, [1u8; 20], 10, 5, 1)),
            Err(PolicyError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn truncated_and_lying_encodings_are_refused() {
        let p = policy("jounit/testnet");
        let bytes = p.serialize();
        assert!(SpendPolicy::deserialize(&bytes[..bytes.len() - 1]).is_err());
        assert!(SpendPolicy::deserialize(&[&bytes[..], &[0u8]].concat()).is_err());

        // A declared recipient count far larger than the bytes present. The
        // offset is derived from a real encoding rather than hand-counted, so
        // this test cannot drift when the layout changes.
        let mut lying = p.serialize();
        let n_rec_offset = 1 + 2 + p.network_id.len() + 20 + 20 + 1 + 8 + 8 + 8;
        assert_eq!(
            u16::from_le_bytes([lying[n_rec_offset], lying[n_rec_offset + 1]]) as usize,
            p.allowed_recipients.len(),
            "recipient count must sit where the test thinks it does"
        );
        lying[n_rec_offset..n_rec_offset + 2].copy_from_slice(&60_000u16.to_le_bytes());
        assert_eq!(
            SpendPolicy::deserialize(&lying).unwrap_err(),
            PolicyError::TooManyRecipients {
                got: 60_000,
                cap: MAX_POLICY_RECIPIENTS
            }
        );
    }

    fn granted_authorization() -> Authorization {
        let mut p = policy("jounit/testnet");
        // Exercise the tagged branch: an authorization that names a service.
        p.allowed_services = vec![[0x5Au8; 32]];
        let mut book = PolicyBook::default();
        let mut r = req(p.agent_id, [1u8; 20], 400, 5, 1);
        r.service = Some([0x5Au8; 32]);
        book.authorize(&p, "jounit/testnet", &r)
            .expect("inside the policy")
    }

    #[test]
    fn an_authorization_round_trips_through_its_canonical_encoding() {
        let a = granted_authorization();
        let bytes = a.serialize();
        let back =
            Authorization::deserialize(&bytes).expect("the inverse must decode its own bytes");
        assert_eq!(back, a);
        // The signing hash is a function of the encoding, so a decoder that
        // dropped or reordered a field would fail here rather than verify.
        assert_eq!(back.signing_hash(), a.signing_hash());
        assert!(
            a.service.is_some(),
            "the fixture exercises the tagged branch"
        );
    }

    #[test]
    fn a_truncated_lengthened_or_unknown_authorization_is_refused() {
        let a = granted_authorization();
        let bytes = a.serialize();
        assert!(Authorization::deserialize(&bytes[..bytes.len() - 1]).is_err());
        assert!(Authorization::deserialize(&[bytes.clone(), vec![0u8]].concat()).is_err());
        let mut wrong = bytes.clone();
        wrong[0] = 0xFF;
        assert_eq!(
            Authorization::deserialize(&wrong).unwrap_err(),
            PolicyError::UnsupportedVersion(0xFF)
        );
    }
}
