//! Network profiles. SPEC.md §10.
//!
//! Section 17 of the design doc requires the mini version to be the *same code*
//! with different parameters — never a second codebase. Every consensus constant
//! therefore lives here, and the mini profile differs only in numbers.

use crate::bls_checkpoint::BlsPublicKey;
use crate::error::{Error, Result};
use crate::hash::{Address, Hash};

pub const SAT_PER_JNT: u64 = 100_000_000;

/// Domain tag for the L2 protocol-escrow identity (Decision 7, SPEC.md §19.4).
/// The escrow address is `SHA256(tag ‖ network_id)[..20]`: deterministic per
/// network, consensus-visible, and holding no key — value parked there moves
/// only by protocol rule, never by signature.
pub const DOM_L2_ESCROW: &[u8] = b"jounit/l2-escrow/v1";

/// Domain tag for the L2 deposit sink (Decision 10, SPEC.md §19.5). A distinct
/// tag from the escrow identity so the two can never coincide; a sink output
/// is an ordinary L1 payment that L2 replay interprets as a deposit.
pub const DOM_L2_DEPOSIT_SINK: &[u8] = b"jounit/l2-deposit-sink/v1";

/// Minimum deposit per sink output, in satoshis (Decision 10 item 3). A
/// dust/bloat floor, not a fee: every credited deposit leaves permanent
/// unspendable UTXO entries, so crediting dust would bloat both ledgers for
/// free. Identical on both profiles — it is economic, not timing.
pub const L2_DEPOSIT_MINIMUM_SAT: u64 = 1_000_000;

/// Flat fee per L2 transaction type, in satoshis (decision D3).
///
/// Flat **per type, not per byte.** A worker deciding whether to post a task has
/// to know the price before it builds the transaction, and a size-metered fee
/// makes the price of the same logical operation depend on how the payload
/// serializer happens to encode it.
///
/// **These do not clear the L1 fee floor, and they are not supposed to.** The
/// only L1 fee rule is `base_fee * gas_used` (`fees::required_fee`), and even the
/// smallest transaction uses `GAS_TX_BASE` gas, so that floor is orders of
/// magnitude above every number below. Decision D3 resolved this by giving L2 a
/// fee path of its own rather than an exemption: `l2::L2TxType::fee_sat` returns
/// these values, and `fees::split_flat_fee` routes the whole flat fee through the
/// unchanged M1 50/50 burn/PSCB rule. The L1 floor is untouched and L2 never
/// consults it. `l2_fees_do_not_use_the_l1_gas_floor` pins that separation.
pub const FEE_TX_POST_TASK_SAT: u64 = 5_000;
pub const FEE_TX_CLAIM_TASK_SAT: u64 = 2_000;
pub const FEE_TX_SUBMIT_RESULT_SAT: u64 = 2_000;
pub const FEE_TX_DISPUTE_SAT: u64 = 10_000;
pub const FEE_TX_SETTLE_SAT: u64 = 20_000;

/// The D3 schedule as one table, so the exact set is asserted in one place and a
/// future change has a single spot to be checked against the decision record.
pub const L2_FEE_SCHEDULE: &[(&str, u64)] = &[
    ("TxPostTask", FEE_TX_POST_TASK_SAT),
    ("TxClaimTask", FEE_TX_CLAIM_TASK_SAT),
    ("TxSubmitResult", FEE_TX_SUBMIT_RESULT_SAT),
    ("TxDispute", FEE_TX_DISPUTE_SAT),
    ("TxSettle", FEE_TX_SETTLE_SAT),
];

/// One genesis-funded L2 balance (Decision 7, SPEC.md §19.4).
///
/// The address is a plain L2 account address; the amount is satoshis released
/// to it once, at L2 genesis, out of the profile's escrow total. Mainnet
/// carries no grants (real allocation arrives with the deposit mechanism, and
/// inventing mainnet beneficiaries here would be inventing economics); `mini`
/// grants three deterministic operator identities so the funded flow is
/// exercisable end to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2GenesisGrant {
    pub address: Address,
    pub amount_sat: u64,
}

/// Address of the deterministic `mini` operator identity for `seed`.
///
/// The same derivation the integration tests use for their wallets
/// (`Wallet::from_private_key_bytes(&[seed; 32])`), so the genesis grants name
/// accounts the tests can actually sign for. Seeds are public test values, not
/// secrets: `mini` is the integration profile, and mainnet carries no grants.
fn l2_operator_address(seed: u8) -> Address {
    crate::wallet::Wallet::from_private_key_bytes(&[seed; 32], "l2-genesis-operator")
        .expect("constant seeds are valid scalars")
        .address()
        .expect("a wallet always has an address")
}

/// Deterministic `mini` validator key for `seed`.
///
/// Derives a real BLS12-381 public key from the same public test seeds, so
/// the mini committee is a valid committee and checkpoint verification is
/// exercisable. The seeds are public test values; `mainnet` carries no
/// committee. Panics only if `min_pk` rejects a constant seed, which is a
/// build-time property, not a runtime input.
fn mini_validator_key(seed: u8) -> BlsPublicKey {
    mini_validator_secret(seed).public_key()
}

/// The deterministic `mini` committee secret for `seed`.
///
/// Public test material, not a secret in the cryptographic sense: these seeds
/// are in the source, so anyone can sign as a mini validator — which is
/// exactly what a permissionless testnet committee means. Exposed so tests
/// (and mini validator nodes) can produce real checkpoint certificates.
/// `mainnet` has no committee and therefore no corresponding secrets.
pub fn mini_validator_secret(seed: u8) -> crate::bls::SecretKey {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed;
    crate::bls::SecretKey::derive(&s).expect("constant seeds are valid scalars")
}

/// The four `mini` committee secrets, in the same order as the seeds.
pub fn mini_committee_secrets() -> Vec<crate::bls::SecretKey> {
    (1u8..=4).map(mini_validator_secret).collect()
}

/// Deterministic `testnet` validator key for `seed` (Decision 13).
///
/// A distinct seed domain from `mini`'s, so testnet and mini committees never
/// coincide, while staying a pure function of the seed — no runtime entropy,
/// two independently constructed `testnet` profiles are identical.
pub fn testnet_validator_key(seed: u8) -> BlsPublicKey {
    testnet_validator_secret(seed).public_key()
}

/// The deterministic `testnet` committee secret for `seed`. Public test
/// material (the seeds are in source), matching the mini committee's status.
pub fn testnet_validator_secret(seed: u8) -> crate::bls::SecretKey {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[16] = seed;
    s[31] = seed;
    crate::bls::SecretKey::derive(&s).expect("constant seeds are valid scalars")
}

/// The four `testnet` committee secrets, in the same order as the seeds.
pub fn testnet_committee_secrets() -> Vec<crate::bls::SecretKey> {
    (1u8..=4).map(testnet_validator_secret).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    pub name: String,
    /// Block spacing the difficulty retarget algorithm aims for.
    pub target_block_time_ms: u64,
    /// Blocks between halvings.
    pub halving_period: u64,
    /// Block reward at halving 0, in satoshis.
    pub start_reward_sat: u64,
    /// Hard supply ceiling in satoshis. Never exceeded — enforced in `supply.rs`.
    pub supply_cap_sat: u64,
    pub difficulty_window: u32,
    /// Max per-block difficulty change, in basis points (1000 = +/-10%).
    pub change_limit_bps: u32,
    pub genesis_difficulty: u128,
    pub min_difficulty: u128,
    pub max_difficulty: u128,
    /// Blocks before coinbase value is spendable.
    pub coinbase_maturity: u64,
    /// Blocks below the tip that can never be reorganized away.
    pub finality_depth: u64,
    pub gas_cap: u64,
    pub base_fee_initial_sat: u64,
    pub base_fee_min_sat: u64,
    pub base_fee_max_sat: u64,
    /// Height interval after which the neural-net weights rotate.
    pub nn_epoch_blocks: u64,
    pub puzzle_id: u64,
    pub max_tx_count: usize,
    pub max_block_bytes: usize,
    /// Reject inputs that carry a single-scheme signature bundle, requiring a
    /// hybrid (multi-scheme) one. Off by default so existing single-scheme
    /// transactions stay valid; flipping it on is how a network would declare
    /// itself post-quantum ready without a hard fork.
    pub require_hybrid_signatures: bool,
    /// 4-byte discriminator checked on every incoming frame (§13.2/§13.3) and
    /// mandatory in the handshake. `mainnet` and `mini` MUST differ; reuse
    /// across two live networks lets a node accept a foreign chain's traffic.
    /// Zero is rejected by `validate()`.
    pub network_magic: [u8; 4],
    /// Human-readable network tag exchanged in the handshake (§13.4). Also
    /// distinguishes profiles when a magic collision is ever introduced.
    pub network_id: String,
    /// Total L2 genesis allocation in satoshis (Decision 7, SPEC.md §19.4).
    /// Released once, at L2 genesis: the grants below plus the remainder to
    /// the protocol escrow identity. Must fit in the sats the L1 ladder can
    /// never mint (`supply_cap_sat - max_issuance_sat`), so combined L1 + L2
    /// money can never exceed the cap with zero L1 consensus change.
    pub l2_genesis_escrow_sat: u64,
    /// Genesis-funded L2 accounts, paid out of `l2_genesis_escrow_sat`.
    pub l2_genesis_grants: Vec<L2GenesisGrant>,
    /// Minimum deposit per sink output in satoshis (Decision 10, SPEC.md
    /// §19.5). A per-profile field rather than the shared constant so a
    /// future network can price its own dust floor without touching code —
    /// but both shipped profiles carry the constant's value.
    pub l2_deposit_minimum_sat: u64,
    /// Fixed genesis validator committee (Decisions 8 and 11, SPEC.md §14).
    /// Explicit BLS keys, no stake ledger behind them: Phase 6 has no bonded
    /// stake, so these keys carry authority by genesis declaration, not by
    /// bond. `mini` carries deterministic test keys; `mainnet` carries an
    /// empty list, meaning no committee yet — checkpoints verify against
    /// nothing and therefore fail closed. Canonically sorted by key bytes at
    /// construction; every node holding these params derives the same set.
    pub genesis_validators: Vec<BlsPublicKey>,
    /// Blocks per checkpoint epoch (Decision 11). `mini` uses 10 so finality
    /// observation is exercisable in tests; `mainnet` uses 100.
    pub checkpoint_interval_blocks: u64,
    /// Height at which a valid checkpoint certificate becomes **binding**
    /// finality (Decisions 12/13, SPEC.md §14.8). `0` means never: the profile
    /// keeps the depth-based fallback only. A checkpoint at a height below this
    /// is observed but never gates `Chain::adopt()`.
    pub finality_activation_height: u64,
}

impl NetworkParams {
    /// Deterministic future-timestamp allowance (SPEC.md §6.1).
    ///
    /// The 2-hour allowance used by Bitcoin was shown by `sim/difficulty_attack_sim.py`
    /// to let a 40% attacker pull difficulty down; one block time does not.
    pub fn future_limit_ms(&self) -> u64 {
        self.target_block_time_ms
    }

    pub fn supply_cap_jnt(&self) -> u64 {
        self.supply_cap_sat / SAT_PER_JNT
    }

    /// The protocol escrow identity holding the un-granted remainder of the L2
    /// genesis allocation (Decision 7, SPEC.md §19.4).
    ///
    /// Derived, not stored: `SHA256(DOM_L2_ESCROW ‖ network_id)[..20]`. Every
    /// node holding these params derives the same address, and no wallet can
    /// hold its key — the remainder is inert until a later milestone authorises
    /// a disbursement rule for it.
    pub fn l2_escrow_address(&self) -> Address {
        let digest: Hash = crate::hash::sha256_dom(DOM_L2_ESCROW, &[self.network_id.as_bytes()]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        out
    }

    /// The deposit sink: an ordinary address nobody can spend from (Decision
    /// 10, SPEC.md §19.5).
    ///
    /// Derived exactly like the escrow identity but under its own domain tag,
    /// so the two can never coincide, and bound to `network_id` so one
    /// network's sink is another network's ordinary burn address. A STANDARD
    /// payment here is valid L1 with no rule change; only L2 replay reads a
    /// deposit into it.
    pub fn l2_deposit_sink(&self) -> Address {
        let digest: Hash =
            crate::hash::sha256_dom(DOM_L2_DEPOSIT_SINK, &[self.network_id.as_bytes()]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        out
    }

    /// Satoshis granted to named accounts at L2 genesis. Checked, not summed
    /// with `+`: a crafted params value overflowing here would understate the
    /// allocation and admit funding above the escrow total.
    pub fn l2_granted_sat(&self) -> Result<u64> {
        let mut total = 0u64;
        for g in &self.l2_genesis_grants {
            total = total
                .checked_add(g.amount_sat)
                .ok_or(Error::Malformed("l2 genesis grants overflow"))?;
        }
        Ok(total)
    }

    pub fn start_reward_jnt(&self) -> u64 {
        self.start_reward_sat / SAT_PER_JNT
    }

    pub fn by_name(name: &str) -> Result<Self> {
        match name {
            "mainnet" => Ok(Self::mainnet()),
            "mini" => Ok(Self::mini()),
            "testnet" => Ok(Self::testnet()),
            _ => Err(Error::Malformed(
                "unknown network; use \"mainnet\", \"testnet\", or \"mini\"",
            )),
        }
    }

    /// Mainnet: 10-minute blocks, ~40M cap, 5-year halving (SPEC.md §7, §10).
    pub fn mainnet() -> Self {
        NetworkParams {
            name: "mainnet".into(),
            target_block_time_ms: 600_000,
            halving_period: 262_800,
            start_reward_sat: 76 * SAT_PER_JNT,
            supply_cap_sat: 39_945_600 * SAT_PER_JNT,
            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: crate::u256::MAX_DIFFICULTY,
            coinbase_maturity: 100,
            finality_depth: 100,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 1_000,
            base_fee_min_sat: 100,
            base_fee_max_sat: 50_000_000,
            nn_epoch_blocks: 50_000,
            puzzle_id: 1,
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            network_magic: [0x6A, 0x4E, 0x54, 0x01],
            network_id: "jounit/mainnet".into(),
            // The L2 genesis escrow (Decision 7): 100,000 JNT of the 788,400
            // JNT the ladder can never mint, held entirely by the protocol
            // escrow identity. No mainnet grants — real beneficiaries arrive
            // with the deposit mechanism, not as hard-coded allocations.
            l2_genesis_escrow_sat: 100_000 * SAT_PER_JNT,
            l2_genesis_grants: Vec::new(),
            l2_deposit_minimum_sat: L2_DEPOSIT_MINIMUM_SAT,
            // No committee yet: mainnet finality observation arrives with the
            // testnet standup, not as placeholder keys. Empty verifies nothing
            // (fail closed), which is the honest pre-committee state.
            genesis_validators: Vec::new(),
            checkpoint_interval_blocks: 100,
            // Binding finality is not activated on mainnet (Decision 12):
            // `0` keeps the depth-based fallback only.
            finality_activation_height: 0,
        }
    }

    /// Mini: identical logic, parameters chosen so a full halving cycle and a
    /// reorg both happen within minutes. Used to validate the production code
    /// end to end (SPEC.md §10, design doc Section 17 step 3).
    pub fn mini() -> Self {
        NetworkParams {
            name: "mini".into(),
            target_block_time_ms: 1_000,
            halving_period: 2_000,
            start_reward_sat: 76 * SAT_PER_JNT,
            supply_cap_sat: 304_000 * SAT_PER_JNT,
            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: 1u128 << 40,
            coinbase_maturity: 10,
            finality_depth: 20,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 100,
            base_fee_min_sat: 10,
            base_fee_max_sat: 1_000_000,
            nn_epoch_blocks: 2_000,
            puzzle_id: 1,
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            // Distinct 4-byte magic so a mini peer can never be mistaken for
            // mainnet at the framing layer (§13.3). Genesis cannot do that job:
            // both profiles have genesis_difficulty=1, so genesis_block() is
            // identical, hence the identical genesis hash.
            network_magic: [0x6A, 0x4E, 0x54, 0x02],
            network_id: "jounit/mini".into(),
            // 10 JNT of the 6,000 JNT gap: 3 × 1 JNT to deterministic operator
            // identities (seeds 1–3, whose keys the integration tests hold),
            // 7 JNT remainder to the protocol escrow identity.
            l2_genesis_escrow_sat: 10 * SAT_PER_JNT,
            l2_genesis_grants: vec![
                L2GenesisGrant {
                    address: l2_operator_address(1),
                    amount_sat: SAT_PER_JNT,
                },
                L2GenesisGrant {
                    address: l2_operator_address(2),
                    amount_sat: SAT_PER_JNT,
                },
                L2GenesisGrant {
                    address: l2_operator_address(3),
                    amount_sat: SAT_PER_JNT,
                },
            ],
            l2_deposit_minimum_sat: L2_DEPOSIT_MINIMUM_SAT,
            // Test committee (Decision 11, SPEC.md §14): deterministic
            // BLS keys so mini exercises checkpoint finality end to end.
            genesis_validators: {
                let mut v: Vec<BlsPublicKey> = (1u8..=4).map(mini_validator_key).collect();
                v.sort_by_key(|a| a.0);
                v.dedup();
                v
            },
            checkpoint_interval_blocks: 10,
            // M4 built the machinery; M5 does not activate binding finality on
            // mini either (that is the dedicated `testnet` profile's job), so
            // mini keeps depth-only finality.
            finality_activation_height: 0,
        }
    }

    /// Testnet: the binding-finality profile (Decision 13). Fast blocks and a
    /// small deterministic committee so the full finality path — certificate,
    /// quorum, conflict, reorg-refusal — is exercisable end to end before any
    /// public deployment.
    ///
    /// Distinct `network_magic`/`network_id` from both other profiles; genesis
    /// is (as always) identical, so the magic/id are the chain identifiers.
    /// No staking, no rotation: the committee is the fixed genesis list.
    pub fn testnet() -> Self {
        NetworkParams {
            name: "testnet".into(),
            target_block_time_ms: 1_000,
            halving_period: 2_000,
            start_reward_sat: 76 * SAT_PER_JNT,
            supply_cap_sat: 304_000 * SAT_PER_JNT,
            difficulty_window: 60,
            change_limit_bps: 1_000,
            genesis_difficulty: 1,
            min_difficulty: 1,
            max_difficulty: 1u128 << 40,
            coinbase_maturity: 10,
            // Depth fallback before activation (Decision 12). After activation
            // the checkpoint rule is authoritative and strictly stronger.
            finality_depth: 20,
            gas_cap: 2_000_000,
            base_fee_initial_sat: 100,
            base_fee_min_sat: 10,
            base_fee_max_sat: 1_000_000,
            nn_epoch_blocks: 2_000,
            puzzle_id: 1,
            max_tx_count: 5_000,
            max_block_bytes: 4_000_000,
            require_hybrid_signatures: false,
            network_magic: [0x6A, 0x4E, 0x54, 0x03],
            network_id: "jounit/testnet".into(),
            // Testnet carries no user grants yet (deposits/exits remain
            // deferred); the escrow is a real, accountable genesis reserve.
            l2_genesis_escrow_sat: 10 * SAT_PER_JNT,
            l2_genesis_grants: Vec::new(),
            l2_deposit_minimum_sat: L2_DEPOSIT_MINIMUM_SAT,
            // Four deterministic testnet keys (distinct derivation from mini),
            // canonically sorted. Quorum for n=4 is ceil(4×6667/10000)=3.
            genesis_validators: {
                let mut v: Vec<BlsPublicKey> = (1u8..=4).map(testnet_validator_key).collect();
                v.sort_by_key(|a| a.0);
                v.dedup();
                v
            },
            checkpoint_interval_blocks: 10,
            // Binding finality turns on at height 20 (Decision 13): an explicit,
            // deterministic activation condition. Below it, observed
            // certificates are never binding.
            finality_activation_height: 20,
        }
    }

    /// Reject a profile that could never produce a valid block.
    pub fn validate(&self) -> Result<()> {
        if self.target_block_time_ms == 0 {
            return Err(Error::Malformed("target_block_time_ms must be > 0"));
        }
        if self.halving_period == 0 {
            return Err(Error::Malformed("halving_period must be > 0"));
        }
        if self.genesis_difficulty < self.min_difficulty {
            return Err(Error::Malformed("genesis_difficulty below min_difficulty"));
        }
        if self.max_difficulty < self.min_difficulty {
            return Err(Error::Malformed("max_difficulty below min_difficulty"));
        }
        if self.max_difficulty > crate::u256::MAX_DIFFICULTY {
            return Err(Error::Malformed("max_difficulty above MAX_DIFFICULTY"));
        }
        if self.coinbase_maturity == 0 {
            return Err(Error::Malformed("coinbase_maturity must be > 0"));
        }
        if self.gas_cap == 0 {
            return Err(Error::Malformed("gas_cap must be > 0"));
        }
        if self.start_reward_sat == 0 {
            return Err(Error::Malformed("start_reward_sat must be > 0"));
        }
        if self.network_magic == [0, 0, 0, 0] {
            return Err(Error::Malformed("network_magic must be non-zero"));
        }
        if self.network_id.is_empty() {
            return Err(Error::Malformed("network_id must be non-empty"));
        }
        // L2 genesis escrow (Decision 7, SPEC.md §19.4). Every rule here is a
        // conservation rule: together they prove combined L1 + L2 money can
        // never exceed the cap (see the module docs on `l2_genesis_escrow_sat`).
        if self.l2_genesis_escrow_sat == 0 {
            return Err(Error::Malformed("l2_genesis_escrow_sat must be > 0"));
        }
        let escrow = self.l2_escrow_address();
        let mut seen: Vec<Address> = Vec::with_capacity(self.l2_genesis_grants.len());
        for g in &self.l2_genesis_grants {
            if g.amount_sat == 0 {
                return Err(Error::Malformed("l2 genesis grant must be > 0"));
            }
            if g.address == escrow {
                return Err(Error::Malformed(
                    "l2 genesis grant must not name the escrow identity",
                ));
            }
            if seen.contains(&g.address) {
                return Err(Error::Malformed("duplicate l2 genesis grant address"));
            }
            seen.push(g.address);
        }
        let granted = self.l2_granted_sat()?;
        if granted > self.l2_genesis_escrow_sat {
            return Err(Error::Malformed(
                "l2 genesis grants exceed the escrow total",
            ));
        }
        // Gap-fit: the escrow must fit in the sats the L1 ladder can never
        // mint. `max_issuance_sat` is the most L1 can ever hold and the escrow
        // is the most L2 can ever hold; both maxima fitting under the cap is
        // what makes the joint invariant hold with no L1 rule change.
        let gap = self
            .supply_cap_sat
            .saturating_sub(crate::supply::max_issuance_sat(self));
        if self.l2_genesis_escrow_sat > gap {
            return Err(Error::Malformed(
                "l2 genesis escrow exceeds the unmintable supply gap",
            ));
        }
        // Deposit floor (Decision 10 item 3): a zero minimum would credit dust
        // and let anyone bloat the UTXO set and L2 state for free.
        if self.l2_deposit_minimum_sat == 0 {
            return Err(Error::Malformed("l2_deposit_minimum_sat must be > 0"));
        }
        // Validator committee (Decision 11): no zero keys (which would
        // silently pass signature verification) and no duplicates.
        let mut seen_keys: Vec<BlsPublicKey> = Vec::with_capacity(self.genesis_validators.len());
        for k in &self.genesis_validators {
            if k.is_zero() {
                return Err(Error::Malformed("genesis_validators contains a zero key"));
            }
            if seen_keys.contains(k) {
                return Err(Error::Malformed(
                    "genesis_validators contains duplicate keys",
                ));
            }
            seen_keys.push(*k);
        }
        if self.checkpoint_interval_blocks == 0 {
            return Err(Error::Malformed("checkpoint_interval_blocks must be > 0"));
        }
        // Binding finality (Decisions 12/13): an activation height must land on
        // an epoch boundary, or no epoch-aligned checkpoint could ever reach it
        // and finality would silently never activate.
        if self.finality_activation_height > 0
            && self.finality_activation_height % self.checkpoint_interval_blocks != 0
        {
            return Err(Error::Malformed(
                "finality_activation_height must be a multiple of checkpoint_interval_blocks",
            ));
        }
        // Binding finality requires a committee to verify against; a nonzero
        // activation with an empty committee would be a rule that can never
        // fire (or, worse, one that accepts nothing). Fail at config time.
        if self.finality_activation_height > 0 && self.genesis_validators.is_empty() {
            return Err(Error::Malformed(
                "finality_activation_height > 0 requires a genesis validator committee",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_matches_design_doc_section_16() {
        let p = NetworkParams::mainnet();
        p.validate().unwrap();
        assert_eq!(p.supply_cap_jnt(), 39_945_600);
        assert_eq!(p.start_reward_jnt(), 76);
        assert_eq!(p.halving_period, 5 * 365 * 144);
        assert_eq!(p.target_block_time_ms, 10 * 60 * 1000);
        assert_eq!(
            p.genesis_difficulty, 1,
            "genesis must be trivially mineable"
        );
    }

    #[test]
    fn mini_cap_is_two_halving_periods_of_rewards() {
        let p = NetworkParams::mini();
        p.validate().unwrap();
        assert_eq!(
            p.supply_cap_jnt(),
            2 * p.halving_period * p.start_reward_jnt()
        );
        assert_eq!(p.target_block_time_ms, 1_000);
    }

    #[test]
    fn future_limit_is_one_block_time() {
        assert_eq!(NetworkParams::mainnet().future_limit_ms(), 600_000);
        assert_eq!(NetworkParams::mini().future_limit_ms(), 1_000);
    }

    #[test]
    fn profiles_resolve_by_name() {
        assert_eq!(
            NetworkParams::by_name("mini").unwrap(),
            NetworkParams::mini()
        );
        assert!(NetworkParams::by_name("nope").is_err());
    }

    #[test]
    fn network_magic_is_distinct_and_nonzero() {
        let m = NetworkParams::mainnet();
        let n = NetworkParams::mini();
        // Non-zero, lest a default profile silently pass for any network.
        assert_ne!(m.network_magic, [0, 0, 0, 0]);
        assert_ne!(n.network_magic, [0, 0, 0, 0]);
        // Distinct across profiles: the whole reason it exists (§13.3). Genesis
        // cannot do this job because both profiles have genesis_difficulty = 1.
        assert_ne!(m.network_magic, n.network_magic);
        assert_ne!(m.network_id, n.network_id);
        assert!(m.network_id.starts_with("jounit/"));
    }

    #[test]
    fn genesis_hash_is_identical_across_profiles() {
        // The property that makes network_magic necessary: genesis_block() takes
        // only difficulty, and both profiles set genesis_difficulty = 1.
        let g = crate::block::genesis_block(NetworkParams::mainnet().genesis_difficulty);
        let h = crate::block::genesis_block(NetworkParams::mini().genesis_difficulty);
        assert_eq!(g.block_hash(), h.block_hash());
    }

    #[test]
    fn l2_fee_schedule_is_the_decided_d3_set() {
        // Written out literally rather than derived from the constants: these are
        // a decision, and a typo in a constant is exactly the mistake a
        // self-referential assertion would agree with.
        assert_eq!(
            L2_FEE_SCHEDULE,
            &[
                ("TxPostTask", 5_000u64),
                ("TxClaimTask", 2_000),
                ("TxSubmitResult", 2_000),
                ("TxDispute", 10_000),
                ("TxSettle", 20_000),
            ]
        );
    }

    /// The decision, stated as a test: L2 fees ride a flat path of their own, the
    /// L1 `base_fee * gas_used` floor is unchanged, and the two are deliberately
    /// unrelated. Fails if someone makes an L2 fee clear the gas floor (which
    /// would mean L1 and L2 had been quietly merged) or if the D3 path stops
    /// preserving the M1 invariant.
    #[test]
    fn l2_fees_do_not_use_the_l1_gas_floor() {
        use crate::fees::{required_fee, split_flat_fee};
        for profile in [NetworkParams::mainnet(), NetworkParams::mini()] {
            // The cheapest fee the L1 rule can ever charge, for the smallest
            // possible transaction.
            let floor = required_fee(profile.base_fee_min_sat, crate::tx::GAS_TX_BASE);
            assert_eq!(
                floor,
                profile.base_fee_min_sat * crate::tx::GAS_TX_BASE,
                "the L1 floor must be exactly base_fee * gas_used"
            );
            for (name, fee) in L2_FEE_SCHEDULE {
                assert!(
                    *fee < floor,
                    "{name} at {fee} sat now clears the {floor} sat L1 gas floor on {} \
                     — L2 must keep its own path, not inherit the L1 floor",
                    profile.name
                );
                let split = split_flat_fee(*fee);
                assert_eq!(split.total_fees, *fee);
                assert_eq!(split.tip, 0);
                assert_eq!(split.burned + split.pscb, *fee);
                assert_eq!(split.pscb, *fee / 2);
            }
        }
    }

    // --- L2 genesis escrow (Decision 7, SPEC.md §19.4) -----------------------

    #[test]
    fn l2_genesis_escrow_fits_the_unmintable_gap_on_both_profiles() {
        // The joint conservation invariant as an executable check: the most
        // L1 can ever mint plus the most L2 can ever hold stays under the cap,
        // with no L1 rule change. If this fails, the escrow does not fit and
        // M2's funding model is inflationary.
        for p in [NetworkParams::mainnet(), NetworkParams::mini()] {
            p.validate().unwrap();
            let reachable = crate::supply::max_issuance_sat(&p);
            assert!(
                reachable + p.l2_genesis_escrow_sat <= p.supply_cap_sat,
                "{}: L1 reachable {} + L2 escrow {} exceeds cap {}",
                p.name,
                reachable,
                p.l2_genesis_escrow_sat,
                p.supply_cap_sat
            );
        }
        // Pin the gaps literally, so a halving-schedule change that shrinks
        // one is noticed here rather than as a far-away funding failure.
        assert_eq!(
            NetworkParams::mainnet().supply_cap_sat
                - crate::supply::max_issuance_sat(&NetworkParams::mainnet()),
            788_400 * SAT_PER_JNT
        );
        assert_eq!(
            NetworkParams::mini().supply_cap_sat
                - crate::supply::max_issuance_sat(&NetworkParams::mini()),
            6_000 * SAT_PER_JNT
        );
    }

    #[test]
    fn l2_escrow_identity_is_deterministic_and_network_bound() {
        let mini = NetworkParams::mini();
        let main = NetworkParams::mainnet();
        assert_eq!(mini.l2_escrow_address(), mini.l2_escrow_address());
        // Bound to the network: sharing an escrow identity across profiles
        // would let a mini replay claim mainnet backing.
        assert_ne!(mini.l2_escrow_address(), main.l2_escrow_address());
        assert_ne!(mini.l2_escrow_address(), [0u8; 20]);
        // No grant may collide with it.
        for g in &mini.l2_genesis_grants {
            assert_ne!(g.address, mini.l2_escrow_address());
        }
    }

    #[test]
    fn mini_grants_name_signable_operator_identities_and_sum_to_escrow() {
        let p = NetworkParams::mini();
        p.validate().unwrap();
        assert_eq!(p.l2_genesis_grants.len(), 3);
        for (i, g) in p.l2_genesis_grants.iter().enumerate() {
            // The tests hold these keys: seed i+1 must derive this address, or
            // the grant names an account nobody can operate.
            let w = crate::wallet::Wallet::from_private_key_bytes(
                &[(i + 1) as u8; 32],
                "l2-genesis-operator",
            )
            .unwrap();
            assert_eq!(g.address, w.address().unwrap());
            assert_eq!(g.amount_sat, SAT_PER_JNT);
        }
        assert_eq!(p.l2_granted_sat().unwrap(), 3 * SAT_PER_JNT);
        assert_eq!(p.l2_genesis_escrow_sat, 10 * SAT_PER_JNT);
        assert!(NetworkParams::mainnet().l2_genesis_grants.is_empty());
    }

    #[test]
    fn malformed_l2_genesis_params_are_rejected() {
        let good = NetworkParams::mini();
        // Zero escrow funds nothing: not a bridge.
        let mut p = good.clone();
        p.l2_genesis_escrow_sat = 0;
        assert!(p.validate().is_err());
        // Grants above the total invent value.
        let mut p = good.clone();
        p.l2_genesis_escrow_sat = 1;
        assert!(p.validate().is_err());
        // Zero-amount grant.
        let mut p = good.clone();
        p.l2_genesis_grants[0].amount_sat = 0;
        assert!(p.validate().is_err());
        // Duplicate address pays twice.
        let mut p = good.clone();
        p.l2_genesis_grants[1].address = p.l2_genesis_grants[0].address;
        assert!(p.validate().is_err());
        // Grant to the escrow identity blurs backing and remainder.
        let mut p = good.clone();
        p.l2_genesis_grants[0].address = p.l2_escrow_address();
        assert!(p.validate().is_err());
        // Escrow above the gap is inflation against the cap.
        let mut p = good.clone();
        p.l2_genesis_escrow_sat = p.supply_cap_sat;
        assert!(p.validate().is_err());
    }

    #[test]
    fn l2_deposit_sink_is_deterministic_network_bound_and_not_escrow() {
        let mini = NetworkParams::mini();
        let main = NetworkParams::mainnet();
        assert_eq!(mini.l2_deposit_sink(), mini.l2_deposit_sink());
        // Bound to the network: a mainnet sink output on mini is a plain burn.
        assert_ne!(mini.l2_deposit_sink(), main.l2_deposit_sink());
        assert_ne!(mini.l2_deposit_sink(), [0u8; 20]);
        // A distinct domain tag from the escrow identity, so the two can never
        // coincide and a deposit can never fund the escrow by confusion.
        assert_ne!(mini.l2_deposit_sink(), mini.l2_escrow_address());
        assert_ne!(main.l2_deposit_sink(), main.l2_escrow_address());
        // The minimum is the decided floor on both profiles.
        assert_eq!(mini.l2_deposit_minimum_sat, L2_DEPOSIT_MINIMUM_SAT);
        assert_eq!(main.l2_deposit_minimum_sat, L2_DEPOSIT_MINIMUM_SAT);
        assert_eq!(L2_DEPOSIT_MINIMUM_SAT, 1_000_000);
        // No grant may name the sink either: grants fund accounts, the sink
        // only receives burns.
        for g in &mini.l2_genesis_grants {
            assert_ne!(g.address, mini.l2_deposit_sink());
        }
        // A zero floor admits dust: refused.
        let mut p = mini.clone();
        p.l2_deposit_minimum_sat = 0;
        assert!(p.validate().is_err());
    }
}
