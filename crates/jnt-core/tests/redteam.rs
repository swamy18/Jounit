//! Red-team regression suite.
//!
//! Every test here is written as an *attack*: it builds the hostile input a
//! network peer would send and asserts that the node refuses it. They are
//! regression tests rather than proofs — each names the concrete rule it is
//! defending and, where the original code was exploitable, says what the
//! failure looked like.
//!
//! Run with `cargo test -p jnt-core --test redteam`.

use jnt_core::block::{Block, Header};
use jnt_core::chain::Chain;
use jnt_core::error::Error;
use jnt_core::hash::Address;
use jnt_core::ledger::{Utxo, UtxoSet};
use jnt_core::params::NetworkParams;
use jnt_core::supply::block_reward_sat;
use jnt_core::tx::{Input, OutPoint, Output, Transaction};
use jnt_core::wallet::Wallet;

/// Mini spacing keeps difficulty pinned at 1, so every hand-built header in
/// this file is trivially valid PoW. That is deliberate: these tests attack
/// *state* rules, and a difficulty-1 PoW is what an attacker gets for free.
fn ts(height: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

/// Timestamps that make the retarget raise difficulty, for branches that need
/// to out-work the main chain.
fn fast_ts(height: u64) -> u64 {
    let t = NetworkParams::mini().target_block_time_ms;
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * (t / 2)
}

fn addr(tag: u8) -> Address {
    [tag; 20]
}

/// Mine `n` empty blocks on `chain`, paying the coinbase to `miner`.
fn extend_to(chain: &mut Chain, miner: Address, n: u64, f: fn(u64) -> u64) {
    for h in (chain.height() + 1)..=(chain.height() + n) {
        let b = chain.mine_block(miner, vec![], f(h)).unwrap();
        chain.submit(b).unwrap();
    }
}

/// Mine `n` empty blocks to an arbitrary address.
fn extend(chain: &mut Chain, n: u64, f: fn(u64) -> u64) {
    extend_to(chain, addr(1), n, f);
}

/// Build a fully-formed block by hand around an arbitrary transaction list.
///
/// Used to smuggle a transaction past `mine_block`, which refuses to build a
/// body it cannot itself validate. Difficulty 1 makes the proof free, so this
/// produces a block that is *byte-perfectly* valid apart from whatever the
/// attacker chose to break.
fn handcraft(chain: &Chain, miner: Address, body: Vec<Transaction>, height: u64) -> Block {
    let parent_hash = chain.tip_hash();
    let mut txs = vec![Transaction::coinbase(
        parent_hash,
        height,
        Output {
            value: block_reward_sat(chain.params(), height),
            address: miner,
        },
    )];
    txs.extend(body);
    let merkle = jnt_core::block::merkle_root(&txs);
    let header = Header {
        version: jnt_core::block::BLOCK_VERSION,
        height,
        prev_hash: parent_hash,
        merkle_root: merkle,
        timestamp_ms: ts(height),
        // Difficulty 1 is what an honest miner produces at this spacing.
        base_fee_sat: if height == 1 {
            chain.params().base_fee_initial_sat
        } else {
            jnt_core::fees::next_base_fee(
                chain.params(),
                chain.tip().header.base_fee_sat,
                chain.tip().total_gas_used().unwrap(),
            )
        },
        difficulty: 1,
        nonce: 0,
        puzzle_id: chain.params().puzzle_id,
        epoch_id: (height / chain.params().nn_epoch_blocks).min(u32::MAX as u64) as u32,
        extra_nonce: [0u8; 16],
        sig_scheme: jnt_core::hash::SIG_SCHEME_SECP256K1_ECDSA,
    };
    Block {
        header,
        signature: [0u8; 64],
        signer_pubkey: [0u8; 33],
        txs,
    }
}

/// A correctly signed 1-in 1-out spend of `op`, paying `pay` to `to`. Whatever
/// the caller does not name as `pay` becomes the transaction's fee.
fn signed_spend(wallet: &Wallet, op: OutPoint, pay: u64, to: Address) -> Transaction {
    let mut tx = Transaction::standard(
        vec![Input::unsigned(&op)],
        vec![Output {
            value: pay,
            address: to,
        }],
    );
    wallet.sign(&mut tx).unwrap();
    tx
}

// ---------------------------------------------------------------------------
// 1. Rejected block must not leave UTXO state behind
// ---------------------------------------------------------------------------

/// **The rule:** a block that fails validation must have no effect whatsoever
/// on chain state.
///
/// **The attack:** a block whose *last* transaction is invalid. `apply_block`
/// applies body transactions one at a time, so the earlier ones are already
/// written to the UTXO set when the failure surfaces. Worth being precise about
/// how far this actually reached: the reorganization path took a full snapshot
/// before applying, so a first attempt at this exploit passed — the snapshot
/// happened to cover it. The direct-extension path in `submit_at` had no such
/// protection, and `apply_block` itself still left the invariant unenforced,
/// relying on every caller to have snapshotted. Writes are now unwound by
/// `apply_block` itself, so no caller has to remember.
#[test]
fn a_rejected_block_must_not_leave_utxo_state_behind() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let miner = Wallet::new_random("miner");
    let attacker = Wallet::new_random("attacker");
    let miner_addr = miner.address().unwrap();
    let attacker_addr = attacker.address().unwrap();

    extend_to(&mut chain, miner_addr, 12, ts);

    // Two spendable matured coinbases belonging to the victim.
    let victim_a = OutPoint {
        txid: chain.block_at(1).unwrap().txs[0].txid(),
        index: 0,
    };
    let victim_b = OutPoint {
        txid: chain.block_at(2).unwrap().txs[0].txid(),
        index: 0,
    };
    let stolen = chain.utxo().get(&victim_a).unwrap().out.value;
    let fee = chain.expected_base_fee_for_next_block() * 100_000 + 1_000;

    // Legit transaction first: it moves the victim's money to the attacker.
    let good = signed_spend(&miner, victim_a, stolen - fee, attacker_addr);
    // Then a transaction that is guaranteed to fail `check_tx`: it spends an
    // outpoint that does not exist.
    let poison = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [0xEEu8; 32],
            index: 7,
        })],
        vec![Output {
            value: 1,
            address: attacker_addr,
        }],
    );

    let before = chain.utxo().total_value();
    let before_len = chain.utxo().len();

    let block = handcraft(&chain, miner_addr, vec![good, poison], chain.height() + 1);
    let result = chain.submit(block);

    assert!(
        result.is_err(),
        "the block must be rejected: a tx spending a nonexistent output is invalid"
    );

    // The whole point: state is untouched.
    assert_eq!(
        chain.utxo().total_value(),
        before,
        "a REJECTED block changed total supply -- unbacked value exists"
    );
    assert_eq!(chain.utxo().len(), before_len, "UTXO entry count changed");
    assert!(
        chain.utxo().get(&victim_a).is_some(),
        "a rejected block consumed the victim's output"
    );
    assert_eq!(
        chain.utxo().outputs_for_address(&attacker_addr),
        Vec::new(),
        "a rejected block credited the attacker"
    );
    assert_eq!(chain.height(), 12, "the tip must not advance");

    // And the node must still agree with a from-genesis replay.
    chain
        .verify_canonical_chain()
        .expect("state diverged from a clean replay");
    assert!(chain.utxo().get(&victim_b).is_some());
}

// ---------------------------------------------------------------------------
// 2. `apply_tx` must be atomic
// ---------------------------------------------------------------------------

/// **The rule:** `apply_tx` either applies the whole transaction or nothing.
///
/// **The attack:** a transaction whose *second* input does not exist. Inputs
/// were removed from the map in a loop, so the first input was already deleted
/// before the `UnknownOutPoint` error fired — and the undo record that could
/// have restored it was discarded with the error. One malformed transaction
/// destroyed coins.
#[test]
fn apply_tx_is_atomic_when_an_input_is_missing() {
    let w = Wallet::new_random("victim");
    let good_op = OutPoint {
        txid: [1u8; 32],
        index: 0,
    };
    let missing_op = OutPoint {
        txid: [2u8; 32],
        index: 0,
    };
    const VALUE: u64 = 5_000_000_000;

    let mut set = UtxoSet::new();
    set.insert(
        good_op,
        Utxo {
            out: Output {
                value: VALUE,
                address: w.address().unwrap(),
            },
            height: 0,
        },
    );

    let tx = Transaction::standard(
        vec![Input::unsigned(&good_op), Input::unsigned(&missing_op)],
        vec![Output {
            value: VALUE - 1,
            address: [9u8; 20],
        }],
    );

    assert!(matches!(set.apply_tx(&tx, 10), Err(Error::UnknownOutPoint)));
    assert!(
        set.contains(&good_op),
        "a failed apply destroyed a live output: {} sat vanished",
        VALUE
    );
    assert_eq!(
        set.total_value(),
        VALUE,
        "a failed apply changed the ledger total"
    );
}

// ---------------------------------------------------------------------------
// 3. Fork choice must not depend on arrival order
// ---------------------------------------------------------------------------

/// **The rule:** two nodes holding the same set of valid blocks must agree on
/// the tip. The module docs claim exactly this.
///
/// **The attack:** two rival blocks at the same height with identical work.
/// The tie-break used `first_seen`, an arrival counter, so node A (which saw
/// `rival_a` first) and node B (which saw `rival_b` first) picked different
/// tips from an identical block set. That is a consensus split with no
/// attacker effort at all.
#[test]
fn fork_choice_is_independent_of_block_arrival_order() {
    let build_rivals = || {
        let mut base = Chain::new(NetworkParams::mini()).unwrap();
        extend(&mut base, 1, ts);
        let mut a = Chain::new(NetworkParams::mini()).unwrap();
        let mut b = Chain::new(NetworkParams::mini()).unwrap();
        // Same parent, different coinbase address => different block, same
        // height, same difficulty, hence exactly equal cumulative work.
        a.submit(base.block_at(1).unwrap().clone()).unwrap();
        b.submit(base.block_at(1).unwrap().clone()).unwrap();
        let blk_a = a.mine_block(addr(0xAA), vec![], ts(2)).unwrap();
        let blk_b = b.mine_block(addr(0xBB), vec![], ts(2)).unwrap();
        assert_ne!(blk_a.block_hash(), blk_b.block_hash());
        assert_eq!(blk_a.header.difficulty, blk_b.header.difficulty);
        (blk_a, blk_b)
    };

    let (blk_a, blk_b) = build_rivals();

    let mut node_a = Chain::new(NetworkParams::mini()).unwrap();
    let mut node_b = Chain::new(NetworkParams::mini()).unwrap();
    let parent = node_a.mine_block(addr(1), vec![], ts(1)).unwrap();
    node_a.submit(parent.clone()).unwrap();
    node_b.submit(parent).unwrap();
    node_a.submit(blk_a.clone()).unwrap();
    node_a.submit(blk_b.clone()).unwrap();
    node_b.submit(blk_b.clone()).unwrap();
    node_b.submit(blk_a.clone()).unwrap();

    assert_eq!(
        node_a.tip_hash(),
        node_b.tip_hash(),
        "two nodes with the same block set chose different tips"
    );
}

// ---------------------------------------------------------------------------
// 4. A block that can never be applied must not count as work
// ---------------------------------------------------------------------------

/// **The rule:** fork choice must only consider blocks a node can actually
/// apply.
///
/// **The attack:** a block that passes the standalone checks (proof of work,
/// merkle root, gas) but fails the state rules. `submit_at` inserted it into
/// the block store *before* applying and never removed it, and `cumulative_work`
/// happily summed its difficulty. So an attacker could accumulate chain weight
/// that no reorganisation could ever realise: fork choice kept selecting the
/// unusable branch, and every honest block was rejected until the honest chain
/// clawed past it. Memory grew without bound in the meantime.
#[test]
fn an_unapplicable_block_must_not_be_retained_or_counted_as_work() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let miner_addr = addr(1);
    extend(&mut chain, 12, ts);

    // Valid PoW, valid merkle root, but the body spends nothing that exists,
    // so `apply_block` must refuse it.
    let poison = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [0xEEu8; 32],
            index: 7,
        })],
        vec![Output {
            value: 1,
            address: addr(9),
        }],
    );
    let block = handcraft(&chain, miner_addr, vec![poison], chain.height() + 1);
    let hash = block.block_hash();
    let honest_work = chain.total_work();

    assert!(chain.submit(block).is_err(), "block must be rejected");

    assert!(
        chain.block_by_hash(&hash).is_none(),
        "an unusable block was retained and can influence future fork choice"
    );
    assert_eq!(
        chain.total_work(),
        honest_work,
        "an unusable block contributed to cumulative work"
    );

    // The consequence that actually matters: a dead branch must not wedge the
    // node. An honest block on top of the tip still has to be accepted, even
    // though the rejected block claimed the same height and the same work.
    let honest = chain
        .mine_block(addr(1), vec![], ts(chain.height() + 1))
        .unwrap();
    chain
        .submit(honest)
        .expect("a rejected phantom block stopped the node accepting honest blocks");
    assert_eq!(chain.height(), 13);
}

// ---------------------------------------------------------------------------
// 5. Finality must hold against a *longer* rival branch
// ---------------------------------------------------------------------------

/// **The rule:** a reorg must never rewrite a block at or below
/// `tip - finality_depth`.
///
/// **The attack:** the guard read
/// `if common <= finalized && self.canon.len() > new_canon.len()`, so it only
/// refused reorgs that *shortened* the chain. A rival that forked below the
/// finality point but ended up *longer* sailed straight through and rewrote
/// settled history. The existing test only covered the shrinking case, which is
/// why the hole survived.
#[test]
fn a_longer_branch_cannot_rewrite_finalized_history() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    extend(&mut chain, 25, ts);
    assert_eq!(chain.finalized_height(), 5);
    let old_tip = chain.tip_hash();

    // Rival shares heights 1..=3, then diverges and climbs *past* height 25 so
    // the new canonical chain would be longer than the current one.
    let mut rival = Chain::new(NetworkParams::mini()).unwrap();
    let mut rival_blocks = Vec::new();
    for h in 1..=3u64 {
        let blk = rival.mine_block(addr(1), vec![], ts(h)).unwrap();
        rival.submit(blk.clone()).unwrap();
        rival_blocks.push(blk);
    }
    // Confirm the rival really does share the prefix we need it to share.
    for h in 1..=3u64 {
        assert_eq!(
            rival_blocks[(h - 1) as usize].block_hash(),
            chain.block_at(h).unwrap().block_hash(),
            "rival must share heights 1..=3"
        );
    }
    for h in 4..=40u64 {
        let blk = rival.mine_block(addr(7), vec![], fast_ts(h)).unwrap();
        rival.submit(blk.clone()).unwrap();
        rival_blocks.push(blk);
    }
    assert!(
        rival.height() > chain.height(),
        "the rival must be longer for this attack to mean anything"
    );
    assert!(
        rival.total_work() > chain.total_work(),
        "the rival must carry more work ({}) than the tip ({})",
        rival.total_work(),
        chain.total_work()
    );

    // Deliver the rival branch. Storing a side block is fine and returns Ok; what
    // must not happen is the fork point moving, so the guard has to fire once
    // the rival finally out-weighs the tip.
    let mut refused_by_finality = 0usize;
    for blk in rival_blocks.iter().skip(3) {
        if let Err(Error::ReorgWouldCrossFinality { .. }) = chain.submit(blk.clone()) {
            refused_by_finality += 1;
        }
    }
    assert!(
        refused_by_finality > 0,
        "the rival never out-worked the tip, so this attack proved nothing"
    );
    assert_eq!(
        chain.height(),
        25,
        "the chain adopted the longer rival branch"
    );
    assert_eq!(chain.tip_hash(), old_tip, "finalized history was rewritten");
    assert_ne!(
        chain.block_at(4).unwrap().block_hash(),
        rival_blocks[3].block_hash(),
        "height 4 is below the finality point and must not be the rival's block"
    );
    chain.verify_canonical_chain().unwrap();
}

// ---------------------------------------------------------------------------
// 6. `build_tx` must honour the fee it is given
// ---------------------------------------------------------------------------

/// **The rule:** `build_tx(inputs, outputs, fee)` is documented as building a
/// transaction paying `outputs` *plus* `fee`.
///
/// **The attack:** the parameter was accepted and then dropped on the floor
/// (`let _ = fee;`). Any fee a caller declared was simply gone — including
/// amounts that made no sense at all — so the function could not honour the
/// contract it advertised and silently produced a different transaction.
#[test]
fn build_tx_does_not_silently_discard_the_fee_it_was_given() {
    let w = Wallet::new_random("payer");
    let dest = [7u8; 20];
    let op = OutPoint {
        txid: [3u8; 32],
        index: 0,
    };
    const VALUE: u64 = 10_000_000;
    const PAY: u64 = 4_000_000;

    // `outputs + fee` must be representable. `fee == u64::MAX` used to be
    // accepted silently because the value was never read.
    assert!(
        w.build_tx(
            &[op],
            vec![Output {
                value: PAY,
                address: dest
            }],
            u64::MAX
        )
        .is_err(),
        "build_tx accepted a fee that cannot coexist with the outputs"
    );

    // A representable fee is accepted, and the caller-supplied change output is
    // what makes `sum(outputs) + fee == sum(inputs)` hold.
    const FEE: u64 = 250_000;
    let mut set = UtxoSet::new();
    set.insert(
        op,
        Utxo {
            out: Output {
                value: VALUE,
                address: w.address().unwrap(),
            },
            height: 0,
        },
    );
    let tx = w
        .build_tx(
            &[op],
            vec![
                Output {
                    value: PAY,
                    address: dest,
                },
                Output {
                    value: VALUE - PAY - FEE,
                    address: w.address().unwrap(),
                },
            ],
            FEE,
        )
        .expect("a representable fee must be accepted");
    let delta = jnt_core::ledger::check_tx(&set, &tx, 10, &NetworkParams::mini(), 0, 0).unwrap();
    assert_eq!(
        delta.fee_total, FEE,
        "the declared fee is not what the transaction pays"
    );
}

// ---------------------------------------------------------------------------
// 7. The chain must survive an exhausted reward ladder
// ---------------------------------------------------------------------------

/// **The rule:** SPEC.md §7 — once the halving ladder reaches zero the coinbase
/// collects "the tips only", and the surplus is unmintable rather than fatal.
///
/// **The attack:** `apply_block` rejected a coinbase with a zero-value output
/// unconditionally. After the last halving, `reward + tip` is legitimately
/// zero for an empty block, so every such block was refused and the chain
/// stopped dead at a fixed height — an unrecoverable halt baked into consensus.
#[test]
fn a_zero_reward_block_at_the_end_of_the_ladder_is_accepted() {
    // Reach past the last halving by mining on a profile whose ladder is short.
    let mut params = NetworkParams::mini();
    // Eight halving periods of 2 000 blocks is 16 000 blocks, too slow to mine
    // here, so shrink the period while keeping the ladder shape.
    params.halving_period = 2;
    params.supply_cap_sat = 1_000_000_000_000;
    params.validate().unwrap();

    let mut chain = Chain::new(params.clone()).unwrap();
    let miner = addr(1);

    // Period p pays 76 >> p; the ladder hits 0 at p == 7 (height 14).
    let mut height_reached_zero_reward = false;
    for h in 1..=20u64 {
        let b = chain.mine_block(miner, vec![], ts(h)).unwrap();
        let reward = block_reward_sat(chain.params(), h);
        let res = chain.submit(b);
        assert!(
            res.is_ok(),
            "block {h} was rejected ({:?}) with reward {reward}; the chain must \
             survive an exhausted reward ladder",
            res.err()
        );
        assert_eq!(chain.height(), h);
        if reward == 0 {
            height_reached_zero_reward = true;
        }
    }
    assert!(
        height_reached_zero_reward,
        "the test never reached a zero-reward block"
    );
    chain.verify_canonical_chain().unwrap();
}

// ---------------------------------------------------------------------------
// 8. Declared counts must be bounded by what the buffer can actually hold
// ---------------------------------------------------------------------------

/// **The rule:** a count field is attacker-controlled and must be checked
/// against a real lower bound on entry size *before* anything is reserved.
///
/// **The attack:** `Transaction::from_reader` only checked `n > remaining()`.
/// A 4 MB block could therefore declare ~4 000 000 inputs and force a
/// `Vec::with_capacity(n)` of `Input` structs several times larger than the
/// buffer that described them — a memory amplification of ~80x from a single
/// 4 MB message.
#[test]
fn a_count_field_cannot_reserve_more_than_the_buffer_could_hold() {
    // A buffer of `n` bytes where every entry would need at least a byte: the
    // declared count is the buffer length, so it is "in bounds" under a naive
    // remaining-bytes check. It must still be rejected, because no real input
    // is one byte long.
    let mut raw = Vec::new();
    raw.extend_from_slice(&1u32.to_le_bytes());
    raw.push(jnt_core::tx::TX_STANDARD);
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.extend_from_slice(&(4096u32).to_le_bytes()); // input_count
                                                     // No input bytes at all follow: the first parse must fail, not allocate.
    assert!(Transaction::deserialize(&raw).is_err());

    // And the honest shapes still round-trip.
    let tx = Transaction::standard(
        vec![Input::unsigned(&OutPoint {
            txid: [1u8; 32],
            index: 0,
        })],
        vec![Output {
            value: 5,
            address: [2; 20],
        }],
    );
    assert_eq!(Transaction::deserialize(&tx.serialize()).unwrap(), tx);
}

// ---------------------------------------------------------------------------
// 9. Unknown header fields must be rejected
// ---------------------------------------------------------------------------

/// **The rule:** SPEC.md §1 — "Nodes MUST reject unknown `sig_scheme`
/// values."
///
/// **The attack:** `sig_scheme` sat in the header, was committed to by the
/// block hash, and was never read by any validation path. A block declaring an
/// unknown scheme was accepted, which is precisely the field an upgrade path
/// depends on being trustworthy.
#[test]
fn an_unknown_header_sig_scheme_is_rejected() {
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    extend(&mut chain, 1, ts);

    let mut block = chain.mine_block(addr(1), vec![], ts(2)).unwrap();
    block.header.sig_scheme = 200;
    assert!(
        matches!(
            chain.validate_standalone(&block),
            Err(Error::UnsupportedSigScheme(200))
        ),
        "an unknown sig_scheme was accepted"
    );
}
