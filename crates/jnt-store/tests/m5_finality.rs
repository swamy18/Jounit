//! M5 binding-finality persistence — Decision 12, restart safety (STEP 3).
//!
//! The store is the only durable copy of the finalized point, so these tests
//! pin the whole round trip: write, reopen, replay, restore — plus every
//! fail-closed refusal `set_finalized` promises (a metadata row can lie only
//! by being refused, never by being believed).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use jnt_core::bls::RealBls;
use jnt_core::chain::Chain;
use jnt_core::params::NetworkParams;
use jnt_core::wallet::Wallet;
use jnt_store::BlockStore;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp_dir(name: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("jnt-store-m5-{name}-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn ts(height: u64) -> u64 {
    jnt_core::block::GENESIS_TIMESTAMP_MS + height * 1_000
}

/// A canonical testnet chain of `to` blocks — the same fixture shape the core
/// M5 suite uses, rebuilt here so the store tests exercise real blocks.
fn chain_to(to: u64) -> Chain {
    let addr = Wallet::from_private_key_bytes(&[9u8; 32], "m5-store")
        .unwrap()
        .address()
        .unwrap();
    let mut chain = Chain::new(NetworkParams::testnet()).unwrap();
    for h in 1..=to {
        let b = chain
            .mine_block(addr, vec![], ts(h))
            .expect("a chain we just built must mine");
        chain.submit(b).unwrap();
    }
    chain
}

fn store_chain(dir: &std::path::Path, chain: &Chain) {
    let params = chain.params().clone();
    let (mut bs, _) = BlockStore::open(dir, &params).unwrap();
    for h in 1..=chain.height() {
        bs.append_block(chain.block_at(h).unwrap()).unwrap();
    }
    bs.set_tip(&chain.tip_hash()).unwrap();
    bs.sync().unwrap();
}

/// Rebuild a chain from stored blocks alone and restore the stored finalized
/// point — exactly what `jnt-node`'s load path does after a restart.
fn reload(dir: &std::path::Path, params: &NetworkParams) -> Chain {
    let (mut bs, _) = BlockStore::open(dir, params).unwrap();
    let mut chain = Chain::new(params.clone()).unwrap();
    let (_, height) = bs.tip();
    for h in 1..=height {
        let block = bs.block_at_height(h).unwrap().unwrap();
        chain.submit(block).unwrap();
    }
    if let Some((fh, fhash)) = bs.finalized() {
        assert!(
            chain.restore_finality(fh, fhash),
            "the persisted finalized point must match the replayed canonical chain"
        );
    }
    chain
}

#[test]
fn the_finalized_point_survives_reopen_and_equals_the_pre_restart_point() {
    let dir = tmp_dir("roundtrip");
    let params = NetworkParams::testnet();

    // Live node: mine, finalize at 20 through the normal certificate path.
    let mut live = chain_to(24);
    let h20 = live.block_hash_at(20).unwrap();
    let cp = {
        use jnt_core::bls::SecretKey;
        use jnt_core::bls_checkpoint::{BlsSignature, Checkpoint, CheckpointPayload};
        let mut pairs: Vec<(SecretKey, jnt_core::bls_checkpoint::BlsPublicKey)> =
            jnt_core::params::testnet_committee_secrets()
                .into_iter()
                .map(|sk| {
                    let pk = sk.public_key();
                    (sk, pk)
                })
                .collect();
        pairs.sort_by_key(|a| a.1 .0);
        let p = CheckpointPayload {
            height: 20,
            block_hash: h20,
            network_id: "jounit/testnet".into(),
            epoch: 2,
        };
        let msg = p.signing_hash();
        let sigs: Vec<BlsSignature> = [0usize, 1, 2]
            .iter()
            .map(|&i| pairs[i].0.sign(&msg))
            .collect();
        let agg = RealBls::aggregate(&sigs).unwrap();
        let mut bitmap = vec![0u8; pairs.len().div_ceil(8)];
        for i in [0usize, 1, 2] {
            bitmap[i / 8] |= 1 << (i % 8);
        }
        Checkpoint {
            payload: p,
            aggregate_sig: agg,
            signer_bitmap: bitmap,
            signer_count: 3,
        }
    };
    live.apply_checkpoint(&cp, &RealBls).unwrap();
    let point = live.finalized_point().expect("checkpoint binds at 20");

    // Persist exactly as the node does: blocks, tip, then the finalized point.
    store_chain(&dir, &live);
    {
        let (mut bs, _) = BlockStore::open(&dir, &params).unwrap();
        bs.set_finalized(point.0, point.1).unwrap();
        assert_eq!(bs.finalized(), Some(point));
    }

    // Restart: everything rebuilt from the store alone.
    let reborn = reload(&dir, &params);
    assert_eq!(
        reborn.finalized_point(),
        Some(point),
        "finalized height/hash before restart == after restart"
    );
    assert_eq!(reborn.finalized_height(), point.0);
    assert_eq!(reborn.tip_hash(), live.tip_hash());

    // A second restart derives exactly the same point — restore is a pure
    // function of stored state, not of how many times it ran.
    let again = reload(&dir, &params);
    assert_eq!(again.finalized_point(), Some(point));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn set_finalized_fails_closed_on_every_lying_row() {
    let dir = tmp_dir("refusals");
    let params = NetworkParams::testnet();
    let chain = chain_to(24);
    store_chain(&dir, &chain);

    let h20 = chain.block_hash_at(20).unwrap();
    let h5 = chain.block_hash_at(5).unwrap();
    let (mut bs, _) = BlockStore::open(&dir, &params).unwrap();
    assert_eq!(bs.finalized(), None);

    // Beyond the stored tip: the store has no block to prove it against.
    assert!(bs.set_finalized(99, h20).is_err());
    // A hash that is not the canonical block at a real height.
    assert!(bs.set_finalized(20, [0x99; 32]).is_err());
    assert_eq!(bs.finalized(), None, "nothing partial was written");

    // The honest claim lands.
    bs.set_finalized(20, h20).unwrap();
    assert_eq!(bs.finalized(), Some((20, h20)));

    // Height 0 is "no finality", never a finalizable height.
    assert!(bs.set_finalized(0, h20).is_err());
    // Regression: finality may only climb.
    assert!(bs.set_finalized(5, h5).is_err());
    // A different hash at the already-final height — the equivocation shape —
    // is refused rather than silently re-finalized.
    assert!(bs.set_finalized(20, [0x88; 32]).is_err());
    // Above the tip after finality exists too.
    assert!(bs.set_finalized(30, [0x88; 32]).is_err());

    assert_eq!(
        bs.finalized(),
        Some((20, h20)),
        "every refusal left the persisted point untouched"
    );

    // Climbing forward with a proven hash is legal and persists.
    let h22 = chain.block_hash_at(22).unwrap();
    bs.set_finalized(22, h22).unwrap();
    assert_eq!(bs.finalized(), Some((22, h22)));
    drop(bs);
    let (bs2, _) = BlockStore::open(&dir, &params).unwrap();
    assert_eq!(bs2.finalized(), Some((22, h22)));

    let _ = std::fs::remove_dir_all(&dir);
}
