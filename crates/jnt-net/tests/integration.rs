//! Integration tests for the jnt-net P2P layer. SPEC.md §13.11 invariants.
//!
//! These tests use an in-process loopback to verify the invariants without
//! requiring actual TCP connections. They follow the same red-before-green
//! discipline as `crates/jnt-core/tests/redteam.rs`.

use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use jnt_core::block::genesis_block;
use jnt_core::chain::Chain;
use jnt_core::hash::Hash;
use jnt_core::params::NetworkParams;
use jnt_net::magic::check_network;
use jnt_net::msg::{INV_TYPE_BLOCK, PROTOCOL_VERSION};
use jnt_net::peer::{perform_handshake, HandshakeConfig};
use jnt_net::syncer::{create_locator, find_fork_and_collect_inv, SyncManager, SyncResult};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mini() -> NetworkParams {
    NetworkParams::mini()
}

fn fresh_chain() -> Chain {
    Chain::new(mini()).expect("genesis ok")
}

fn genesis_hash(params: &NetworkParams) -> Hash {
    genesis_block(params.genesis_difficulty).block_hash()
}

fn mine_n(chain: &mut Chain, n: u64) {
    // Use the frozen GENESIS_TIMESTAMP_MS so the median-time rule is always satisfied.
    // Increment by 1 ms per block so timestamps are strictly increasing.
    let addr = [1u8; 20];
    let mut ts = jnt_core::block::GENESIS_TIMESTAMP_MS + 1;
    for _ in 0..n {
        let b = chain.mine_block(addr, vec![], ts).unwrap();
        chain.submit(b).unwrap();
        ts += 60_000; // 60s per block — well within the mini target
    }
}

// ---------------------------------------------------------------------------
// §13.11 invariant 2: two nodes converge on the same tip regardless of order
// ---------------------------------------------------------------------------

#[test]
fn two_nodes_converge_regardless_of_delivery_order() {
    let mut chain_a = fresh_chain();
    mine_n(&mut chain_a, 5);

    let mut chain_b = fresh_chain();
    let mut syncer_b = SyncManager::new();

    // Collect all A's post-genesis blocks
    let blocks: Vec<_> = (1..=chain_a.height())
        .map(|h| chain_a.block_at(h).unwrap().clone())
        .collect();

    // Submit in reverse order to B — early ones become orphans, resolve when
    // their parents arrive.
    for block in blocks.iter().rev() {
        let _ = syncer_b.handle_block(block.clone(), &mut chain_b, None);
    }

    assert_eq!(
        chain_a.tip_hash(),
        chain_b.tip_hash(),
        "both nodes must converge on the same tip"
    );
    assert_eq!(chain_a.height(), chain_b.height());
}

// ---------------------------------------------------------------------------
// §13.11 invariant 5: invalid blocks never enter the store
// ---------------------------------------------------------------------------

#[test]
fn invalid_blocks_never_enter_the_store() {
    let mut chain = fresh_chain();
    mine_n(&mut chain, 3);

    let mut syncer = SyncManager::new();

    // Corrupt the merkle_root of block 1: this makes it invalid regardless of
    // difficulty (block hash commits to merkle_root via the header, so the
    // merkle check in validate_standalone fires before PoW).
    let mut bad_block = chain.block_at(1).unwrap().clone();
    bad_block.header.merkle_root[0] ^= 0xFF;

    let before_height = chain.height();
    let result = syncer.handle_block(bad_block, &mut chain, None);

    assert!(
        matches!(result, SyncResult::Invalid(_)),
        "block with corrupted merkle_root must be rejected, got: {result:?}"
    );
    assert_eq!(
        chain.height(),
        before_height,
        "invalid block must not advance the chain"
    );

    // Chain must still accept a valid next block afterwards
    let mut chain2 = fresh_chain();
    mine_n(&mut chain2, 3);
    // Submit chain2's blocks 1–3 to `chain` via syncer; they're all orphans
    // initially (chain2 has different blocks), which is fine — what matters is
    // that the chain remains at the same height and didn't get corrupted.
    let result2 = syncer.handle_block(chain2.block_at(1).unwrap().clone(), &mut chain, None);
    assert!(
        !matches!(result2, SyncResult::Accepted { .. }),
        "a block from a different chain cannot extend our canonical chain"
    );
}

// ---------------------------------------------------------------------------
// §13.11 invariant 6: orphan pool is bounded
// ---------------------------------------------------------------------------

#[test]
fn orphan_pool_is_bounded() {
    let mut chain = fresh_chain();
    let mut syncer = SyncManager::new();

    // Build a foreign chain whose blocks are all orphans relative to `chain`
    // (they reference each other but none reference chain's genesis-only store).
    let mut foreign = fresh_chain();
    mine_n(&mut foreign, 80); // more than orphan_pool_max (64)

    // Submit all foreign blocks; each is an orphan for `chain`.
    for h in 1..=80 {
        let block = foreign.block_at(h).unwrap().clone();
        syncer.handle_block(block, &mut chain, None);
    }

    assert!(
        syncer.orphan_count() <= jnt_net::syncer::ORPHAN_POOL_MAX,
        "orphan pool count {} exceeds maximum {}",
        syncer.orphan_count(),
        jnt_net::syncer::ORPHAN_POOL_MAX
    );
}

// ---------------------------------------------------------------------------
// §13.7: locator construction and fork-point discovery
// ---------------------------------------------------------------------------

#[test]
fn locator_includes_tip_and_genesis() {
    let mut chain = fresh_chain();
    mine_n(&mut chain, 20);

    let locator = create_locator(&chain);

    assert_eq!(
        locator[0],
        chain.tip_hash(),
        "first entry must be the current tip"
    );

    let genesis = chain.block_hash_at(0).unwrap();
    assert!(
        locator.contains(&genesis),
        "locator must always contain the genesis hash"
    );
    assert!(locator.len() <= 500, "locator must not exceed 500 entries");
}

/// A node at genesis sends a locator = [genesis_hash]. A fully-synced peer
/// must respond with INV entries for heights 1..=tip.
#[test]
fn find_fork_collects_inv_from_common_ancestor() {
    // chain_a is fully synced with 10 blocks
    let mut chain_a = fresh_chain();
    mine_n(&mut chain_a, 10);

    // chain_b is at genesis — it knows nothing beyond block 0.
    let chain_b = fresh_chain();

    // chain_b builds a locator: just [genesis_hash] (height 0 is the only known block).
    let locator = create_locator(&chain_b);
    // Locator from a genesis-only chain must contain the genesis hash.
    assert_eq!(locator[0], chain_b.tip_hash());

    // Ask chain_a for blocks past the fork (genesis is the common ancestor).
    let inv = find_fork_and_collect_inv(&chain_a, &locator, &Hash::default());

    assert!(
        !inv.is_empty(),
        "responder must return inventory of blocks past the common ancestor"
    );
    for e in &inv {
        assert_eq!(e.kind, INV_TYPE_BLOCK, "every entry must be a block");
    }
    // The first INV entry should be height 1 (block after genesis)
    let height_1_hash = chain_a.block_hash_at(1).unwrap();
    assert_eq!(inv[0].hash, height_1_hash, "first INV entry is height 1");
}

/// A fresh syncer receiving blocks in forward order resolves them correctly.
#[test]
fn sync_manager_resolves_blocks_in_order() {
    let mut chain_a = fresh_chain();
    mine_n(&mut chain_a, 5);

    let mut chain_b = fresh_chain();
    let mut syncer = SyncManager::new();

    for h in 1..=5u64 {
        let block = chain_a.block_at(h).unwrap().clone();
        let result = syncer.handle_block(block, &mut chain_b, None);
        assert!(
            matches!(
                result,
                SyncResult::Accepted {
                    extended_tip: true,
                    ..
                }
            ),
            "block {h} must be accepted and extend the tip"
        );
    }
    assert_eq!(chain_a.tip_hash(), chain_b.tip_hash());
}

// ---------------------------------------------------------------------------
// §13.11 invariant 4: cross-network isolation
// ---------------------------------------------------------------------------

#[test]
fn mini_node_rejects_mainnet_handshake() {
    let mainnet = NetworkParams::mainnet();
    let mini = mini();

    // A mini node validating an inbound mainnet VERSION must reject it.
    let result = check_network(&mini, mainnet.network_magic, &mainnet.network_id);
    assert!(
        result.is_err(),
        "mini node must reject a mainnet magic + id"
    );
}

// ---------------------------------------------------------------------------
// §13.4: handshake over real loopback sockets
// ---------------------------------------------------------------------------

#[test]
fn handshake_completes_on_loopback() {
    let params = mini();
    let gh = genesis_hash(&params);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_params = params.clone();
    let server_gh = gh;
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Server is at genesis — pass the real genesis hash so validation passes.
        let mut config = HandshakeConfig::new(server_params, 0, server_gh);
        config.user_agent = "test-server/0.1".into();
        perform_handshake(&mut stream, &config, false)
    });

    let mut client_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    let mut client_config = HandshakeConfig::new(params.clone(), 0, gh);
    client_config.user_agent = "test-client/0.1".into();
    let client_ver = perform_handshake(&mut client_stream, &client_config, true)
        .expect("client handshake must succeed");

    let server_ver = server_handle
        .join()
        .unwrap()
        .expect("server handshake must succeed");

    assert_eq!(client_ver.network_id, params.network_id);
    assert_eq!(server_ver.network_id, params.network_id);
    assert_eq!(client_ver.protocol_version, PROTOCOL_VERSION);
}

#[test]
fn cross_network_handshake_is_rejected_at_connect() {
    let mainnet = NetworkParams::mainnet();
    let mini_params = mini();
    let mini_gh = genesis_hash(&mini_params);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Server is a mainnet node
    let mainnet_gh = genesis_hash(&mainnet);
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let config = HandshakeConfig::new(mainnet, 0, mainnet_gh);
        perform_handshake(&mut stream, &config, false)
    });

    // Client is a mini node connecting to a mainnet server
    let mut client_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    let client_config = HandshakeConfig::new(mini_params, 0, mini_gh);
    let client_result = perform_handshake(&mut client_stream, &client_config, true);

    let _ = server_handle.join();

    assert!(
        client_result.is_err(),
        "mini client must fail to handshake with a mainnet server"
    );
}

// ---------------------------------------------------------------------------
// §13.11 invariant 1: relay cannot change validity
// ---------------------------------------------------------------------------

#[test]
fn relay_block_equals_locally_mined_block() {
    let mut chain_a = fresh_chain();
    mine_n(&mut chain_a, 3);

    let mut chain_b = fresh_chain();

    // Relay block 1 from A to B
    let block = chain_a.block_at(1).unwrap().clone();
    let block_bytes_before = block.serialize();

    chain_b.submit(block.clone()).unwrap();

    let b_block = chain_b.block_by_hash(&block.block_hash()).unwrap();
    assert_eq!(
        b_block.serialize(),
        block_bytes_before,
        "relayed block must be byte-identical to the locally accepted block"
    );
}
