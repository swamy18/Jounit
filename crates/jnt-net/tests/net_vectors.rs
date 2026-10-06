//! Wire-format vectors for `jnt-net`. SPEC.md §13.12.
//!
//! The §13 message set is frozen, so the bytes on the wire are a contract
//! between implementations exactly as much as a block hash is. A silent change
//! to field order, byte order or a length prefix would still pass every
//! round-trip test in this crate — a round trip only proves the codec agrees
//! with itself — while breaking every peer running the previous version. These
//! vectors pin the bytes themselves.
//!
//! Regenerate with `UPDATE_NET_VECTORS=1 cargo test -p jnt-net`.
//!
//! Note what is *not* here: a second implementation, the way
//! `sim/jounit_reference.py` re-derives the puzzle from §5 prose. A disagreement
//! between two encoders of these rules looks exactly like a consensus split,
//! and that check is still owed.

use jnt_core::chain::Chain;
use jnt_core::hash::Hash;
use jnt_core::params::NetworkParams;
use jnt_net::frame::{read_frame, write_frame, MAX_FRAME_PAYLOAD};
use jnt_net::msg::{
    InvEntry, Message, MessageType, SocketAddr as WireAddr, Version, INV_TYPE_BLOCK,
    MAX_ADDR_PER_MSG, MAX_INV_PER_MSG, MAX_LOCATOR_ENTRIES, PROTOCOL_VERSION,
};
use jnt_net::syncer::{create_locator, find_fork_and_collect_inv};

use std::io::Cursor;

/// `jnt-net` deliberately depends only on `jnt-core` and std, so the test
/// carries its own hex encoder rather than pulling in a dependency for one
/// function.
fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A pinned payload: `(name, hex)`.
type Item = (String, String);
/// A pinned scalar: `(name, value)`.
type Fact = (String, u64);

/// `(name, hex bytes)` pairs plus scalar facts, written as one JSON document.
fn build_vectors() -> (Vec<Item>, Vec<Fact>) {
    let mini = NetworkParams::mini();
    let mut items: Vec<(String, String)> = Vec::new();
    let mut facts: Vec<(String, u64)> = Vec::new();

    // --- frames ---------------------------------------------------------
    // magic(4) ‖ msg_type(1) ‖ payload_len(4 LE) ‖ payload
    let mut wire = Vec::new();
    write_frame(&mut wire, &mini, 7, b"jnt").unwrap();
    items.push(("frame_inv_type7_len3".into(), hex_of(&wire)));

    let mut cursor = Cursor::new(wire);
    let (ty, payload) = read_frame(&mut cursor, &mini).unwrap();
    assert_eq!(ty, 7);
    assert_eq!(payload, b"jnt");

    // --- VERSION, every profile ----------------------------------------
    for (label, params) in [
        ("mainnet", NetworkParams::mainnet()),
        ("mini", mini.clone()),
    ] {
        let v = Version {
            network_magic: params.network_magic,
            network_id: params.network_id.clone(),
            protocol_version: PROTOCOL_VERSION,
            services: 1,
            height: 42,
            tip_hash: [0x5Au8; 32],
            user_agent: "/jnt-net:0.2".into(),
            nonce: 0x0123_4567_89AB_CDEF,
        };
        let enc = Message::Version(v).encode();
        facts.push((format!("version_{label}_len"), enc.len() as u64));
        items.push((format!("version_{label}"), hex_of(&enc)));
    }

    // --- every msg_type round-trips to a pinned payload -----------------
    let msgs: Vec<(&str, Message)> = vec![
        ("verack", Message::Verack { nonce: 0xDEAD }),
        ("ping", Message::Ping { nonce: 0xBEEF }),
        ("pong", Message::Pong { nonce: 0xFEED }),
        (
            "inv",
            Message::Inv(vec![
                InvEntry {
                    kind: INV_TYPE_BLOCK,
                    hash: [0x11u8; 32],
                },
                InvEntry {
                    kind: INV_TYPE_BLOCK,
                    hash: [0x22u8; 32],
                },
            ]),
        ),
        (
            "getdata",
            Message::GetData(vec![InvEntry {
                kind: INV_TYPE_BLOCK,
                hash: [0x33u8; 32],
            }]),
        ),
        (
            "getblocks",
            Message::GetBlocks {
                locator: vec![[0x44u8; 32], [0x55u8; 32]],
                stop: [0x66u8; 32],
            },
        ),
        (
            "addr",
            Message::Addr(vec![WireAddr {
                // IPv4-mapped IPv6: ::ffff:127.0.0.1 (§13.5)
                ip: {
                    let mut ip = [0u8; 16];
                    ip[10] = 0xFF;
                    ip[11] = 0xFF;
                    ip[12] = 127;
                    ip[15] = 1;
                    ip
                },
                port: 8333,
            }]),
        ),
    ];
    for (name, msg) in &msgs {
        let enc = msg.encode();
        facts.push((format!("{name}_len"), enc.len() as u64));
        items.push((format!("msg_{name}"), hex_of(&enc)));
    }

    // --- BLOCK ----------------------------------------------------------
    let mut chain = Chain::new(NetworkParams::mini()).expect("mini chain");
    let b = chain
        .mine_block(
            [7u8; 20],
            vec![],
            jnt_core::block::GENESIS_TIMESTAMP_MS + 1_000,
        )
        .expect("mine block 1");
    let block_bytes = b.serialize();
    facts.push(("block1_len".into(), block_bytes.len() as u64));
    items.push(("block1".into(), hex_of(&block_bytes)));

    // Decode must return the identical block, not merely a block.
    match Message::decode(MessageType::Block as u8, &block_bytes).unwrap() {
        Message::Block(decoded) => assert_eq!(*decoded, b),
        other => panic!("expected Block, got {other:?}"),
    }

    // --- locator construction from a 200-block chain --------------------
    let mut ts = jnt_core::block::GENESIS_TIMESTAMP_MS + 1;
    for _ in 0..200 {
        let blk = chain.mine_block([7u8; 20], vec![], ts).unwrap();
        chain.submit(blk).unwrap();
        ts += 60_000;
    }
    let locator = create_locator(&chain);
    facts.push(("locator_len_200".into(), locator.len() as u64));
    for (i, h) in locator.iter().enumerate().take(8) {
        items.push((format!("locator_{i}"), hex_of(h)));
    }

    // --- GETBLOCKS response against a divergent chain --------------------
    // A requester at genesis gets heights 1..=200, capped at max_inv_per_msg.
    let genesis_only = Chain::new(NetworkParams::mini()).unwrap();
    let loc = create_locator(&genesis_only);
    let inv = find_fork_and_collect_inv(&chain, &loc, &Hash::default());
    facts.push(("inv_from_genesis_len".into(), inv.len() as u64));
    items.push(("inv_from_genesis_first".into(), hex_of(&inv[0].hash)));

    // --- spec bounds, as scalars ---------------------------------------
    facts.push(("max_frame_payload".into(), MAX_FRAME_PAYLOAD as u64));
    facts.push(("max_inv_per_msg".into(), MAX_INV_PER_MSG as u64));
    facts.push(("max_addr_per_msg".into(), MAX_ADDR_PER_MSG as u64));
    facts.push(("max_locator_len".into(), MAX_LOCATOR_ENTRIES as u64));

    (items, facts)
}

#[test]
fn net_vectors_are_stable() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/net_vectors.json");
    let (items, facts) = build_vectors();

    let mut doc = serde_json::Map::new();
    doc.insert("spec_section".into(), serde_json::json!("13.12"));
    doc.insert(
        "note".into(),
        serde_json::json!(
            "Wire-format vectors. Regenerate with UPDATE_NET_VECTORS=1 cargo test -p jnt-net. \
             No independent implementation exists yet, unlike sim/jounit_reference.py for §5."
        ),
    );
    doc.insert(
        "items".into(),
        serde_json::Value::Array(
            items
                .iter()
                .map(|(n, h)| serde_json::json!({ "name": n, "hex": h }))
                .collect(),
        ),
    );
    doc.insert(
        "facts".into(),
        serde_json::Value::Array(
            facts
                .iter()
                .map(|(n, v)| serde_json::json!({ "name": n, "value": v }))
                .collect(),
        ),
    );
    let json = serde_json::to_string_pretty(&serde_json::Value::Object(doc)).unwrap();

    if std::env::var("UPDATE_NET_VECTORS").is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, json).unwrap();
        eprintln!("wrote {}", path.display());
        return;
    }

    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nregenerate with UPDATE_NET_VECTORS=1",
            path.display()
        )
    });
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();

    let listed = v["items"].as_array().expect("items must be an array");
    assert_eq!(
        listed.len(),
        items.len(),
        "vector file is stale: item count"
    );
    for (entry, (name, hex)) in listed.iter().zip(items.iter()) {
        assert_eq!(entry["name"].as_str().unwrap(), name);
        assert_eq!(
            entry["hex"].as_str().unwrap(),
            hex,
            "wire bytes for `{name}` changed — a frozen §13.5 payload must not move"
        );
    }

    let listed_facts = v["facts"].as_array().expect("facts must be an array");
    assert_eq!(
        listed_facts.len(),
        facts.len(),
        "vector file is stale: fact count"
    );
    for (entry, (name, value)) in listed_facts.iter().zip(facts.iter()) {
        assert_eq!(entry["name"].as_str().unwrap(), name);
        assert_eq!(entry["value"].as_u64().unwrap(), *value, "`{name}` changed");
    }

    // Independent restatements of the §13.5 layout, so a vector file that was
    // regenerated from wrong code cannot pass silently. VERSION is
    // magic(4) + id_len(1) + id + proto(4) + services(8) + height(8) +
    // tip(32) + ua_len(1) + ua + nonce(8).
    const FIXED: u64 = 4 + 1 + 4 + 8 + 8 + 32 + 1 + 8;
    let fact = |name: &str| -> u64 {
        listed_facts
            .iter()
            .find(|f| f["name"] == name)
            .unwrap_or_else(|| panic!("fact `{name}` is missing"))["value"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(
        fact("version_mainnet_len"),
        FIXED + 14 + 12,
        "VERSION payload layout (13.4)"
    );
    assert_eq!(
        fact("version_mini_len"),
        FIXED + 11 + 12,
        "VERSION length tracks network_id"
    );
    assert_eq!(fact("max_locator_len"), 500, "13.8");
    assert_eq!(fact("max_inv_per_msg"), 500, "13.8");
    assert_eq!(fact("max_addr_per_msg"), 100, "13.8");
    assert_eq!(fact("max_frame_payload"), 4_100_000, "13.8");
    assert!(
        fact("inv_from_genesis_len") <= MAX_INV_PER_MSG as u64,
        "a GETBLOCKS response must never exceed max_inv_per_msg"
    );
    assert_eq!(
        fact("inv_from_genesis_len"),
        200,
        "a genesis-only peer is answered with every block after the fork point"
    );
}

/// A block frame carrying a maximum-size block must fit inside the cap: the
/// bound is `max_block_bytes + 100_000` precisely so this holds (§13.8).
#[test]
fn a_maximum_size_block_is_relayable_within_the_frame_cap() {
    let params = NetworkParams::mini();
    assert!(
        MAX_FRAME_PAYLOAD as usize > params.max_block_bytes,
        "max_frame_bytes must exceed max_block_bytes, or no maximum block is relayable"
    );
}
