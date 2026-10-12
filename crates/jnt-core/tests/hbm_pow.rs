//! M4 registration regression: the HBM scratchpad puzzle is a registered
//! `puzzle_id = 2`, so a chain configured for it mines and accepts id=2 blocks,
//! and an unregistered puzzle id is rejected before PoW.
//!
//! Run with `cargo test -p jnt-core --test hbm_pow`.

use jnt_core::block::GENESIS_TIMESTAMP_MS;
use jnt_core::chain::Chain;
use jnt_core::hbm_pow::HbmConfig;
use jnt_core::params::NetworkParams;

/// Difficulty 1 ⇒ target is all-ones ⇒ every memory hash satisfies, so mining
/// is instant regardless of puzzle kind. These tests exercise the dispatch, not
/// the work.
fn hbm_params() -> NetworkParams {
    let mut p = NetworkParams::mini();
    p.puzzle_id = 2;
    p.hbm = HbmConfig::test();
    p
}

fn ts(height: u64) -> u64 {
    GENESIS_TIMESTAMP_MS + height * 1_000
}

#[test]
fn an_hbm_puzzle_id_2_block_is_mined_and_accepted() {
    let mut chain = Chain::new(hbm_params()).unwrap();
    let b = chain
        .mine_block([1u8; 20], vec![], ts(1))
        .expect("id=2 blocks must mine with the HBM dispatch");
    assert_eq!(b.header.puzzle_id, 2, "header must carry the HBM puzzle id");
    chain
        .submit(b)
        .expect("a valid HBM block must be accepted by check_block");
}

#[test]
fn an_unregistered_puzzle_id_is_rejected_before_pow() {
    // Mine a valid id=1 block, then rebadge it with an unknown puzzle id. The
    // rejection must come from the registry (UnknownPuzzle), not from PoW.
    let mut chain = Chain::new(NetworkParams::mini()).unwrap();
    let mut b = chain
        .mine_block([1u8; 20], vec![], ts(1))
        .expect("id=1 block must mine");
    b.header.puzzle_id = 999;
    let err = format!("{:?}", chain.submit(b).unwrap_err());
    assert!(
        err.contains("UnknownPuzzle(999)"),
        "expected UnknownPuzzle, got {err}"
    );
}

#[test]
fn hbm_config_validates_degenerate_zero_lanes() {
    assert!(matches!(
        HbmConfig {
            lanes: 0,
            accesses: 8
        }
        .validate(),
        Err(jnt_core::error::Error::BadPuzzleSpec(_))
    ));
}
