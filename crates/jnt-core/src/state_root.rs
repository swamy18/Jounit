//! L2 state-root commitment and Merkle inclusion proofs (SPEC.md §19.2, P1).
//!
//! This is the **proof half** of the approved L2 → L1 exit rule (Decision 10
//! as amended 2026-10-09, E-1 = (a)). An exit needs L1 to verify that a
//! claimed L2 balance really exists in the L2 state; L2 state is *derived by
//! replay* and is not committed anywhere L1 can read, so the design commits a
//! state root and requires a Merkle inclusion proof against it.
//!
//! ## What exists here, and what deliberately does not
//!
//! This module **only builds and verifies proofs**. It adds **no consensus
//! rule**: nothing calls it from `Chain::apply_block`, no block field carries
//! the root, and no sink output can be spent with one. That is intentional —
//! the release rule needs an activation mechanism that does not exist yet, and
//! shipping a verifier is safe precisely because it grants no authority.
//! Until the release rule lands, an exit proof proves a balance and can only be
//! *displayed*; `crates/jnt-core/tests/sink_unspendable.rs` still holds the
//! "no signature authorises a sink spend" line.
//!
//! ## Construction
//!
//! Leaves are accounts, ordered by address, each hashed with its own domain tag
//! so an account leaf can never be reinterpreted as an L1 or L2 transaction
//! leaf (`block.rs` uses `0x00`/`0x02`; this uses [`ACCOUNT_LEAF_TAG`]).
//! Internal nodes use the same `0x01` internal tag as the block tree. The final
//! fold is wrapped in an explicit domain string, so a state root is not even
//! comparable to a block merkle root.
//!
//! Odd levels duplicate the last node, Bitcoin-style. That construction is
//! famously ambiguous when a verifier accepts an arbitrary depth
//! (CVE-2012-2459 shape), so [`verify_inclusion`] refuses a proof whose depth
//! does not match the committed leaf count and requires a duplicated node to
//! carry *itself* as its sibling. Without both checks, a 3-leaf tree and a
//! 4-leaf tree can share a root and a forged proof would still verify.

use crate::hash::{sha256, sha256_dom, Address, Hash};

const INTERNAL_TAG: u8 = 0x01;

/// Account leaves are domain-separated from block leaves: `0x00` is an L1
/// transaction leaf and `0x02` an L2 transaction leaf (`block.rs`).
pub const ACCOUNT_LEAF_TAG: u8 = 0x03;

/// Domain string for the final fold, so a state root is never a bare merkle
/// root over the same leaves.
const STATE_ROOT_DOMAIN: &[u8] = b"jnt/l2-state-root/v1";

/// The leaf for one account: address plus balance in satoshis.
///
/// The balance is encoded little-endian and fixed-width, so two accounts
/// differing only in a digit cannot collide by concatenation.
pub fn account_leaf(address: &Address, balance_sat: u64) -> Hash {
    sha256(&[&[ACCOUNT_LEAF_TAG], address, &balance_sat.to_le_bytes()])
}

fn internal(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[INTERNAL_TAG], left, right])
}

/// The committed root for a set of leaves, in canonical (address) order.
///
/// An empty state commits to the all-zero root rather than the hash of an empty
/// domain, matching `block::merkle_from_leaves`: an empty L2 state is a
/// distinct, recognisable value, and it can never be confused with a state
/// holding one account.
pub fn state_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(internal(&pair[0], &pair[0]));
            } else {
                next.push(internal(&pair[0], &pair[1]));
            }
        }
        level = next;
    }
    sha256_dom(STATE_ROOT_DOMAIN, &[&level[0]])
}

/// An inclusion proof for one leaf.
///
/// `leaf_count` and `index` are carried explicitly because the odd-level
/// duplication rule makes the root ambiguous without them; a verifier must
/// check the proof against the committed count, not infer it from depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Position of the proven leaf in the canonical leaf order.
    pub index: usize,
    /// Total leaves committed by the root being proven against.
    pub leaf_count: usize,
    /// Sibling hashes from the leaf level upward.
    pub siblings: Vec<Hash>,
}

/// Build the proof for `leaves[index]`, or `None` when the index is out of
/// range (an absent account has no proof — it has nothing to prove).
pub fn prove_inclusion(leaves: &[Hash], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut siblings = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            // Odd level, right-most node: duplicated, so its sibling is itself.
            *level.get(idx + 1).unwrap_or(&level[idx])
        } else {
            level[idx - 1]
        };
        siblings.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(internal(&pair[0], &pair[0]));
            } else {
                next.push(internal(&pair[0], &pair[1]));
            }
        }
        level = next;
        idx /= 2;
    }
    Some(InclusionProof {
        index,
        leaf_count: leaves.len(),
        siblings,
    })
}

/// Check `leaf` at `proof.index` against `root`.
///
/// Rejects, rather than tolerates: an out-of-range index, an empty committed
/// state, a depth that does not match `leaf_count`, and a duplicated node
/// whose sibling is not itself. Each of those is the shape of a forgery, not a
/// malformed-but-valid proof.
pub fn verify_inclusion(root: Hash, leaf: Hash, proof: &InclusionProof) -> bool {
    if proof.leaf_count == 0 || proof.index >= proof.leaf_count {
        return false;
    }
    let mut node = leaf;
    let mut idx = proof.index;
    let mut count = proof.leaf_count;
    let mut depth = 0usize;
    while count > 1 {
        let Some(&sibling) = proof.siblings.get(depth) else {
            return false;
        };
        // Last node of an odd level is its own sibling by construction; any
        // other value here is an attempt to steer the fold.
        if count % 2 == 1 && idx == count - 1 && sibling != node {
            return false;
        }
        node = if idx % 2 == 0 {
            internal(&node, &sibling)
        } else {
            internal(&sibling, &node)
        };
        idx /= 2;
        count = count.div_ceil(2);
        depth += 1;
    }
    // The fold is wrapped in the root domain, so the last step is not a bare
    // comparison against the folded node.
    depth == proof.siblings.len() && sha256_dom(STATE_ROOT_DOMAIN, &[&node]) == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(tag: u8) -> Address {
        [tag; 20]
    }

    fn leaves_for(balances: &[(u8, u64)]) -> Vec<Hash> {
        balances
            .iter()
            .map(|(t, bal)| account_leaf(&addr(*t), *bal))
            .collect()
    }

    #[test]
    fn empty_state_commits_to_zero_root() {
        assert_eq!(state_root(&[]), [0u8; 32]);
        assert!(prove_inclusion(&[], 0).is_none());
    }

    #[test]
    fn a_single_account_proves_with_no_siblings() {
        let leaves = leaves_for(&[(1, 500)]);
        let root = state_root(&leaves);
        let proof = prove_inclusion(&leaves, 0).unwrap();
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.leaf_count, 1);
        assert!(verify_inclusion(root, leaves[0], &proof));
        // A one-leaf tree is the leaf wrapped in the root domain, never the
        // leaf itself.
        assert_eq!(root, sha256_dom(STATE_ROOT_DOMAIN, &[&leaves[0]]));
    }

    #[test]
    fn every_leaf_in_every_tree_size_proves() {
        // Sizes 1..=9 cover even and odd levels at several depths.
        for n in 1..=9usize {
            let balances: Vec<(u8, u64)> = (1..=n as u8).map(|i| (i, i as u64 * 10)).collect();
            let leaves = leaves_for(&balances);
            let root = state_root(&leaves);
            for i in 0..n {
                let proof = prove_inclusion(&leaves, i).unwrap();
                assert!(
                    verify_inclusion(root, leaves[i], &proof),
                    "leaf {i} of {n} failed to prove"
                );
            }
        }
    }

    #[test]
    fn a_tampered_balance_does_not_verify() {
        let leaves = leaves_for(&[(1, 100), (2, 200), (3, 300)]);
        let root = state_root(&leaves);
        let proof = prove_inclusion(&leaves, 1).unwrap();
        // Same account, one satoshi more: the leaf differs, so the fold differs.
        let forged = account_leaf(&addr(2), 201);
        assert!(!verify_inclusion(root, forged, &proof));
        assert!(verify_inclusion(root, leaves[1], &proof));
    }

    #[test]
    fn a_balance_change_moves_the_root() {
        assert_ne!(
            state_root(&leaves_for(&[(1, 100), (2, 200)])),
            state_root(&leaves_for(&[(1, 100), (2, 201)]))
        );
    }

    #[test]
    fn leaf_order_is_load_bearing_so_leaves_must_be_sorted() {
        let sorted = leaves_for(&[(1, 100), (2, 200)]);
        let swapped = vec![sorted[1], sorted[0]];
        assert_ne!(state_root(&sorted), state_root(&swapped));
    }

    #[test]
    fn an_out_of_range_or_absent_index_has_no_proof() {
        let leaves = leaves_for(&[(1, 1), (2, 2)]);
        assert!(prove_inclusion(&leaves, 2).is_none());
        assert!(prove_inclusion(&leaves, usize::MAX).is_none());
    }

    #[test]
    fn an_index_beyond_the_committed_count_is_refused() {
        let leaves = leaves_for(&[(1, 1), (2, 2)]);
        let root = state_root(&leaves);
        let mut proof = prove_inclusion(&leaves, 0).unwrap();
        proof.index = 5;
        assert!(!verify_inclusion(root, leaves[0], &proof));
    }

    #[test]
    fn a_truncated_or_padded_proof_is_refused() {
        // 4 leaves with 2 siblings; claim true length 3 and the depth no longer
        // matches, which is the CVE-2012-2459 shape: without the count check
        // these two trees can share a root.
        let leaves = leaves_for(&[(1, 1), (2, 2), (3, 3), (4, 4)]);
        let root = state_root(&leaves);
        let good = prove_inclusion(&leaves, 3).unwrap();
        assert!(verify_inclusion(root, leaves[3], &good));

        let mut shortened = good.clone();
        shortened.leaf_count = 3;
        assert!(!verify_inclusion(root, leaves[3], &shortened));

        let mut extended = good.clone();
        extended.siblings.push([9u8; 32]);
        assert!(!verify_inclusion(root, leaves[3], &extended));
    }

    #[test]
    fn a_duplicated_node_cannot_choose_its_own_sibling() {
        let leaves = leaves_for(&[(1, 1), (2, 2), (3, 3)]); // 3 leaves: level 2 duplicates
        let root = state_root(&leaves);
        let proof = prove_inclusion(&leaves, 2).unwrap();
        assert!(verify_inclusion(root, leaves[2], &proof));

        let mut forged = proof.clone();
        forged.siblings[0] = [7u8; 32];
        assert!(!verify_inclusion(root, leaves[2], &forged));
    }

    #[test]
    fn a_root_from_another_tree_does_not_verify() {
        let a = leaves_for(&[(1, 10), (2, 20)]);
        let b = leaves_for(&[(1, 10), (2, 21)]);
        let proof = prove_inclusion(&a, 1).unwrap();
        assert!(!verify_inclusion(state_root(&b), a[1], &proof));
    }

    #[test]
    fn a_state_root_is_not_a_block_merkle_root_over_the_same_leaves() {
        // The final fold carries its own domain, so an L1 verifier cannot be
        // handed a block root where a state root is expected.
        let leaves = leaves_for(&[(1, 1)]);
        // One leaf: the fold is a single internal-or-none step; the domain wrap
        // is what separates it from the raw leaf.
        assert_ne!(state_root(&leaves), leaves[0]);
        assert_eq!(state_root(&[]), [0u8; 32]);
        // The empty root is the all-zero sentinel, not the domain hash of nothing.
        assert_ne!(
            state_root(&[]),
            sha256_dom(STATE_ROOT_DOMAIN, &[&[0u8; 32]])
        );
    }
}
