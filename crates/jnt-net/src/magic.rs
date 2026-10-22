//! Network identity. SPEC.md §13.3.
//!
//! Both profiles share `genesis_difficulty = 1`, so `genesis_block()` is
//! identical and the genesis hashes are identical (`params.rs` now tests this
//! explicitly). The 4-byte magic is therefore the *only* cheap,
//! allocation-free discriminator at the framing layer, and the `network_id`
//! string is the human-readable one exchanged in the handshake. Both are
//! required, and any two live profiles MUST differ in both.

use crate::error::{NetError, NetResult};
use jnt_core::params::NetworkParams;

/// `magic` as a flat byte array in the canonical on-wire order.
pub fn magic_of(params: &NetworkParams) -> [u8; 4] {
    params.network_magic
}

/// Encode the 4-byte magic as the fixed prefix every frame starts with.
pub fn magic_bytes(params: &NetworkParams) -> Vec<u8> {
    params.network_magic.to_vec()
}

/// Validate that a peer's handshake declares our network. Magic is checked on
/// every frame; `network_id` is checked once at handshake. Both MUST match.
pub fn check_network(params: &NetworkParams, magic: [u8; 4], id: &str) -> NetResult<()> {
    let want_magic = params.network_magic;
    if magic != want_magic {
        return Err(NetError::InvalidMagic {
            got: magic,
            want: want_magic,
        });
    }
    if id != params.network_id {
        return Err(NetError::NetworkIdMismatch {
            got: id.to_string(),
            want: params.network_id.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_and_mini_do_not_share_an_identity() {
        let m = NetworkParams::mainnet();
        let n = NetworkParams::mini();
        assert_ne!(magic_of(&m), magic_of(&n));
        assert_ne!(m.network_id, n.network_id);
        // A cross-network handshake is rejected at both checks.
        assert!(check_network(&m, magic_of(&n), &n.network_id).is_err());
        assert!(check_network(&n, magic_of(&m), &m.network_id).is_err());
    }

    #[test]
    fn pre_bump_mainnet_magic_is_refused() {
        // The protocol bump moved mainnet 6A4E5401 -> 6A4E5402. An old node
        // still presenting 01 must be refused even with the right network id,
        // so a stale peer can never silently join the new mainnet.
        let m = NetworkParams::mainnet();
        let old_mainnet = [0x6A, 0x4E, 0x54, 0x01];
        assert!(check_network(&m, old_mainnet, &m.network_id).is_err());
        // And the new mainnet magic is not accepted by any other profile.
        for p in [NetworkParams::mini(), NetworkParams::testnet()] {
            assert!(check_network(&p, magic_of(&m), &p.network_id).is_err());
        }
    }
}
