//! L2 genesis funding: the Decision 7 escrow as replayed state.
//!
//! # What this is
//!
//! The single production source of L2 value: a total allocation fixed in
//! [`NetworkParams`](jnt_core::params::NetworkParams), released once per state
//! construction as grants to named accounts plus the remainder to the protocol
//! escrow identity. There is no other production funding path — no deposit
//! transaction (deferred by Decision 7), no validator or worker credit, and
//! `L2State::credit` stays a test seam that production never calls.
//!
//! # Why replay/restart/reorg cannot duplicate it
//!
//! Genesis is applied by [`L2State::apply_genesis`], which refuses a second
//! application, and only ever to a freshly constructed state: every
//! [`ChainL2`](crate::replay::ChainL2) constructor builds fresh state and
//! applies genesis exactly once. Restart and reorg both rebuild through those
//! constructors, so the funding exists exactly once in every derived state by
//! construction — there is no persisted funding record to go stale and no
//! block-carried funding to replay twice.
//!
//! # Conservation
//!
//! `L2State::funded_total` counts every satoshi genesis (or a test credit)
//! ever released; `conservation_total` counts every satoshi still inside the
//! system. Their equality is the M2 invariant, and together with the params
//! backing rule (`l2_genesis_escrow_sat ≤ escrow_ceiling_sat`, enforced by
//! `NetworkParams::validate`) it proves combined L1 + L2 money can never
//! exceed the joint bound — the L1 issuance integral at the tip plus
//! `escrow_ceiling_sat` (SPEC.md §19.4).

use jnt_core::hash::Address;
use jnt_core::params::NetworkParams;

use crate::error::{L2Error, L2Result};

/// The L2 genesis allocation for one network profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Genesis {
    /// Total allocation. Nothing in L2 may ever hold more than this:
    /// `funded_total` starts here and `credit` is never called by production
    /// again.
    pub escrow_total_sat: u64,
    /// `(address, amount)` pairs funded at genesis, in params order.
    /// Canonical by construction: every node holds the same params.
    pub grants: Vec<(Address, u64)>,
    /// Protocol identity holding `escrow_total_sat − granted`. Inert in M2:
    /// no disbursement rule exists for it yet, so it simply sits — provably
    /// unspendable, since no key exists for a derived address.
    pub escrow_id: Address,
}

impl L2Genesis {
    /// The allocation for `params`. Assumes valid params (`Chain` Construction
    /// validates them; tests use the shipped profiles or `empty`).
    pub fn for_params(params: &NetworkParams) -> Self {
        L2Genesis {
            escrow_total_sat: params.l2_genesis_escrow_sat,
            grants: params
                .l2_genesis_grants
                .iter()
                .map(|g| (g.address, g.amount_sat))
                .collect(),
            escrow_id: params.l2_escrow_address(),
        }
    }

    /// No funding at all: for unit tests that build custom-funded states via
    /// `credit`, preserving the M1 unfunded-behaviour coverage.
    pub fn empty() -> Self {
        L2Genesis {
            escrow_total_sat: 0,
            grants: Vec::new(),
            escrow_id: [0u8; 20],
        }
    }

    /// Satoshis released to named grants. Fails closed on overflow rather than
    /// understating the allocation.
    pub fn granted_total(&self) -> L2Result<u64> {
        let mut total = 0u64;
        for (_, amount) in &self.grants {
            total = total.checked_add(*amount).ok_or(L2Error::Overflow)?;
        }
        Ok(total)
    }

    /// What stays with the protocol escrow identity. Fails if the grants
    /// exceed the total rather than wrapping into a huge remainder.
    pub fn escrow_remainder(&self) -> L2Result<u64> {
        self.escrow_total_sat
            .checked_sub(self.granted_total()?)
            .ok_or(L2Error::Overflow)
    }

    /// Structural checks: no zero grant, no duplicate address, no grant to the
    /// escrow identity, grants within the total. The params-level gap-fit rule
    /// lives in `NetworkParams::validate` (it needs the supply schedule,
    /// which is `jnt-core`'s knowledge, not this crate's).
    pub fn validate(&self) -> L2Result<()> {
        for (addr, amount) in &self.grants {
            if *amount == 0 {
                return Err(L2Error::ZeroAmount("genesis grant"));
            }
            if *addr == self.escrow_id {
                return Err(L2Error::InvalidGenesis(
                    "grant must not name the escrow identity",
                ));
            }
        }
        let mut seen: Vec<Address> = Vec::with_capacity(self.grants.len());
        for (addr, _) in &self.grants {
            if seen.contains(addr) {
                return Err(L2Error::InvalidGenesis("duplicate genesis grant address"));
            }
            seen.push(*addr);
        }
        // Fails if grants exceed the total: funding above the escrow is the
        // exact inflation this module exists to prevent.
        let _ = self.escrow_remainder()?;
        Ok(())
    }
}
