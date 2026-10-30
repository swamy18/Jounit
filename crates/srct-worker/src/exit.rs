//! Queueing an L2 → L1 exit from the worker SDK (approved P1, E-1).
//!
//! A worker holds L2 balances it cannot otherwise move back to L1. This is the
//! only SDK path that asks for that: it debits the owner on L2 and records the
//! exit the permissionless crank later settles on L1. It follows the same shape
//! as [`crate::claim`] — plan locally, then broadcast — because the balance
//! check has to happen against a state that may already have moved.

use srct_core::hash::Address;
use srct_core::l2::{ExitQueuePayload, L2Payload, L2Transaction};
use srct_core::wallet::Wallet;
use srct_l2::L2State;

use crate::error::{WorkerError, WorkerResult};
use crate::node::{Host, L2Broadcaster, L2NodeView};

/// What queueing an exit costs, and what will be paid out.
///
/// Every figure the caller needs to decide whether to exit is here, so nobody
/// has to go read the L2 state to find out what an exit would net them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPlan {
    /// The transaction the node must carry for the queue to take effect.
    pub tx: L2Transaction,
    /// The exit identity, `(owner, nonce)` — released exactly once, ever.
    pub owner: Address,
    pub nonce: u64,
    /// Satoshis that will land at `destination` on L1.
    pub amount_sat: u64,
    /// Satoshis prepaid to whoever cranks the release. This is what makes the
    /// crank permissionless without being a griefing surface.
    pub exit_fee_sat: u64,
    pub destination: Address,
    /// Flat queue fee charged on L2 at queue time, on top of the debit.
    pub queue_fee_sat: u64,
    /// Total debited from the L2 balance by this queue.
    pub total_debit_sat: u64,
    /// Transaction id, for reconciling a broadcast whose outcome is unknown.
    pub txid: srct_core::hash::Hash512,
}

/// Build the exit queue transaction without broadcasting it.
///
/// Fails, without mutating anything, when: the amount is zero, the destination
/// is the sink (paying the sink an exit would move value in, not out), the
/// balance cannot cover principal plus prepaid fee plus the queue fee, or the
/// profile has not activated exits at this height. The last case matters most
/// for mainnet today: `exit_activation_height == 0` means *never*, so queueing
/// there is refused rather than leaving funds encumbered with no release.
pub fn queue_exit_plan(
    wallet: &Wallet,
    amount_sat: u64,
    destination: Address,
    exit_fee_sat: u64,
    nonce: u64,
    state: &L2State,
    height: u64,
) -> WorkerResult<ExitPlan> {
    let owner = wallet
        .address()
        .map_err(|_| WorkerError::IdentityMismatch)?;
    if amount_sat == 0 {
        return Err(WorkerError::Protocol(srct_l2::L2Error::ZeroAmount(
            "an exit must move a non-zero amount",
        )));
    }
    // The SDK promised this check in its own docstring but never performed
    // it: an exit to the sink moves value *in*, not out, and the protocol
    // would queue it into an unspendable address. Refused locally, before
    // any fee is considered.
    if destination == state.deposit_sink() {
        return Err(WorkerError::Protocol(srct_l2::L2Error::BadExitDestination(
            "the destination is the deposit sink",
        )));
    }
    if !state.exit_queue_is_active(height) {
        return Err(WorkerError::TaskNotAvailable(
            "exits are not active at this height on this profile",
        ));
    }
    let queue_fee_sat = srct_core::l2::L2TxType::ExitQueue.fee_sat();
    let total_debit_sat = amount_sat
        .checked_add(exit_fee_sat)
        .and_then(|v| v.checked_add(queue_fee_sat))
        .ok_or(WorkerError::Protocol(srct_l2::L2Error::Overflow))?;
    let have = state.balance(&owner);
    if have < total_debit_sat {
        return Err(WorkerError::InsufficientBalance {
            needed: total_debit_sat,
            available: have,
        });
    }
    let payload = ExitQueuePayload::build(wallet, nonce, amount_sat, destination, exit_fee_sat)?;
    let tx = L2Transaction::new(L2Payload::ExitQueue(payload));
    Ok(ExitPlan {
        txid: tx.txid(),
        owner,
        nonce,
        amount_sat,
        exit_fee_sat,
        destination,
        queue_fee_sat,
        total_debit_sat,
        tx,
    })
}

/// Build and broadcast in one call. Returns the plan that was sent.
///
/// A [`WorkerError::BroadcastUnavailable`] means the transaction MAY have landed
/// (SPEC.md §18.9) — reconcile by `plan.txid`, exactly as for a claim.
pub fn queue_exit<V: L2NodeView, B: L2Broadcaster>(
    host: &mut Host<V, B>,
    wallet: &Wallet,
    amount_sat: u64,
    destination: Address,
    exit_fee_sat: u64,
    nonce: u64,
) -> WorkerResult<ExitPlan> {
    let (state, height) = host.observe()?;
    let plan = queue_exit_plan(
        wallet,
        amount_sat,
        destination,
        exit_fee_sat,
        nonce,
        &state,
        height,
    )?;
    host.broadcast(&plan.tx).map_err(WorkerError::from)?;
    Ok(plan)
}
