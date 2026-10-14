//! Shared in-memory node harness for the worker-SDK integration tests.
//!
//! `Core` is the "node": an `L2State`, a validator set, a height, and a
//! broadcast path that applies transactions exactly like `L2State::apply` —
//! because that IS the protocol. `TestView`/`TestNet` adapt it to the SDK's
//! §18.3 seams, sharing one `Rc<RefCell<Core>>` so a restarted client sees
//! the same authoritative state a live network would serve.

// Shared harness: helpers not used by every test binary are not dead code.
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use jnt_core::bls_checkpoint::{BlsVerifier, ValidatorSet};
use jnt_core::hash::Hash512;
use jnt_core::l2::L2Transaction;
use jnt_core::wallet::Wallet;
use jnt_l2::{L2Config, L2State};
use jnt_worker::node::{BroadcastError, L2Broadcaster, L2NodeView};

pub mod bls;

/// The "node" under the seams. Applying here (rather than queueing) is what a
/// single-node network does: broadcast == accepted, modulo the app's own
/// refusals, which is exactly the surface the SDK has to survive.
pub struct Core {
    pub state: L2State,
    pub height: u64,
    ///preset broadcast failures, consumed in order: Some(err) => next
    /// broadcast returns it instead of applying.
    pub fail_next: Vec<BroadcastError>,
}

impl Core {
    pub fn new(credited: u64) -> Self {
        let mut state = L2State::new(L2Config::mini());
        for seed in 1..=3u8 {
            state
                .credit(wallet(seed).address().unwrap(), credited)
                .unwrap();
        }
        Core {
            state,
            height: 1,
            fail_next: Vec::new(),
        }
    }

    /// Apply like a node would, refusing replays and invalid payloads.
    pub fn apply(&mut self, tx: &L2Transaction) -> Result<Hash512, String> {
        if let Some(err) = self.fail_next.pop() {
            return Err(match err {
                BroadcastError::Retryable(s) => format!("retryable: {s}"),
                BroadcastError::Refused(s) => format!("refused: {s}"),
            });
        }
        // A real verifier: only a genuine quorum aggregate settles.
        let mut state = self.state.clone();
        let res = state.apply(tx, self.height, &self.validators(), &RealVerifier);
        self.state = state;
        res.map(|_| tx.txid()).map_err(|e| format!("{e:?}"))
    }

    pub fn validators(&self) -> ValidatorSet {
        bls::validator_set(4)
    }
}

/// The `BlsVerifier` impl a node would run: real BLS (blst).
pub struct RealVerifier;

impl BlsVerifier for RealVerifier {
    fn verify_aggregate(
        &self,
        signers: &[jnt_core::bls_checkpoint::BlsPublicKey],
        msg: &jnt_core::hash::Hash,
        sig: &jnt_core::bls_checkpoint::BlsSignature,
    ) -> bool {
        jnt_core::bls::RealBls::verify_aggregate(signers, msg, sig)
    }
}

pub fn wallet(seed: u8) -> Wallet {
    Wallet::from_private_key_bytes(&[seed; 32], "worker-test").unwrap()
}

pub fn addr(w: &Wallet) -> jnt_core::hash::Address {
    w.address().unwrap()
}

/// Read seam. Clones the state — the SDK model where observation is a query.
pub struct TestView(Rc<RefCell<Core>>);

impl TestView {
    pub fn new(core: &Rc<RefCell<Core>>) -> Self {
        TestView(Rc::clone(core))
    }
}

impl L2NodeView for TestView {
    fn l2_state(&self) -> jnt_worker::WorkerResult<L2State> {
        Ok(self.0.borrow().state.clone())
    }
    fn chain_height(&self) -> jnt_worker::WorkerResult<u64> {
        Ok(self.0.borrow().height)
    }
}

/// Write seam. Applies into the shared core (single-node broadcast path).
pub struct TestNet(Rc<RefCell<Core>>);

impl TestNet {
    pub fn new(core: &Rc<RefCell<Core>>) -> Self {
        TestNet(Rc::clone(core))
    }
}

impl L2Broadcaster for TestNet {
    fn broadcast(&mut self, tx: &L2Transaction) -> Result<(), BroadcastError> {
        self.0.borrow_mut().apply(tx).map(|_| ()).map_err(|msg| {
            if msg.starts_with("retryable:") {
                BroadcastError::Retryable(msg)
            } else {
                BroadcastError::Refused(msg)
            }
        })
    }
}

/// Advance the core's height (the "chain moved" event).
pub fn advance(core: &Rc<RefCell<Core>>, to: u64) {
    core.borrow_mut().height = to;
    core.borrow_mut().state.advance_block(to);
}

/// A default test filter config for a wallet.
pub fn client_config(w: &Wallet) -> jnt_worker::WorkerConfig {
    jnt_worker::WorkerConfig::from_wallet(w).with_deposit(100_000)
}
