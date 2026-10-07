//! Worker configuration (SPEC.md §18.12).
//!
//! Configuration is operator data: the wallet, the backend the machine offers,
//! the deposit to lock on the next claim, the discovery filter, and — bounded —
//! how much state one discovery pass may scan. The SDK holds the wallet by
//! value; nothing here (or in any error/Debug the SDK produces) renders
//! key material (§18.16).

use jnt_core::compute_ir::ComputeBackend;
use jnt_core::hash::Address;
use jnt_core::wallet::Wallet;

/// What a discovery pass may accept. Pure policy: the protocol is silent on
/// desirability, so every knob here defaults to permissive and narrowing is
/// the operator's choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Escrow floor. Tasks paying less are not surfaced.
    pub min_payment_sat: u64,
    /// Net (escrow minus the settle fee) floor.
    pub min_net_payment_sat: u64,
    /// `deadline_height - height` must not exceed this.
    pub max_deadline_distance: u64,
    /// Tasks requiring more memory than this are not surfaced.
    pub max_memory_bytes: u64,
    /// Backend classes the machine can honour.
    pub backends: Vec<ComputeBackend>,
    /// A scan bound on the number of tasks one state may expose. A state that
    /// exceeds it is treated as malformed observation, not silently truncated.
    pub max_scan: usize,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            min_payment_sat: 0,
            min_net_payment_sat: 0,
            // Far enough to be no filter; an operator narrows deliberately.
            max_deadline_distance: u64::MAX,
            max_memory_bytes: u64::MAX,
            backends: vec![
                ComputeBackend::Cpu,
                ComputeBackend::Gpu,
                ComputeBackend::Npu,
                ComputeBackend::Tpu,
                ComputeBackend::Ascend,
                ComputeBackend::Fpga,
                ComputeBackend::Photonic,
            ],
            max_scan: 100_000,
        }
    }
}

/// Operator-supplied worker configuration (§18.12).
///
/// `WorkerConfig` derives `Debug` to be inspectable, so it MUST NOT contain and
/// MUST NOT render the wallet's private key; the wallet itself is held by
/// [`WorkerClient`](crate::WorkerClient) and rendered through the redacted
/// wrapper in `executor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    /// The address the wallet signs as — captured for discovery/earnings so
    /// hot paths do not re-derive it.
    pub address: Address,
    /// Deposit the worker locks on its next claim. `0` is legal (§15.5: a
    /// claim with no deposit simply forfeits insurance on expiry) and is the
    /// SDK's own default; positive deposits are the operator's risk decision.
    pub worker_deposit_sat: u64,
    pub filter: Filter,
}

impl WorkerConfig {
    /// Derive the config from a wallet: the address is bound to the wallet's
    /// hybrid address, so a configuration that disagrees with its own wallet
    /// cannot exist.
    pub fn from_wallet(wallet: &Wallet) -> Self {
        WorkerConfig {
            address: wallet.address().expect("a valid wallet has an address"),
            worker_deposit_sat: 0,
            filter: Filter::default(),
        }
    }

    pub fn with_deposit(mut self, sat: u64) -> Self {
        self.worker_deposit_sat = sat;
        self
    }

    pub fn with_filter(mut self, filter: Filter) -> Self {
        self.filter = filter;
        self
    }
}
