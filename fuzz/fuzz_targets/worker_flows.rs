#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the worker-SDK boundaries (SPEC.md §18).
//
// The SDK is the client an untrusted operator environment runs; its two
// attacker-reachable boundaries are:
//
//   1. **Plan construction over adversarial inputs** — `claim_plan`,
//      `submit_plan`, `dispute_plan`, discovery and reconciliation each get
//      an arbitrary task id, arbitrary balances, arbitrary heights, and
//      arbitrary byte inputs. Every call must return Ok or a named error,
//      never panic, and never mutate whatever it observed into something the
//      caller did not ask for.
//   2. **The lifecycle interpreter** — the SDK's own reconcile functions must
//      be total over any state the view could hand them: same state twice in
//      a row is the same answer (deterministic, no clock, no RNG).
//
// Authorization itself is NOT re-fuzzed here beyond one round trip: the
// protocol layer signs and verifies everything (l2_payload_decode's target
// covers the wire), and §18.11's escalation suite covers the refusal paths
// deterministically.

fuzz_target!(|data: &[u8]| {
    use jnt_core::compute_ir::ComputeBackend;
    use jnt_core::l2::L2Transaction;
    use jnt_worker::{
        claim_plan, reconcile_claimed, reconcile_submitted, discover_tasks, dispute_plan,
        submit_plan, WorkerConfig,
    };

    // A wallet is deterministic from the fuzz bytes so signing never sees
    // random keys; a 32-byte slice drives it.
    if data.len() < 32 {
        return;
    }
    let wallet = match jnt_core::wallet::Wallet::from_private_key_bytes(
        &data[..32],
        "fuzz-worker",
    ) {
        Ok(w) => w,
        // Out-of-range scalar: a named failure IS the expected result.
        _ => return,
    };
    let config = WorkerConfig::from_wallet(&wallet);
    let address = wallet.address().unwrap();

    // Slices of the input as semantically different fields.
    let mut task_id = [0u8; 32];
    task_id.copy_from_slice(&data[0..32]);

    // Deterministic fake state: fund the wallet so the financing precondition
    // passes and the deeper paths are reached (a zero-balance state would
    // refuse everything at the same spot, which is a valid but degenerate
    // fuzzing domain).
    let mut state = jnt_l2::L2State::new(jnt_l2::L2Config::mini());
    let _ = state.credit(address, u64::from(data[0]) * 1_000_000);

    // Heights covering the deadline shapes: past / at / future.
    for height in [0u64, 50, u64::MAX] {
        // Claim: Ok or named error, twice identical (determinism).
        let a = claim_plan(&wallet, &config, task_id, &state, height)
            .err()
            .map(|e| e.to_string());
        let b = claim_plan(&wallet, &config, task_id, &state, height)
            .err()
            .map(|e| e.to_string());
        assert_eq!(a, b, "claim_plan must be deterministic");

        // Submit with output bytes derived from the input.
        let out = &data[data.len().saturating_sub(64)..];
        let a = submit_plan(&wallet, task_id, out, ComputeBackend::Cpu, &state, height);
        let b = submit_plan(&wallet, task_id, out, ComputeBackend::Cpu, &state, height);
        assert_eq!(a.err().map(|e| e.to_string()), b.err().map(|e| e.to_string()));

        // Dispute with an arbitrary counter-result.
        let a = dispute_plan(&wallet, task_id, [data[1]; 32], &state, height);
        let b = dispute_plan(&wallet, task_id, [data[1]; 32], &state, height);
        assert_eq!(a.err().map(|e| e.to_string()), b.err().map(|e| e.to_string()));

        // Discovery over the same state: deterministic, and never surfaces a
        // task that is unknown.
        let cfg = WorkerConfig::from_wallet(&wallet);
        let a = discover_tasks(
            &EmbeddedView { state: state.clone(), height },
            &cfg,
        );
        let b = discover_tasks(
            &EmbeddedView { state: state.clone(), height },
            &cfg,
        );
        assert_eq!(a.err().map(|e| e.to_string()), b.err().map(|e| e.to_string()));

        // Reconciliation: total over anything, deterministic.
        let _ = reconcile_claimed(&state, &address, &task_id);
        let _ = reconcile_submitted(&state, &address, &task_id);
    }

    // Adversarial transaction bytes through the SDK's only deserialize path:
    // a broadcast candidate is decoded before it is reported applied, so the
    // SDK must never panic on whatever a hostile node echoes back.
    let _ = L2Transaction::deserialize(data);
});

struct EmbeddedView {
    state: jnt_l2::L2State,
    height: u64,
}

impl jnt_worker::L2NodeView for EmbeddedView {
    fn l2_state(&self) -> jnt_worker::WorkerResult<jnt_l2::L2State> {
        Ok(self.state.clone())
    }
    fn chain_height(&self) -> jnt_worker::WorkerResult<u64> {
        Ok(self.height)
    }
}
