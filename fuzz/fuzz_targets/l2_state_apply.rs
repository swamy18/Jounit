#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant fuzzer over L2 state transitions (Phase 3).
//
// This is the strongest of the four new targets: rather than checking that a
// decoder agrees with itself, it drives real, *validly signed* transactions
// through `L2State` and asserts the one property that must never break —
//
//     accounts + locked + burned + PSCB + vault_remaining == total credited
//
// after every single step. A bug that drops an escrow refund, double-counts a
// fee, mints a bounty out of nothing, or slashes a deposit twice shows up here
// as a conservation failure rather than as subtle accounting drift. This check
// is exactly what caught the missing submitter refund in Phase 2.
//
// Inputs are structure-aware: three deterministic wallets come from the first
// 96 bytes, and the rest is a program of operations (post / claim / submit /
// dispute / settle-by-arbitration / advance) whose amounts are bounded so the
// arithmetic stays in range.
fuzz_target!(|data: &[u8]| {
    use jnt_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
    use jnt_core::compute_ir::{ComputeAttestation, ComputeBackend, ComputeTask};
    use jnt_core::hash::Hash;
    use jnt_core::l2::{
        ClaimTaskPayload, DisputePayload, L2Payload, L2Transaction, PostTaskPayload,
        SubmitResultPayload,
    };
    use jnt_core::wallet::Wallet;
    use jnt_l2::{ContractState, DisputeEngine, L2Config, L2State};

    if data.len() < 100 {
        return;
    }
    let mk = |s: &[u8]| Wallet::from_private_key_bytes(s, "l2-fuzz");
    let (Ok(submitter), Ok(worker), Ok(challenger)) =
        (mk(&data[0..32]), mk(&data[32..64]), mk(&data[64..96]))
    else {
        return;
    };
    let sa = submitter.address().unwrap_or([0u8; 20]);
    let wa = worker.address().unwrap_or([1u8; 20]);
    let ca = challenger.address().unwrap_or([2u8; 20]);

    const FUND: u64 = 1_000_000_000;
    let credited = FUND * 3;

    let mut state = L2State::new(L2Config::mini());
    for a in [sa, wa, ca] {
        state.credit(a, FUND).unwrap();
    }
    let validators = ValidatorSet::new((1..=4u8).map(|i| BlsPublicKey([i; 48])).collect());
    let verifier = MockBls;

    let attest = |task_id: Hash, result: Hash, who: [u8; 20], salt: u8| ComputeAttestation {
        task_id,
        result_hash: result,
        backend: ComputeBackend::Cpu,
        worker_address: who,
        attest_height: 0,
        signature: vec![salt],
    };

    let mut task: Option<Hash> = None;
    let mut height = 1u64;
    let mut i = 96usize;
    while i + 4 <= data.len() {
        let op = data[i] % 6;
        let amount = (data[i + 1] as u64) * 40_000 + 40_000; // 40 000 ..= 10 240 000
        let salt = data[i + 2] | 1;
        let result: Hash = [data[i + 3]; 32];

        match op {
            // PostTask
            0 => {
                let deadline = height + 60;
                let compute_task = ComputeTask {
                    task_id: [0x11u8; 32],
                    ir_hash: [result[0]; 32],
                    input_hash: [salt; 32],
                    required_memory_bytes: 0,
                    backend_hint: ComputeBackend::Cpu,
                    reward_sat: 0,
                    expiry_height: deadline,
                    submit_height: height,
                };
                if let Ok(post) =
                    PostTaskPayload::build(&submitter, height, amount, deadline, compute_task)
                {
                    let id = post.task_id;
                    if state
                        .apply(
                            &L2Transaction::new(L2Payload::Post(post)),
                            height,
                            &validators,
                            &verifier,
                        )
                        .is_ok()
                    {
                        task = Some(id);
                    }
                }
            }
            // ClaimTask
            1 => {
                if let Some(id) = task {
                    if let Ok(c) = ClaimTaskPayload::build(&worker, id, ComputeBackend::Cpu, amount)
                    {
                        let _ = state.apply(
                            &L2Transaction::new(L2Payload::Claim(c)),
                            height,
                            &validators,
                            &verifier,
                        );
                    }
                }
            }
            // SubmitResult
            2 => {
                if let Some(id) = task {
                    let a = attest(id, result, wa, salt);
                    if let Ok(s) = SubmitResultPayload::build(&worker, id, a) {
                        let _ = state.apply(
                            &L2Transaction::new(L2Payload::Submit(s)),
                            height,
                            &validators,
                            &verifier,
                        );
                    }
                }
            }
            // Dispute
            3 => {
                if let Some(id) = task {
                    let a = attest(id, result, ca, salt);
                    if let Ok(d) = DisputePayload::build(&challenger, id, result, a, amount) {
                        let _ = state.apply(
                            &L2Transaction::new(L2Payload::Dispute(d)),
                            height,
                            &validators,
                            &verifier,
                        );
                    }
                }
            }
            // Settle along the arbitrated path: ask the engine what the reference
            // result implies, then settle with the verdict it returns.
            4 => {
                if let Some(id) = task {
                    let disputed = match state.task(&id) {
                        Some(t) => match &t.state {
                            ContractState::Disputed(c) => {
                                Some((c.against_result, c.counter_result))
                            }
                            _ => None,
                        },
                        None => None,
                    };
                    if let Some((against, counter)) = disputed {
                        let reference = match data[i + 3] % 3 {
                            0 => [0xCCu8; 32], // matches neither -> inconclusive
                            1 => counter,      // challenger correct -> Fraudulent
                            _ => against,      // worker correct -> Correct
                        };
                        if let Ok(v) =
                            DisputeEngine::resolve(state.task(&id).expect("exists"), reference)
                        {
                            if let Ok(payload) =
                                v.settle_payload([0xAAu8; 96], vec![0b0000_0111], 3)
                            {
                                let _ = state.apply(
                                    &L2Transaction::new(L2Payload::Settle(payload)),
                                    height,
                                    &validators,
                                    &verifier,
                                );
                            }
                        }
                    }
                }
            }
            // Advance-only step: the clock moves and implicit transitions fire.
            _ => {}
        }

        let _ = state.advance_block(height);
        height += 1;
        i += 4;

        assert_eq!(
            state.conservation_total(),
            credited,
            "L2 value conservation broke after op {op}"
        );
    }
});
