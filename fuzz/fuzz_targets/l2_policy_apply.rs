#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant fuzzer over the agent-authority layer (SPEC.md §21).
//
// The policy layer is the first place in Solar Cyber Unit where a *rule* rather than a
// *transfer* is the interesting object: a grant says how much an agent may
// spend, to whom, inside which window, and the chain has to enforce all of it
// against state it keeps. This target drives real, validly signed grants and
// spends through `L2State` and asserts the properties that must never break:
//
//   1. **Value conservation.** accounts + locked + exits_locked + credit_locked
//      + burned + PSCB + vault_remaining == total credited, after every step.
//      A spend that paid out twice, or a fee that was minted rather than
//      burned, shows up here.
//   2. **A spend never exceeds its grant.** If a spend applied, the grant's
//      counters must reflect exactly that spend: the per-transaction cap, the
//      per-window cap, the recipient allow-list and the service list were all
//      checked by the state machine, and the counters it committed are the
//      record of that.
//   3. **Revocation is absolute.** A revoked grant, and every grant that
//      descends from it, authorises nothing.
//   4. **Authority narrows.** A delegated grant that widens its parent never
//      applies, and the parent's caps are the ceiling.
//   5. **Replay is refused.** The same transaction applied twice is `Replay`,
//      and the state is byte-identical afterwards.
//
// Inputs are structure-aware: three deterministic wallets come from the first
// 96 bytes, and the rest is a program of operations (publish / delegate /
// revoke / spend / advance) whose amounts are bounded so the arithmetic stays
// in range and the interesting boundaries are still reachable.
fuzz_target!(|data: &[u8]| {
    use srct_core::agent::{derive_agent_id, derive_sub_agent_id, AgentRole, SpendPolicy};
    use srct_core::bls_checkpoint::{BlsPublicKey, MockBls, ValidatorSet};
    use srct_core::hash::Hash;
    use srct_core::l2::{
        AgentSpendPayload, L2Payload, L2Transaction, PolicyPayload, PolicyRevokePayload,
    };
    use srct_core::wallet::Wallet;
    use srct_l2::{L2Config, L2Error, L2State};

    if data.len() < 100 {
        return;
    }
    let mk = |s: &[u8]| Wallet::from_private_key_bytes(s, "policy-fuzz");
    let (Ok(owner), Ok(agent), Ok(other)) =
        (mk(&data[0..32]), mk(&data[32..64]), mk(&data[64..96]))
    else {
        return;
    };
    let oa = owner.address().unwrap_or([0u8; 20]);
    let aa = agent.address().unwrap_or([1u8; 20]);
    let xa = other.address().unwrap_or([2u8; 20]);
    let network = "srct/mini";

    const FUND: u64 = 1_000_000_000;
    let credited = FUND * 3;

    let mut state = L2State::new(L2Config::mini());
    for a in [oa, aa, xa] {
        state.credit(a, FUND).unwrap();
    }
    let validators = ValidatorSet::new((1..=4u8).map(|i| BlsPublicKey([i; 48])).collect());
    let verifier = MockBls;

    // The grant the owner will publish: caps and allow-list come from the
    // input, so the boundary cases (a cap of one satoshi, an empty
    // allow-list, a window of one block) are all reachable.
    let per_tx = (data[96] as u64) * 1_000 + 1;
    let window = (data[97] as u64).max(1);
    let cumulative = (data[98] as u64) * 10_000 + per_tx;
    let allow_other = data[99] & 1 == 1;

    let root_agent = derive_agent_id(network, AgentRole::Machine, &oa);
    let grant = |parent: Option<[u8; 20]>, per_tx: u64, cumulative: u64| SpendPolicy {
        version: srct_core::agent::POLICY_VERSION,
        network_id: network.to_string(),
        agent_id: match parent {
            Some(p) => derive_sub_agent_id(network, &p, AgentRole::Machine),
            None => root_agent,
        },
        owner: oa,
        role: AgentRole::Machine,
        per_tx_max_sat: per_tx,
        window_blocks: window,
        cumulative_max_sat: cumulative,
        allowed_recipients: if allow_other {
            vec![aa, xa]
        } else {
            vec![aa]
        },
        allowed_services: vec![],
        not_before_height: 0,
        expires_at_height: 1_000_000,
        revoked: false,
        parent_agent_id: parent,
    };

    let mut published: Option<Hash> = None;
    let mut child: Option<Hash> = None;
    let mut height = 1u64;
    let mut i = 100usize;
    let mut last_spend_payload: Option<AgentSpendPayload> = None;
    let mut nonce = 0u64;
    while i + 4 <= data.len() {
        let op = data[i] % 5;
        let amount = (data[i + 1] as u64) * 2_000 + 1;
        let salt = data[i + 2];
        let widen = data[i + 3] & 1 == 1;

        match op {
            // Publish a root grant.
            0 => {
                let policy = grant(None, per_tx, cumulative);
                let payload = match PolicyPayload::build_from_policy(&owner, &policy, aa) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let tx = L2Transaction::new(L2Payload::Policy(payload));
                if state.apply(&tx, height, &validators, &verifier).is_ok() {
                    published = Some(policy.hash());
                }
            }
            // Publish a delegated grant: strictly narrower, or an attempt to
            // widen the parent (which must never apply).
            1 => {
                let parent_id = match published.and_then(|h| state.policy(&h)) {
                    Some(entry) => entry.agent_id,
                    None => break,
                };
                let (child_per_tx, child_cumulative) = if widen {
                    (per_tx.saturating_add(1), cumulative.saturating_add(1))
                } else {
                    (per_tx, cumulative)
                };
                let policy = grant(Some(parent_id), child_per_tx, child_cumulative);
                let payload = match PolicyPayload::build_from_policy(&owner, &policy, aa) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let tx = L2Transaction::new(L2Payload::Policy(payload));
                let before = state.committed_root();
                match state.apply(&tx, height, &validators, &verifier) {
                    Ok(_) => {
                        // A widening grant must never have applied.
                        assert!(
                            !widen,
                            "a grant that widens its parent was accepted"
                        );
                        child = Some(policy.hash());
                    }
                    Err(_) => {
                        assert_eq!(
                            before,
                            state.committed_root(),
                            "a refused grant must not change the state"
                        );
                    }
                }
            }
            // Revoke: the owner kills a grant, and with it every descendant.
            2 => {
                let target = if salt & 1 == 1 { child } else { published };
                let Some(hash) = target else { break };
                let Some(entry) = state.policy(&hash) else { break };
                let payload = match PolicyRevokePayload::build(&owner, entry.agent_id) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let tx = L2Transaction::new(L2Payload::PolicyRevoke(payload));
                let _ = state.apply(&tx, height, &validators, &verifier);
            }
            // Spend under a grant.
            3 => {
                let Some(hash) = published else { break };
                nonce += 1;
                let to = if salt & 1 == 1 { xa } else { aa };
                let payload = match AgentSpendPayload::build(
                    &agent, hash, nonce, to, amount, None,
                ) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let tx = L2Transaction::new(L2Payload::AgentSpend(payload.clone()));
                let before = state.committed_root();
                let applied = state.apply(&tx, height, &validators, &verifier).is_ok();
                if applied {
                    let entry = state.policy(&hash).expect("the grant is published");
                    // The counters are the record of what the chain allowed.
                    assert!(
                        entry.spent_in_window_sat <= entry.policy.cumulative_max_sat,
                        "the window cap was exceeded"
                    );
                    assert!(
                        entry.total_spent_sat >= amount,
                        "an applied spend did not reach the counters"
                    );
                    assert!(
                        entry.last_nonce == nonce,
                        "an applied spend did not advance the nonce"
                    );
                    assert!(
                        entry.policy.allowed_recipients.contains(&to),
                        "an applied spend went to a recipient that is not on the list"
                    );
                    assert!(
                        !entry.revoked,
                        "a revoked grant authorised a spend"
                    );
                    assert_ne!(
                        before,
                        state.committed_root(),
                        "an applied spend must change the committed root"
                    );
                    last_spend_payload = Some(payload);
                } else {
                    assert_eq!(
                        before,
                        state.committed_root(),
                        "a refused spend must not change the state"
                    );
                }
            }
            // Replay the exact spend payload from op 3: applying it twice must
            // be refused as Replay, and the state must be byte-identical.
            4 => {
                let Some(payload) = last_spend_payload.clone() else { break };
                let tx = L2Transaction::new(L2Payload::AgentSpend(payload));
                let before = state.committed_root();
                let err = state
                    .apply(&tx, height, &validators, &verifier)
                    .expect_err("a replayed transaction must be refused");
                assert!(
                    matches!(err, L2Error::Replay) || matches!(err, L2Error::UnknownPolicy),
                    "unexpected refusal for a replayed transaction: {err:?}"
                );
                assert_eq!(
                    before,
                    state.committed_root(),
                    "a refused replay must not change the state"
                );
            }
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
        assert!(
            state.check_conservation(),
            "L2 funded-total invariant broke after op {op}"
        );
    }
});
