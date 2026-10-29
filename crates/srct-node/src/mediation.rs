//! Fraud arbitration in the node (Decision 21 — P3, SPEC.md §16).
//!
//! Two jobs, deliberately separated:
//!
//! 1. **Produce.** When this node is an arbitrator and a dispute is live, it
//!    derives the canonical reference itself, signs one vote and broadcasts it.
//! 2. **Collect.** When a reaching quorum of votes exists for a dispute, build
//!    the `Settle` L2 transaction and put it in the include queue, so the miner
//!    applies it through the *existing* settlement path.
//!
//! # Why the second job is only "propose"
//!
//! `VoteTally::settle_payload` re-verifies the aggregate from the votes with
//! real pairings before producing anything, and `L2State::apply_settle` verifies
//! it *again* from scratch when the transaction is applied. So a node that
//! proposes a settlement is not acting on its own tally: it is telling the chain
//! what a quorum signed, and the chain decides. A node with a wrong or forged
//! tally produces either nothing (the aggregate does not verify) or a
//! transaction every peer refuses — there is no path by which a transport bug
//! becomes a slashing.
//!
//! # What this module does not decide
//!
//! - Whether a dispute is still open. That is `L2State`'s question, and the
//!   settle path answers it by refusing a second settlement, or one for a task
//!   that settled, expired or was never disputed.
//! - Key custody. `votes_for` takes the `Committee` it is given.
//! - Signing authority. Only a key the operator placed in
//!   `<data-dir>/validators/` is used, and only through `Committee`.

use srct_core::arbitration::{ArbitrationVote, ARBITRATION_VOTE_VERSION};
use srct_core::bls_checkpoint::BlsPublicKey;
use srct_core::chain::Chain;
use srct_core::hash::Hash;
use srct_core::l2::{L2Payload, L2Transaction, SettlePayload, Verdict, VWC_HASH_EXPIRED};
use srct_core::signing::Committee;
use srct_l2::{DisputeEngine, L2State};

/// Build the votes this node should sign and broadcast.
///
/// Deterministic by construction: `DisputeEngine::resolve` derives the reference
/// from the task's own committed fields, so two honest arbitrators over the same
/// chain sign the same bytes. A dispute whose arbitration is `Inconclusive`
/// produces no vote — "no match" is not guilt (§16), and a vote for it would be
/// unbacked.
///
/// `height` is the chain height the votes are bound to. Passing it in rather
/// than reading it keeps this pure and makes the binding explicit at the call
/// site, which is where the node knows what it just settled.
pub fn votes_for(
    chain: &Chain,
    l2: &L2State,
    committee: &Committee,
    height: u64,
) -> Vec<ArbitrationVote> {
    if committee.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for task in l2.disputed_tasks() {
        let Ok(verdict) = DisputeEngine::resolve(task) else {
            // Evidence that fails validation yields no verdict, so no vote.
            continue;
        };
        let Some(decision) = verdict.verdict() else {
            continue;
        };
        // One vote per held key: each is a distinct committee member, and a
        // quorum is defined by *distinct* signers — so a node holding four keys
        // is four members of the committee, not one with four signatures.
        for key in committee.keys() {
            if let Some(vote) = sign_vote(
                key,
                chain,
                task.task_id,
                decision,
                verdict.re_execution_result,
                height,
            ) {
                out.push(vote);
            }
        }
    }
    out
}

/// Sign one vote with this node's own key.
///
/// `None` when the committee holds no keys, or the verdict is not one an
/// arbitrator may cast. A node with several keys signs with all of them, since
/// each is a distinct committee member and a quorum is defined by distinct
/// signers.
/// Sign one vote for **one** key.
///
/// `key` is the signer, not a set: an arbitration vote is one arbitrator's
/// statement, so a node holding several committee keys produces one vote per key
/// (see [`votes_for`]) rather than one vote naming an arbitrary member.
pub fn sign_vote(
    key: &srct_core::signing::ValidatorKey,
    chain: &Chain,
    task_id: Hash,
    verdict: Verdict,
    vwc_hash: Hash,
    height: u64,
) -> Option<ArbitrationVote> {
    if verdict == Verdict::Expired || vwc_hash == VWC_HASH_EXPIRED {
        return None;
    }
    let base = ArbitrationVote {
        version: ARBITRATION_VOTE_VERSION,
        task_id,
        verdict,
        vwc_hash,
        network_id: chain.params().network_id.clone(),
        height,
        signer: key.public_key(),
        signature: srct_core::bls_checkpoint::BlsSignature([0u8; 96]),
        pq_sig: None,
    };
    let msg = base.signing_hash();
    // A vote carries a lattice signature exactly when its signer holds a
    // registered lattice key in the bond ledger. Attaching one for a keyless
    // member would build a settle the chain must refuse ("entry for keyless
    // member"), turning every vote this node casts into a stuck settlement —
    // so the bond registry, not the key file, decides.
    let pq_sig = chain
        .bonds()
        .find_by_key(&key.public_key())
        .filter(|(_, r)| r.mldsa_pk.is_some())
        .and_then(|_| key.sign_pq(&msg).ok());
    Some(ArbitrationVote {
        signature: key.sign_hash(&msg),
        pq_sig,
        ..base
    })
}

/// A quorum-signed settlement ready for the include queue.
#[derive(Debug, Clone)]
pub struct ProposedSettlement {
    /// The dispute this settles.
    pub task_id: Hash,
    /// The L2 transaction the miner should include.
    pub tx: L2Transaction,
}

/// Collect every dispute with a reaching quorum and build its settle
/// transaction.
///
/// Deterministic: the vote book walks disputes in task-id order, so two nodes
/// holding the same votes propose the same settlements in the same order —
/// which is what makes a quorum outcome reproducible rather than
/// arrival-dependent.
///
/// `None` for anything that does not clear quorum, because `VoteTally::
/// settle_payload` re-verifies the aggregate from the votes and declines rather
/// than producing an unverifiable payload.
pub fn propose(
    votes: &srct_core::arbitration::VoteBook,
    committee_keys: &[BlsPublicKey],
) -> Vec<ProposedSettlement> {
    votes
        .ready(committee_keys)
        .into_iter()
        .map(|(task_id, payload)| ProposedSettlement {
            task_id,
            tx: L2Transaction::new(L2Payload::Settle(payload)),
        })
        .collect()
}

/// Whether a proposed settlement is still worth including.
///
/// A dispute that already settled, expired, or is no longer disputed produces a
/// transaction the chain will refuse, and including a refused L2 transaction is
/// harmless but pointless — it shows up in `L2State::skipped`. Filtering here
/// keeps the queue meaningful without weakening anything: the chain remains the
/// authority.
pub fn still_live(l2: &L2State, settlement: &ProposedSettlement) -> bool {
    let task_id: Hash = settlement.task_id;
    let Some(task) = l2.task(&task_id) else {
        return false;
    };
    matches!(task.state, srct_l2::ContractState::Disputed(_))
}

/// Convenience for the node: the settle payloads it should include, filtered to
/// disputes that are still open.
pub fn live_proposals(
    votes: &srct_core::arbitration::VoteBook,
    committee_keys: &[BlsPublicKey],
    l2: &L2State,
) -> Vec<ProposedSettlement> {
    propose(votes, committee_keys)
        .into_iter()
        .filter(|p| still_live(l2, p))
        .collect()
}

/// Keep the settle-payload type in scope for readers tracing the seam.
#[allow(dead_code)]
type Settlement = SettlePayload;
