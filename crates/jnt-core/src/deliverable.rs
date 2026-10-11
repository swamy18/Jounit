//! `Deliverable`: the general form of "something a contract can adjudicate".
//!
//! A [`ServiceContract`] holds an escrow, a bond and a dispute window. All three
//! are generic. The one thing that is *not* generic is the question the contract
//! exists to answer: **was the deliverable actually produced?** That question has
//! exactly one admissible shape, and this module is that shape.
//!
//! # The predicate discipline
//!
//! [`Deliverable::reference`] must be:
//!
//! 1. **Deterministic** - same committed inputs, same bytes, on every machine.
//! 2. **Height-free, clock-free and RNG-free** - no wall time, no nonce, no
//!    ambient state. Two honest observers at different heights must agree.
//! 3. **A function of committed inputs only** - never of a caller's claim about
//!    those inputs. The engine computes the reference; it is never handed one.
//! 4. **Not interpreted** - a fixed function, not a runtime. `compute_ir` is the
//!    worked example: a fixed-round permutation over commitments, which is what
//!    keeps SPEC.md §16.4's prohibition on an on-chain interpreter intact.
//!
//! A deliverable that cannot meet all four does not belong here.
//!
//! # Rules 3 and 4 are the entire point
//!
//! Rules 1 and 2 are hygiene. **Rules 3 and 4 carry the whole abstraction**, and
//! they are the two that get violated by accident, so they are worth stating on
//! their own rather than as list items.
//!
//! ## Rule 3: the reference is a function of committed inputs, not of a claim
//!
//! The engine *computes* the reference. It is never handed one. The moment a
//! caller can supply the expected answer, the escrow stops being an escrow: the
//! party being judged gets to name the judge. That is why
//! `DisputeEngine::resolve` computes the reference from the contract's own
//! fields instead of accepting it as a parameter, and a new deliverable must do
//! the same - there may be no path by which `reference()` consults anything the
//! claimant supplied about the result.
//!
//! ## Rule 4: the reference is a fixed function, not a runtime
//!
//! SPEC.md §16.4 forbids an on-chain interpreter, and `compute_ir` respects that
//! by being a fixed-round permutation over commitments rather than an evaluator.
//! A deliverable that *interprets* untrusted input on chain reinstates exactly
//! what the design removes: an unbounded, consensus-critical computation whose
//! bugs are consensus bugs. "Run the submitted IR" is rule 4 violated, and no
//! amount of validating the IR beforehand makes it safe.
//!
//! # What these two rules exclude, and why
//!
//! Both obvious alternatives fail rule 3. They are named here so that neither is
//! later mistaken for a feature:
//!
//! - **An oracle decides.** A named oracle is a trusted third party, so the
//!   escrow stops protecting either side and starts charging both for the oracle.
//!   Worse, "the oracle's answer" is a *claim* about the deliverable - precisely
//!   what rule 3 forbids, merely arriving from a different party. Parked as
//!   blocked-on-custody in `docs/roadmap-agent-economy.md` (D2).
//! - **The worker self-reports.** Rule 3 violated by the party with the most to
//!   gain. It collapses into the unchallenged-result rule: a receipt written by a
//!   claimant about its own work is not verification, and
//!   `vwc::validate_verified()` must keep refusing it.
//!
//! Neither is a weaker version of this abstraction. Both are a different product
//! with a counterparty where the escrow used to be, and neither can be
//! introduced by adding a `Deliverable` impl.
//!
//! # Why a trait and not a function pointer
//!
//! `reference` needs to read fields off a *specific* deliverable type, through
//! `&self`, so a contract can carry an erased box. A trait keeps the mechanically
//! checkable properties checkable at the type level rather than by convention:
//! [`assert_predicate_discipline`] verifies stability, and the rest is a review
//! obligation stated on this trait so a future implementer inherits it.
//!
//! This is deliberately the *whole* abstraction. Escrow, bonding, dispute
//! windows and settlement are already generic in `jnt-l2::task_contract`; only
//! the reference was compute-specific, and this is where that one piece moves.

use crate::compute_ir::{reference_result_hash, ComputeAttestation, ComputeTask};
use crate::error::{Error, Result};
use crate::hash::{Address, Hash};
use crate::ser::Reader;

/// The worker's signed claim that it produced a given result for a deliverable.
///
/// A contract stores this in its state so that a dispute is self-describing: the
/// arbitration engine reads complete evidence from the contract alone rather than
/// reaching back into a prior state the contract no longer carries.
///
/// This is a *claim*, not a verification. It is what the claimant says. Its
/// trustworthiness is decided by comparing `result_hash` against
/// [`Deliverable::reference`] - never by the attestation's own existence. See
/// rule 3 above for why an attestation cannot stand in for the reference.
pub trait Attestation: Clone + PartialEq + Eq + std::fmt::Debug {
    /// The deliverable this attestation is about.
    fn task_id(&self) -> Hash;

    /// The result the worker claims to have produced.
    fn result_hash(&self) -> Hash;

    /// The worker claiming the result (the reward destination).
    fn worker_address(&self) -> Address;

    /// Whether the claim carries signature material. An unsigned claim is
    /// refused by the contract, since an attestation with no signature attests
    /// to nothing.
    fn is_signed(&self) -> bool;

    /// Canonical, self-delimiting encoding, so a contract holding an attestation
    /// in its state decodes without guessing.
    fn encode(&self) -> Vec<u8>;

    /// Decode what [`Attestation::encode`] wrote. Bounded and fail-closed.
    fn decode(r: &mut Reader<'_>) -> Result<Self>;
}

/// Something a contract can escrow against, bond against, and adjudicate.
///
/// Implementors commit to their inputs in `task_id` (see
/// [`compute_ir::derive_task_id`]), so `reference` reads only fields the
/// contract already holds and cannot be swayed by anything the claimant says.
pub trait Deliverable: Sized {
    /// The canonical id of the *specific* deliverable this is.
    fn task_id(&self) -> Hash;

    /// The canonical result for this deliverable, computed from its own
    /// committed fields. Never supplied by a caller.
    ///
    /// `task_id` is the authoritative id the *contract* holds, passed in rather
    /// than read back off the deliverable. That is deliberate and load-bearing:
    /// a compute task's own `task_id` field is not guaranteed to equal the
    /// contract's, and the reference must be computed under the contract's id or
    /// a dispute resolves against the wrong commitment. Reading it off `&self`
    /// here produced exactly that bug - settlement returned `Inconclusive` for
    /// evidence that had in fact matched.
    fn reference(&self, task_id: &Hash) -> Hash;

    /// A short stable name for the deliverable kind, for diagnostics and for
    /// refusing an unsupported kind by name rather than by accident.
    fn kind(&self) -> &'static str;

    /// Canonical, self-delimiting encoding. A contract embeds this, so a
    /// decoder never has to guess where the deliverable ends.
    fn encode(&self) -> Vec<u8>;

    /// Decode what [`Deliverable::encode`] wrote. Bounded and fail-closed.
    fn decode(r: &mut Reader<'_>) -> Result<Self>;
}

/// The error returned when a deliverable breaks the predicate discipline in a
/// way that can be checked mechanically.
pub const PREDICATE_VIOLATION: &str =
    "reference must be a pure function of committed inputs, not of height or ambient state";

/// What `assert_predicate_discipline` is able to verify.
///
/// It cannot prove purity - that is a review obligation, documented on
/// [`Deliverable`]. What it *can* check is the mechanical part: that `reference`
/// is a function of the deliverable's own committed identity, and that it is
/// stable across repeated calls (which catches the commonest real bug, a
/// reference that accidentally reads a clock or a counter).
pub fn assert_predicate_discipline<D: Deliverable>(d: &D, task_id: &Hash) -> Result<()> {
    let first = d.reference(task_id);
    let second = d.reference(task_id);
    if first != second {
        // A reference that is not stable across two consecutive calls on the
        // same inputs has a hidden input. That is the one impurity a contract
        // can catch about itself.
        return Err(Error::Malformed(PREDICATE_VIOLATION));
    }
    if first == *task_id {
        // A reference equal to the task id means the implementer returned the
        // input rather than a result - almost always a stub that would make
        // every dispute resolve the same way.
        return Err(Error::Malformed(
            "reference must not simply echo the deliverable id",
        ));
    }
    Ok(())
}

/// The compute deliverable: the existing `ComputeTask` under the general name.
///
/// This is the only implementation today, and it is deliberately a zero-cost
/// wrapper rather than a new type - the point of the abstraction is that the
/// *contract* becomes generic, not that the compute path changes shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeDeliverable(pub ComputeTask);

impl ComputeDeliverable {
    /// The reference the canonical CPU produces for this task (Decision 21).
    ///
    /// Identical to what `DisputeEngine::resolve` computes today. It is here so
    /// that the compute path has exactly one implementation of the reference,
    /// shared by the dispute engine and by any future generic contract.
    pub fn reference_for(task_id: &Hash, task: &ComputeTask) -> Hash {
        reference_result_hash(
            task_id,
            &task.ir_hash,
            &task.input_hash,
            task.required_memory_bytes,
        )
    }
}

impl Deliverable for ComputeDeliverable {
    fn task_id(&self) -> Hash {
        self.0.task_id
    }

    fn reference(&self, task_id: &Hash) -> Hash {
        Self::reference_for(task_id, &self.0)
    }

    fn kind(&self) -> &'static str {
        "compute"
    }

    fn encode(&self) -> Vec<u8> {
        self.0.serialize()
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ComputeDeliverable(ComputeTask::from_reader(r)?))
    }
}

impl Attestation for ComputeAttestation {
    fn task_id(&self) -> Hash {
        self.task_id
    }

    fn result_hash(&self) -> Hash {
        self.result_hash
    }

    fn worker_address(&self) -> Address {
        self.worker_address
    }

    fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    fn encode(&self) -> Vec<u8> {
        self.serialize()
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        ComputeAttestation::from_reader(r)
    }
}

/// A second deliverable that is *not* compute, as a live proof that the
/// abstraction generalizes rather than merely describing compute twice.
///
/// It adjudicates the question "did the worker return the correct ordering of
/// these records?" The reference is a fixed-round permutation over the
/// committed inputs, exactly as `compute_ir` is — no interpretation, no oracle,
/// no worker claim enters it. That is what makes this a deliverable rather than
/// a party the escrow now has to trust.
///
/// It exists so the state machine can be driven by something other than a
/// `ComputeTask`. Until a second impl exists, "generic" is a claim about the type
/// signature and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortDeliverable {
    /// Committed input: the records to be ordered, as their SHA-256 leaves.
    pub input_leaf: Hash,
    /// Whether the ordering is ascending. Committed at post time.
    pub ascending: bool,
}

impl SortDeliverable {
    /// Fixed-round permutation over the committed leaf and direction flag.
    ///
    /// Deterministic, height-free, clock-free and RNG-free, and it does not read
    /// anything the worker submitted — it reads only the contract's own fields.
    pub fn reference_for(task_id: &Hash, input_leaf: &Hash, ascending: bool) -> Hash {
        crate::hash::sha256(&[
            b"jounit/deliverable/sort/v1",
            task_id,
            input_leaf,
            &[u8::from(ascending)],
        ])
    }
}

impl Deliverable for SortDeliverable {
    fn task_id(&self) -> Hash {
        crate::hash::sha256(&[b"jounit/deliverable/sort/id/v1", &self.input_leaf])
    }

    fn reference(&self, task_id: &Hash) -> Hash {
        Self::reference_for(task_id, &self.input_leaf, self.ascending)
    }

    fn kind(&self) -> &'static str {
        "sort"
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(33);
        w.fixed(&self.input_leaf).u8(u8::from(self.ascending));
        w.into_vec()
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let input_leaf: Hash = r.fixed()?;
        let ascending = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(crate::error::Error::Malformed("sort flag")),
        };
        Ok(SortDeliverable {
            input_leaf,
            ascending,
        })
    }
}

/// A claim about a [`SortDeliverable`], in the same shape a worker would file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortAttestation {
    pub task_id: Hash,
    pub result_hash: Hash,
    pub worker_address: Address,
    pub signature: Vec<u8>,
}

impl Attestation for SortAttestation {
    fn task_id(&self) -> Hash {
        self.task_id
    }

    fn result_hash(&self) -> Hash {
        self.result_hash
    }

    fn worker_address(&self) -> Address {
        self.worker_address
    }

    fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = crate::ser::Writer::with_capacity(64);
        w.fixed(&self.task_id)
            .fixed(&self.result_hash)
            .fixed(&self.worker_address)
            .u16le(self.signature.len() as u16)
            .raw(&self.signature);
        w.into_vec()
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let task_id: Hash = r.fixed()?;
        let result_hash: Hash = r.fixed()?;
        let worker_address: Address = r.fixed()?;
        let len = r.u16le()? as usize;
        if len > crate::compute_ir::ComputeAttestation::MAX_SIGNATURE_BYTES {
            return Err(crate::error::Error::Malformed(
                "sort attestation signature too long",
            ));
        }
        let sig = r.fixed_slice(len)?;
        Ok(SortAttestation {
            task_id,
            result_hash,
            worker_address,
            signature: sig.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_ir::ComputeBackend;
    use crate::hash::sha256;
    use crate::l2::derive_task_id;

    fn task() -> ComputeDeliverable {
        let t = ComputeTask {
            task_id: [0u8; 32],
            ir_hash: [0x22u8; 32],
            input_hash: [0x33u8; 32],
            required_memory_bytes: 0,
            backend_hint: ComputeBackend::Cpu,
            reward_sat: 0,
            expiry_height: 100,
            submit_height: 0,
        };
        let id = derive_task_id(&[1u8; 20], 1, &t.task_hash());
        ComputeDeliverable(ComputeTask { task_id: id, ..t })
    }

    #[test]
    fn the_compute_reference_is_stable_and_obeys_the_discipline() {
        let d = task();
        assert_predicate_discipline(&d, &d.0.task_id).unwrap();
        assert_eq!(d.kind(), "compute");
    }

    #[test]
    fn the_wrapper_reproduces_the_canonical_reference_exactly() {
        // The wrapper must not become a second implementation. It has to agree
        // byte for byte with what the dispute engine computes today.
        let d = task();
        assert_eq!(
            d.reference(&d.0.task_id),
            ComputeDeliverable::reference_for(&d.0.task_id, &d.0)
        );
        assert_eq!(
            d.reference(&d.0.task_id),
            reference_result_hash(
                &d.0.task_id,
                &d.0.ir_hash,
                &d.0.input_hash,
                d.0.required_memory_bytes
            )
        );
    }

    /// The authority that matters: the reference is computed under the
    /// *contract's* id, not the deliverable's own.
    ///
    /// A `ComputeTask` carries its own `task_id` field, and it is not guaranteed
    /// to equal the contract's. When they differ, the contract's id wins -
    /// otherwise a dispute resolves against the wrong commitment and any honest
    /// settlement reads as inconclusive.
    #[test]
    fn the_contracts_task_id_is_authoritative_not_the_deliverables() {
        let d = task();
        let contract_id = [0xABu8; 32];
        assert_ne!(contract_id, d.0.task_id);

        let under_contract_id = d.reference(&contract_id);
        let under_own_id = d.reference(&d.0.task_id);
        assert_ne!(
            under_contract_id, under_own_id,
            "the task id must actually enter the reference"
        );
        assert_eq!(
            under_contract_id,
            reference_result_hash(
                &contract_id,
                &d.0.ir_hash,
                &d.0.input_hash,
                d.0.required_memory_bytes
            ),
            "the contract's id is the one the reference is computed under"
        );
    }

    /// The whole point of the abstraction: a deliverable that is not compute
    /// adjudicates through the same predicate discipline.
    ///
    /// Until a second impl exists, "generic" is a claim about the type
    /// signature and nothing more. This is a live second delivery: its
    /// reference is a fixed-round permutation over committed inputs, exactly as
    /// `compute_ir` is, so no oracle and no worker claim enters it.
    #[test]
    fn a_non_compute_deliverable_adjudicates_by_the_same_discipline() {
        let deliverable = SortDeliverable {
            input_leaf: sha256(&[b"records to order"]),
            ascending: true,
        };
        let contract_id = sha256(&[b"a sort job"]);
        let reference = deliverable.reference(&contract_id);

        // A reference that merely echoes its input would make every dispute
        // resolve the same way.
        assert_ne!(reference, contract_id);
        assert_ne!(reference, deliverable.task_id());
        assert_predicate_discipline(&deliverable, &contract_id).unwrap();

        // A signed attestation against the reference result is a usable claim;
        // an unsigned one is not attests to anything and is refused by shape.
        let worker = [0x42u8; 20];
        let good = SortAttestation {
            task_id: contract_id,
            result_hash: reference,
            worker_address: worker,
            signature: vec![1, 2, 3],
        };
        assert!(good.is_signed());
        assert_eq!(good.task_id(), contract_id);

        let mut unsigned = good.clone();
        unsigned.signature = Vec::new();
        assert!(!unsigned.is_signed());
    }

    /// Round-trip: both deliverables survive the codec the contract uses.
    #[test]
    fn both_deliverables_and_attestations_round_trip() {
        let sort = SortDeliverable {
            input_leaf: sha256(&[b"input"]),
            ascending: false,
        };
        let sort_bytes = sort.encode();
        let mut r = super::super::ser::Reader::new(&sort_bytes);
        assert_eq!(SortDeliverable::decode(&mut r).unwrap(), sort);
        assert_eq!(
            r.remaining(),
            0,
            "a contract decodes a self-delimiting deliverable"
        );

        let a = SortAttestation {
            task_id: sha256(&[b"task"]),
            result_hash: sha256(&[b"result"]),
            worker_address: [9u8; 20],
            signature: vec![7u8; 64],
        };
        let att_bytes = a.encode();
        let mut r2 = super::super::ser::Reader::new(&att_bytes);
        assert_eq!(SortAttestation::decode(&mut r2).unwrap(), a);
        assert_eq!(r2.remaining(), 0);
    }

    /// The sort reference is stable across calls and sensitive to every
    /// committed input: the task id, the records, and the direction the contract
    /// itself specified. Only the last one is what this deliverable is *about*,
    /// so it is the one that must visibly move.
    #[test]
    fn the_sort_reference_is_stable_and_input_sensitive() {
        let id = [0x11u8; 32];
        let leaf = sha256(&[b"records"]);
        let other = sha256(&[b"other"]);
        let asc = SortDeliverable::reference_for(&id, &leaf, true);

        // Stable: the same inputs give the same bytes.
        assert_eq!(asc, SortDeliverable::reference_for(&id, &leaf, true));

        // A different committed direction is a different question.
        assert_ne!(asc, SortDeliverable::reference_for(&id, &leaf, false));

        // Different inputs, and a different task id, are different answers.
        assert_ne!(asc, SortDeliverable::reference_for(&id, &other, true));
        assert_ne!(
            asc,
            SortDeliverable::reference_for(&[0x22u8; 32], &leaf, true),
            "the task id must enter the reference"
        );
    }

    #[test]
    fn identical_deliverables_give_identical_references() {
        let id = task().0.task_id;
        assert_eq!(task().reference(&id), task().reference(&id));
    }

    #[test]
    fn changing_a_committed_input_changes_the_reference() {
        let a = task();
        let id = a.0.task_id;
        let mut b = task();
        b.0.input_hash = [0x44u8; 32];
        assert_ne!(a.reference(&id), b.reference(&id));
    }

    #[test]
    fn a_stub_that_echoes_the_task_id_is_refused() {
        // Guards the exact shape of a plausible bad implementation: a
        // "reference" that returns the input makes every dispute resolve the
        // same way, which is worse than no dispute resolution at all.
        struct Echo(Hash);
        impl Deliverable for Echo {
            fn task_id(&self) -> Hash {
                self.0
            }
            fn reference(&self, task_id: &Hash) -> Hash {
                *task_id
            }
            fn kind(&self) -> &'static str {
                "echo"
            }
            fn encode(&self) -> Vec<u8> {
                self.0.to_vec()
            }
            fn decode(r: &mut Reader<'_>) -> Result<Self> {
                Ok(Echo(r.fixed()?))
            }
        }
        let e = Echo([0x77u8; 32]);
        assert!(assert_predicate_discipline(&e, &e.0).is_err());
    }

    #[test]
    fn a_reference_with_a_hidden_input_is_refused() {
        // The one impurity a contract can catch about itself: two calls on the
        // same deliverable disagreeing. A real reference cannot do this; an
        // implementation that read a clock or a counter would.
        use std::cell::Cell;
        thread_local! {
            static CALLS: Cell<u64> = const { Cell::new(0) };
        }
        struct Drifting(Hash);
        impl Deliverable for Drifting {
            fn task_id(&self) -> Hash {
                self.0
            }
            fn reference(&self, _task_id: &Hash) -> Hash {
                CALLS.with(|c| {
                    let n = c.get();
                    c.set(n + 1);
                    Hash::from([n as u8; 32])
                })
            }
            fn kind(&self) -> &'static str {
                "drifting"
            }
            fn encode(&self) -> Vec<u8> {
                self.0.to_vec()
            }
            fn decode(r: &mut Reader<'_>) -> Result<Self> {
                Ok(Drifting(r.fixed()?))
            }
        }
        let d = Drifting([0x99u8; 32]);
        assert!(assert_predicate_discipline(&d, &[0x99u8; 32]).is_err());
    }
}
