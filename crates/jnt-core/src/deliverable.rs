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
//! A deliverable that cannot meet all four does not belong here. "Ask an oracle"
//! and "ask the worker" both fail (2) and (3), and admitting either would turn
//! the escrow from a trust primitive back into a counterparty relationship.
//!
//! # Why a trait and not a function pointer
//!
//! `reference` needs to read fields off a *specific* deliverable type, and it
//! needs to do so through `&self` so a contract can carry an erased box. A trait
//! keeps the four properties checkable at the type level rather than by
//! convention: [`Deliverable::assert_predicate_discipline`] verifies the parts
//! that are mechanically verifiable, and the rest is a review obligation stated
//! here so a future implementer inherits it.
//!
//! This is deliberately the *whole* abstraction. Escrow, bonding, dispute
//! windows and settlement are already generic in `jnt-l2::task_contract`; only
//! the reference was compute-specific, and this is where that one piece moves.

use crate::compute_ir::{reference_result_hash, ComputeTask};
use crate::error::{Error, Result};
use crate::hash::Hash;

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
    fn reference(&self) -> Hash;

    /// A short stable name for the deliverable kind, for diagnostics and for
    /// refusing an unsupported kind by name rather than by accident.
    fn kind(&self) -> &'static str;
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
pub fn assert_predicate_discipline<D: Deliverable>(d: &D) -> Result<()> {
    let first = d.reference();
    let second = d.reference();
    if first != second {
        // A reference that is not stable across two consecutive calls on the
        // same inputs has a hidden input. That is the one impurity a contract
        // can catch about itself.
        return Err(Error::Malformed(PREDICATE_VIOLATION));
    }
    if first == d.task_id() {
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

    fn reference(&self) -> Hash {
        Self::reference_for(&self.0.task_id, &self.0)
    }

    fn kind(&self) -> &'static str {
        "compute"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_ir::ComputeBackend;
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
        assert_predicate_discipline(&d).unwrap();
        assert_eq!(d.kind(), "compute");
    }

    #[test]
    fn the_wrapper_reproduces_the_canonical_reference_exactly() {
        // The wrapper must not become a second implementation. It has to agree
        // byte for byte with what the dispute engine computes today.
        let d = task();
        assert_eq!(
            d.reference(),
            ComputeDeliverable::reference_for(&d.0.task_id, &d.0)
        );
        assert_eq!(
            d.reference(),
            reference_result_hash(
                &d.0.task_id,
                &d.0.ir_hash,
                &d.0.input_hash,
                d.0.required_memory_bytes
            )
        );
    }

    #[test]
    fn identical_deliverables_give_identical_references() {
        assert_eq!(task().reference(), task().reference());
    }

    #[test]
    fn changing_a_committed_input_changes_the_reference() {
        let a = task();
        let mut b = task();
        b.0.input_hash = [0x44u8; 32];
        assert_ne!(a.reference(), b.reference());
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
            fn reference(&self) -> Hash {
                self.0
            }
            fn kind(&self) -> &'static str {
                "echo"
            }
        }
        let e = Echo([0x77u8; 32]);
        assert!(assert_predicate_discipline(&e).is_err());
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
            fn reference(&self) -> Hash {
                CALLS.with(|c| {
                    let n = c.get();
                    c.set(n + 1);
                    Hash::from([n as u8; 32])
                })
            }
            fn kind(&self) -> &'static str {
                "drifting"
            }
        }
        let d = Drifting([0x99u8; 32]);
        assert!(assert_predicate_discipline(&d).is_err());
    }
}
