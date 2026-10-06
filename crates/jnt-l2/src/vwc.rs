//! Verified Work Certificates (SPEC.md §17).
//!
//! A VWC is the protocol's receipt for verified correct work: task `T` settled
//! as `Correct` with result `R`, worker `W` paid `P` sats at height `H`. It is a
//! *derived consequence* of a settlement, never a claim an actor makes — there
//! is no issuance transaction and no issuer key, because the settlement path
//! that produced it already did all the authorizing. A worker's own attestation
//! is necessary but never sufficient (§17.4).
//!
//! Two things this module deliberately does not do:
//!
//! - **No revocation and no pending/expired states.** Settlement is terminal
//!   and one-way, so a `Correct` settlement can never be overturned later —
//!   exactly the condition that would make revocation necessary (§17.8).
//! - **No claim of physical execution.** `Quorum` verification proves a quorum
//!   signed the decision; `WindowElapsed` proves the protocol accepted the
//!   result unchallenged. Neither says a machine physically ran anything
//!   (§17.1).

use jnt_core::bls_checkpoint::{BlsSignature, BlsVerifier, ValidatorSet};
use jnt_core::hash::{sha256_dom, Address, Hash};
use jnt_core::l2::{SettlePayload, Verdict, DOM_L2_VWC, MAX_SIGNER_BITMAP_BYTES, VWC_HASH_EXPIRED};
use jnt_core::ser::{Reader, Writer};

use crate::error::{L2Error, L2Result};

/// The only certificate format version this build understands. A decoded
/// certificate claiming another version is refused, never guessed at.
pub const VWC_VERSION: u32 = 1;

const KIND_QUORUM: u8 = 1;
const KIND_WINDOW_ELAPSED: u8 = 2;

/// How the protocol verified the work this certificate certifies.
///
/// The distinction is load-bearing for a relying party (§17.5): `Quorum` is
/// offline-verifiable against the validator set, `WindowElapsed` is not — its
/// strength is the on-chain record, and a party who needs more MUST demand
/// `Quorum`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VwcVerification {
    /// An explicit `Settle` transaction: the payload's quorum aggregate, reused
    /// rather than re-signed. It signs exactly
    /// `SettlePayload { task_id, Correct, result_hash }.signing_hash()`.
    Quorum {
        bls_sig: [u8; 96],
        signer_bitmap: Vec<u8>,
        signer_count: u32,
    },
    /// An implicit settlement (auto-settle or dispute lapse, §15.7): no
    /// aggregate exists for a transition no one transacted.
    WindowElapsed,
}

impl VwcVerification {
    fn kind(&self) -> u8 {
        match self {
            VwcVerification::Quorum { .. } => KIND_QUORUM,
            VwcVerification::WindowElapsed => KIND_WINDOW_ELAPSED,
        }
    }
}

/// A certificate for one settled task. `id` is derived from every other field
/// (§17.3), so it is never serialized: a tampered certificate cannot carry a
/// matching id, and the encoding of one certificate is byte-unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWorkCertificate {
    pub id: Hash,
    pub task_id: Hash,
    pub worker: Address,
    /// The settlement's `vwc_hash` — the result the verdict named.
    pub result_hash: Hash,
    pub settled_height: u64,
    /// What the worker was actually paid (escrow minus the settle fee).
    pub payment_sat: u64,
    pub verification: VwcVerification,
}

impl VerifiedWorkCertificate {
    /// Issue a certificate from a settled outcome.
    ///
    /// The sanity rules here are the ones §17.6 lists: a certificate names a
    /// real result, a real worker and a real height. `payment_sat` MAY be zero:
    /// an escrow that exactly covered the settle fee pays the worker nothing,
    /// but the work was still verified and still deserves its certificate. Any
    /// other failure means the caller is not looking at a settlement at all.
    pub fn from_settlement(
        task_id: Hash,
        worker: Address,
        result_hash: Hash,
        settled_height: u64,
        payment_sat: u64,
        verification: VwcVerification,
    ) -> L2Result<Self> {
        if result_hash == VWC_HASH_EXPIRED {
            return Err(L2Error::VwcInvalid(
                "an expired settlement has no result to certify",
            ));
        }
        if worker == [0u8; 20] {
            return Err(L2Error::VwcInvalid("worker address is zero"));
        }
        if settled_height == 0 {
            return Err(L2Error::VwcInvalid("settled_height is zero"));
        }
        if let VwcVerification::Quorum {
            signer_bitmap,
            signer_count,
            ..
        } = &verification
        {
            if signer_bitmap.len() > MAX_SIGNER_BITMAP_BYTES {
                return Err(L2Error::VwcInvalid("signer bitmap over cap"));
            }
            let pop: usize = signer_bitmap.iter().map(|b| b.count_ones() as usize).sum();
            if pop != *signer_count as usize {
                return Err(L2Error::VwcInvalid("signer count disagrees with bitmap"));
            }
            if *signer_count == 0 {
                return Err(L2Error::VwcInvalid("quorum certificate with no signers"));
            }
        }
        let mut cert = VerifiedWorkCertificate {
            id: [0u8; 32],
            task_id,
            worker,
            result_hash,
            settled_height,
            payment_sat,
            verification,
        };
        cert.id = sha256_dom(DOM_L2_VWC, &[&cert.body()]);
        Ok(cert)
    }

    /// The canonical encoding, without the id (§17.2).
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32le(VWC_VERSION)
            .fixed(&self.task_id)
            .fixed(&self.worker)
            .fixed(&self.result_hash)
            .u64le(self.settled_height)
            .u64le(self.payment_sat)
            .u8(self.verification.kind());
        if let VwcVerification::Quorum {
            bls_sig,
            signer_bitmap,
            signer_count,
        } = &self.verification
        {
            w.raw(bls_sig)
                .u32le(signer_bitmap.len() as u32)
                .raw(signer_bitmap)
                .u32le(*signer_count);
        }
        w.into_vec()
    }

    /// The certificate id: a function of the canonical encoding alone.
    pub fn id(&self) -> Hash {
        sha256_dom(DOM_L2_VWC, &[&self.body()])
    }

    pub fn encode(&self) -> Vec<u8> {
        self.body()
    }

    /// Parse the exact bytes [`VerifiedWorkCertificate::encode`] produces.
    ///
    /// Structural only: decoding accepts well-formed bytes regardless of the
    /// sanity rules, which are validation's job (§17.6). The id is recomputed
    /// from the decoded body, so decode → encode → decode is the identity.
    pub fn decode(bytes: &[u8]) -> L2Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u32le()?;
        if version != VWC_VERSION {
            return Err(L2Error::VwcInvalid("unsupported certificate version"));
        }
        let task_id = r.fixed()?;
        let worker = r.fixed()?;
        let result_hash = r.fixed()?;
        let settled_height = r.u64le()?;
        let payment_sat = r.u64le()?;
        let verification = match r.u8()? {
            KIND_QUORUM => {
                let bls_sig: [u8; 96] = r.fixed()?;
                let n = r.u32le()? as usize;
                if n > MAX_SIGNER_BITMAP_BYTES {
                    return Err(L2Error::VwcInvalid("signer bitmap over cap"));
                }
                if n > r.remaining() {
                    return Err(L2Error::VwcInvalid("signer bitmap exceeds buffer"));
                }
                let signer_bitmap = r.fixed_slice(n)?.to_vec();
                let signer_count = r.u32le()?;
                VwcVerification::Quorum {
                    bls_sig,
                    signer_bitmap,
                    signer_count,
                }
            }
            KIND_WINDOW_ELAPSED => VwcVerification::WindowElapsed,
            _ => return Err(L2Error::VwcInvalid("unknown verification kind")),
        };
        r.expect_end()?;
        let mut cert = VerifiedWorkCertificate {
            id: [0u8; 32],
            task_id,
            worker,
            result_hash,
            settled_height,
            payment_sat,
            verification,
        };
        cert.id = sha256_dom(DOM_L2_VWC, &[&cert.body()]);
        Ok(cert)
    }

    /// Validate a certificate on its own: identity, sanity, and — for `Quorum` —
    /// the quorum aggregate over the exact decision the settlement signed.
    ///
    /// Total and deterministic; every failure is named. Structural validity is
    /// not acceptance: a certificate that is not in the issuing state's registry
    /// was never issued, which [`crate::L2State::validate_vwc`] checks.
    pub fn validate(&self, validators: &ValidatorSet, verifier: &dyn BlsVerifier) -> L2Result<()> {
        // Identity: a hand-built or copied struct whose id does not follow from
        // its fields is refused before anything else is believed.
        if self.id != self.id() {
            return Err(L2Error::VwcInvalid(
                "id does not follow from the certificate body",
            ));
        }
        // Sanity (§17.6 check 2).
        if self.result_hash == VWC_HASH_EXPIRED {
            return Err(L2Error::VwcInvalid(
                "certifies the expired-placeholder hash",
            ));
        }
        if self.worker == [0u8; 20] {
            return Err(L2Error::VwcInvalid("worker address is zero"));
        }
        if self.settled_height == 0 {
            return Err(L2Error::VwcInvalid("settled_height is zero"));
        }
        // `payment_sat` may be zero: an escrow that exactly covered the settle
        // fee paid the worker nothing, but the work was still verified.

        match &self.verification {
            VwcVerification::WindowElapsed => {
                // No further local evidence exists (§17.5); the on-chain record
                // is the check, and `L2State::validate_vwc` performs it.
            }
            VwcVerification::Quorum {
                bls_sig,
                signer_bitmap,
                signer_count,
            } => {
                // The same three checks the settle path applies, over the same
                // message the settle path signed: rebuild the *decision* (not
                // the evidence) and verify the aggregate against it.
                let signers = validators.signers_from_bitmap(signer_bitmap);
                if signers.len() != *signer_count as usize {
                    return Err(L2Error::VwcInvalid("signer count disagrees with bitmap"));
                }
                if signers.len() < validators.quorum_size() {
                    return Err(L2Error::VwcInvalid("signer count below quorum"));
                }
                let decision = SettlePayload {
                    task_id: self.task_id,
                    verdict: Verdict::Correct,
                    vwc_hash: self.result_hash,
                    bls_sig: [0u8; 96],
                    signer_bitmap: Vec::new(),
                    signer_count: 0,
                };
                let msg = decision.signing_hash();
                if !verifier.verify_aggregate(&signers, &msg, &BlsSignature(*bls_sig)) {
                    return Err(L2Error::VwcInvalid("quorum aggregate did not verify"));
                }
            }
        }
        Ok(())
    }

    /// True when this certificate is exactly the one the given settle payload
    /// decided: same task, `Correct`, same result hash. The certificate carries
    /// the payload's evidence; this is the binding check between them.
    pub fn matches_settle(&self, payload: &SettlePayload) -> bool {
        payload.task_id == self.task_id
            && payload.verdict == Verdict::Correct
            && payload.vwc_hash == self.result_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jnt_core::bls::{RealBls, SecretKey};

    const TASK: Hash = [0x11u8; 32];
    const RESULT: Hash = [0xAAu8; 32];
    const WORKER: Address = [0x07u8; 20];

    fn validators(n: usize) -> (ValidatorSet, Vec<SecretKey>) {
        // Real derived keys, not placeholder bytes: the real verifier refuses a
        // public key that is not a curve point, which is exactly the property
        // these tests rely on.
        let secrets: Vec<SecretKey> = (1..=n as u8)
            .map(|i| SecretKey::derive(&[i; 32]).unwrap())
            .collect();
        let set = ValidatorSet::new(secrets.iter().map(|sk| sk.public_key()).collect());
        (set, secrets)
    }

    /// A *real* quorum aggregate over the certificate's decision, signed by the
    /// first three validators of the set. This is the same cryptographic
    /// construction the settle path would carry, so the tests below exercise
    /// real pairing verification, not the mock's non-zero check.
    fn real_quorum() -> (ValidatorSet, VwcVerification) {
        let (set, secrets) = validators(4);
        let payload = SettlePayload {
            task_id: TASK,
            verdict: Verdict::Correct,
            vwc_hash: RESULT,
            bls_sig: [0u8; 96],
            signer_bitmap: Vec::new(),
            signer_count: 0,
        };
        let msg = payload.signing_hash();
        let indices = [0usize, 1, 2];
        let bitmap = set.bitmap_from_indices(&indices);
        let signers = set.signers_from_bitmap(&bitmap);
        // Map each sorted signer key back to the secret that owns it.
        let sigs: Vec<_> = signers
            .iter()
            .map(|pk| {
                let sk = secrets
                    .iter()
                    .find(|sk| sk.public_key().0 == pk.0)
                    .expect("every set key came from a derived secret");
                sk.sign(&msg)
            })
            .collect();
        let aggregate = RealBls::aggregate(&sigs).unwrap();
        (
            set,
            VwcVerification::Quorum {
                bls_sig: *aggregate.as_bytes(),
                signer_bitmap: bitmap,
                signer_count: 3,
            },
        )
    }

    fn quorum_cert() -> (ValidatorSet, VerifiedWorkCertificate) {
        let (set, verification) = real_quorum();
        let cert = VerifiedWorkCertificate::from_settlement(
            TASK,
            WORKER,
            RESULT,
            9,
            980_000,
            verification,
        )
        .unwrap();
        (set, cert)
    }

    #[test]
    fn a_certificate_validates_against_a_real_quorum_aggregate() {
        let (set, cert) = quorum_cert();
        cert.validate(&set, &RealBls).unwrap();
        assert_eq!(cert.id, cert.id(), "the id is stable");
    }

    #[test]
    fn the_id_is_a_function_of_the_fields_alone() {
        let (_set, cert) = quorum_cert();
        let rebuilt = VerifiedWorkCertificate::from_settlement(
            TASK,
            WORKER,
            RESULT,
            9,
            980_000,
            cert.verification.clone(),
        )
        .unwrap();
        assert_eq!(cert.id, rebuilt.id);

        // Every field change moves the id.
        let mut other = rebuilt.clone();
        other.payment_sat += 1;
        assert_ne!(other.id(), cert.id);
        let mut other = rebuilt.clone();
        other.settled_height += 1;
        assert_ne!(other.id(), cert.id);
    }

    #[test]
    fn encoding_is_an_exact_inverse_and_deterministic() {
        let (_set, cert) = quorum_cert();
        let bytes = cert.encode();
        let decoded = VerifiedWorkCertificate::decode(&bytes).unwrap();
        assert_eq!(decoded, cert);
        assert_eq!(decoded.id, cert.id);
        assert_eq!(decoded.encode(), bytes, "re-encoding is byte-identical");

        // The window-elapsed shape round-trips too.
        let plain = VerifiedWorkCertificate::from_settlement(
            TASK,
            WORKER,
            RESULT,
            5,
            1_000_000,
            VwcVerification::WindowElapsed,
        )
        .unwrap();
        let back = VerifiedWorkCertificate::decode(&plain.encode()).unwrap();
        assert_eq!(back, plain);
    }

    #[test]
    fn decoding_refuses_unknown_versions_and_kinds() {
        let (_set, cert) = quorum_cert();
        let mut bytes = cert.encode();
        bytes[0] = 2; // version
        assert!(matches!(
            VerifiedWorkCertificate::decode(&bytes),
            Err(L2Error::VwcInvalid(_))
        ));
        let mut bytes = cert.encode();
        // The kind byte sits after version(4) + task(32) + worker(20) + result(32)
        // + height(8) + payment(8) = 104.
        bytes[104] = 9;
        assert!(matches!(
            VerifiedWorkCertificate::decode(&bytes),
            Err(L2Error::VwcInvalid(_))
        ));
    }

    #[test]
    fn decoding_is_total_over_adversarial_bytes() {
        let (_set, cert) = quorum_cert();
        let good = cert.encode();
        for cut in 0..good.len() {
            let _ = VerifiedWorkCertificate::decode(&good[..cut]);
        }
        for i in 0..good.len() {
            let mut flipped = good.clone();
            flipped[i] ^= 0x80;
            let _ = VerifiedWorkCertificate::decode(&flipped);
        }
        let mut oversized = good.clone();
        oversized.extend_from_slice(&[0u8; 64]);
        assert!(VerifiedWorkCertificate::decode(&oversized).is_err());
    }

    #[test]
    fn tampering_is_caught_where_it_should_be() {
        let (set, cert) = quorum_cert();

        // A tampered *and re-id'd* certificate is structurally self-consistent,
        // so `validate` alone accepts it — but the id no longer matches the one
        // the protocol issued, which is what the registry comparison is for.
        let mut forged = cert.clone();
        forged.payment_sat += 1;
        forged.id = forged.id();
        assert_eq!(forged.validate(&set, &RealBls), Ok(()));

        // Without re-deriving the id, validation refuses immediately.
        let mut naive = cert.clone();
        naive.payment_sat += 1;
        assert!(matches!(
            naive.validate(&set, &RealBls),
            Err(L2Error::VwcInvalid(_))
        ));

        // A copied id over a different body is refused the same way.
        let mut stolen = cert.clone();
        stolen.task_id = [0x22u8; 32];
        assert!(matches!(
            stolen.validate(&set, &RealBls),
            Err(L2Error::VwcInvalid(_))
        ));
    }

    #[test]
    fn a_quorum_certificate_needs_a_real_verifying_aggregate() {
        let (set, cert) = quorum_cert();

        // Zeroed signature: refused by the real verifier.
        let mut broken = cert.clone();
        if let VwcVerification::Quorum { bls_sig, .. } = &mut broken.verification {
            *bls_sig = [0u8; 96];
        }
        broken.id = broken.id();
        assert!(matches!(
            broken.validate(&set, &RealBls),
            Err(L2Error::VwcInvalid(_))
        ));

        // A signature over a *different* decision must not verify here.
        let mut replay = cert.clone();
        replay.result_hash = [0xBBu8; 32];
        replay.id = replay.id();
        assert!(matches!(
            replay.validate(&set, &RealBls),
            Err(L2Error::VwcInvalid(_))
        ));

        // Sub-quorum bitmap: refused by the threshold check.
        let mut short = cert.clone();
        if let VwcVerification::Quorum {
            signer_bitmap,
            signer_count,
            ..
        } = &mut short.verification
        {
            *signer_bitmap = set.bitmap_from_indices(&[0, 1]);
            *signer_count = 2;
        }
        short.id = short.id();
        assert!(matches!(
            short.validate(&set, &RealBls),
            Err(L2Error::VwcInvalid(_))
        ));
    }

    #[test]
    fn the_sanity_rules_fail_closed() {
        let cases = vec![
            (
                TASK,
                WORKER,
                VWC_HASH_EXPIRED,
                9u64,
                100u64,
                VwcVerification::WindowElapsed,
                "expired placeholder",
            ),
            (
                TASK,
                [0u8; 20],
                RESULT,
                9,
                100,
                VwcVerification::WindowElapsed,
                "zero worker",
            ),
            (
                TASK,
                WORKER,
                RESULT,
                0,
                100,
                VwcVerification::WindowElapsed,
                "zero height",
            ),
        ];
        for (task, worker, result, height, payment, verification, why) in cases {
            assert!(
                VerifiedWorkCertificate::from_settlement(
                    task,
                    worker,
                    result,
                    height,
                    payment,
                    verification
                )
                .is_err(),
                "expected refusal: {why}"
            );
        }

        // A quorum certificate with a lying count is refused at construction.
        let (_set, cert) = quorum_cert();
        let mut lying = cert.clone();
        if let VwcVerification::Quorum { signer_count, .. } = &mut lying.verification {
            *signer_count = 99;
        }
        assert!(VerifiedWorkCertificate::from_settlement(
            lying.task_id,
            lying.worker,
            lying.result_hash,
            lying.settled_height,
            lying.payment_sat,
            lying.verification
        )
        .is_err());
    }

    #[test]
    fn a_zero_payout_settlement_still_certifies() {
        // An escrow that exactly covered the settle fee pays the worker nothing,
        // but the work was verified: the certificate records it honestly.
        let (set, verification) = real_quorum();
        let cert =
            VerifiedWorkCertificate::from_settlement(TASK, WORKER, RESULT, 9, 0, verification)
                .unwrap();
        cert.validate(&set, &RealBls).unwrap();
        assert_eq!(cert.payment_sat, 0);
    }

    /// A manual measurement probe, not a CI assertion: timing bounds flake, so
    /// the numbers are recorded in `docs/status.md` and the probe exists to
    /// re-measure after changes. Run with
    /// `cargo test -p jnt-l2 --lib vwc_perf_probe -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual perf probe; see docs/status.md for the recorded numbers"]
    fn vwc_perf_probe() {
        use std::time::Instant;

        let (set, verification) = real_quorum();
        let cert = VerifiedWorkCertificate::from_settlement(
            TASK,
            WORKER,
            RESULT,
            9,
            980_000,
            verification,
        )
        .unwrap();
        let n = 10_000u64;

        let t = Instant::now();
        for i in 0..n {
            let mut c = cert.clone();
            c.payment_sat = i;
            c.id = c.id();
            let _ = c.encode();
        }
        let encode_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;

        let bytes = cert.encode();
        let t = Instant::now();
        for _ in 0..n {
            let _ = VerifiedWorkCertificate::decode(&bytes).unwrap();
        }
        let decode_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;

        // The expensive path: a real pairing per validation.
        let t = Instant::now();
        for _ in 0..n {
            cert.validate(&set, &RealBls).unwrap();
        }
        let validate_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;

        println!("vwc encode {encode_us:.2} us, decode {decode_us:.2} us, validate {validate_us:.2} us (real BLS)");
    }

    #[test]
    fn the_certificate_binds_to_the_settle_decision_it_came_from() {
        let (_set, cert) = quorum_cert();
        let payload = SettlePayload {
            task_id: TASK,
            verdict: Verdict::Correct,
            vwc_hash: RESULT,
            bls_sig: [0u8; 96],
            signer_bitmap: Vec::new(),
            signer_count: 0,
        };
        assert!(cert.matches_settle(&payload));

        let wrong_result = SettlePayload {
            vwc_hash: [0xBBu8; 32],
            ..payload.clone()
        };
        assert!(!cert.matches_settle(&wrong_result));
        let wrong_verdict = SettlePayload {
            verdict: Verdict::Fraudulent,
            ..payload
        };
        assert!(!cert.matches_settle(&wrong_verdict));
    }
}
