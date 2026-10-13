//! Keys, addresses and transaction building/signing. SPEC.md §1.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::{address_from_pubkey, Address};
use crate::tx::{Input, OutPoint, Output, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub label: String,
    #[serde(with = "crate::hexserde::h32")]
    pub private_key: [u8; 32],
}

/// The scheme set an input is signed under. See [`Wallet::sign_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMode {
    /// ECDSA only. The pre-hybrid format.
    Classical,
    /// ECDSA + BIP-340 Schnorr. Default before a lattice component is added.
    Hybrid,
    /// ECDSA + Schnorr + ML-DSA-65. The post-quantum-ready bundle.
    PostQuantum,
}

impl Wallet {
    pub fn new_random(label: impl Into<String>) -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Wallet {
            label: label.into(),
            private_key: bytes,
        }
    }

    pub fn from_private_key_bytes(bytes: &[u8], label: impl Into<String>) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::BadKey("private key must be 32 bytes"));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(bytes);
        let w = Wallet {
            label: label.into(),
            private_key: pk,
        };
        // Reject out-of-range scalars up front rather than at signing time.
        w.signing_key()?;
        Ok(w)
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        SigningKey::from_bytes((&self.private_key).into())
            .map_err(|_| Error::BadKey("scalar out of range"))
    }

    pub fn pubkey(&self) -> Result<[u8; 33]> {
        let sk = self.signing_key()?;
        Ok(sk.verifying_key().to_encoded_point(true).as_bytes()[..33]
            .try_into()
            .unwrap())
    }

    /// The address funds from this wallet.
    ///
    /// This is the **hybrid** address, matching what [`Wallet::sign`]
    /// produces by default. A wallet that signs a hybrid bundle and is
    /// credited at a single-scheme address would be spending against outputs it
    /// cannot move, so the two must agree.
    pub fn address(&self) -> Result<Address> {
        self.hybrid_address()
    }

    /// Address for a single-scheme ECDSA-only bundle.
    ///
    /// Only for wallets that sign with `sign_with(tx, false)`. Kept explicit
    /// because mixing the two silently produces unspendable outputs.
    pub fn ecdsa_address(&self) -> Result<Address> {
        Ok(address_from_pubkey(&self.pubkey()?))
    }

    /// Deterministic ECDSA over a SHA-256 digest, low-`s` canonicalised.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let sk = self.signing_key()?;
        let (sig, _rec): (Signature, _) = sk
            .sign_prehash(digest)
            .map_err(|_| Error::BadKey("signing failed"))?;
        let canonical = sig.normalize_s().unwrap_or(sig);
        let bytes = canonical.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    pub fn public_key_hex(&self) -> Result<String> {
        Ok(hex::encode(self.pubkey()?))
    }

    /// Build and fully sign a spend of `inputs` paying `outputs` plus `fee`.
    ///
    /// The caller is responsible for making `sum(outputs) + fee` equal the
    /// resolved input total — that means including change in `outputs`. This
    /// function cannot check it, because resolving input values needs the UTXO
    /// set, which it does not have; `check_tx` is where that is enforced.
    ///
    /// `fee` is therefore an assertion, not a suggestion: it must be
    /// representable alongside the outputs. It used to be accepted and then
    /// discarded outright (`let _ = fee;`), so a caller following the doc —
    /// sizing `outputs` to the inputs and passing the fee separately — got a
    /// transaction paying whatever the leftover happened to be, which is zero
    /// when no change output was added.
    pub fn build_tx(
        &self,
        inputs: &[OutPoint],
        outputs: Vec<Output>,
        fee: u64,
    ) -> Result<Transaction> {
        if inputs.is_empty() {
            return Err(Error::BadKey("transaction needs at least one input"));
        }
        let mut tx = Transaction::standard(
            inputs.iter().map(Input::unsigned).collect::<Vec<_>>(),
            outputs,
        );
        if tx.value_out_overflows() {
            return Err(Error::ValueOverflow);
        }
        tx.value_out()
            .checked_add(fee)
            .ok_or(Error::ValueOverflow)?;
        self.sign(&mut tx)?;
        Ok(tx)
    }

    /// Sign every input of `tx`. Re-signing after an output change invalidates
    /// all previous signatures, which is exactly the intended behaviour.
    ///
    /// Three modes, and the mode decides which address the output must have
    /// been credited to, because the address commits to the whole key set:
    ///
    /// - `SignMode::Classical` — ECDSA only (`ecdsa_address`).
    /// - `SignMode::Hybrid` — ECDSA + Schnorr (`hybrid_address`, the default).
    /// - `SignMode::PostQuantum` — ECDSA + Schnorr + ML-DSA-65 (`pq_address`).
    ///
    /// The post-quantum bundle is the one to use once a CRQC is plausible: a
    /// Shor break of secp256k1 forges the classical components but cannot
    /// produce the lattice one, and every component must verify.
    pub fn sign(&self, tx: &mut Transaction) -> Result<()> {
        self.sign_with(tx, true)
    }

    pub fn sign_with(&self, tx: &mut Transaction, hybrid: bool) -> Result<()> {
        self.sign_mode(
            tx,
            if hybrid {
                SignMode::Hybrid
            } else {
                SignMode::Classical
            },
        )
    }

    /// Sign every input under an explicit scheme set. See [`Wallet::sign`] for
    /// what each mode commits to.
    pub fn sign_mode(&self, tx: &mut Transaction, mode: SignMode) -> Result<()> {
        if tx.is_coinbase() {
            return Err(Error::BadKey("coinbase transactions are not signed"));
        }
        let ecdsa_pub = self.pubkey()?;
        let schnorr_pub = self.schnorr_pubkey()?;
        let ml_dsa_pub = if mode == SignMode::PostQuantum {
            Some(self.ml_dsa_pubkey()?)
        } else {
            None
        };
        let mut key_components = vec![crate::sig::Component::new(
            crate::sig::SCHEME_SECP256K1_ECDSA,
            ecdsa_pub.to_vec(),
        )];
        if mode != SignMode::Classical {
            key_components.push(crate::sig::Component::new(
                crate::sig::SCHEME_SECP256K1_SCHNORR,
                schnorr_pub.to_vec(),
            ));
        }
        if let Some(pq) = ml_dsa_pub {
            key_components.push(crate::sig::Component::new(crate::sig::SCHEME_ML_DSA_65, pq));
        }

        for k in 0..tx.inputs.len() {
            let msg = tx.message_for_input(k);
            let mut sig_components = vec![crate::sig::Component::new(
                crate::sig::SCHEME_SECP256K1_ECDSA,
                self.sign_digest(&msg)?.to_vec(),
            )];
            if mode != SignMode::Classical {
                sig_components.push(crate::sig::Component::new(
                    crate::sig::SCHEME_SECP256K1_SCHNORR,
                    self.sign_schnorr(&msg)?.to_vec(),
                ));
            }
            if mode == SignMode::PostQuantum {
                sig_components.push(crate::sig::Component::new(
                    crate::sig::SCHEME_ML_DSA_65,
                    self.sign_ml_dsa(&msg)?,
                ));
            }
            let input = &mut tx.inputs[k];
            input.keys = crate::sig::Bundle {
                components: key_components.clone(),
            };
            input.sigs = crate::sig::Bundle {
                components: sig_components,
            };
        }
        Ok(())
    }

    /// The address a hybrid bundle from this wallet would produce.
    pub fn hybrid_address(&self) -> Result<Address> {
        let ecdsa_pub = self.pubkey()?;
        let schnorr_pub = self.schnorr_pubkey()?;
        crate::sig::Bundle {
            components: vec![
                crate::sig::Component::new(crate::sig::SCHEME_SECP256K1_ECDSA, ecdsa_pub.to_vec()),
                crate::sig::Component::new(
                    crate::sig::SCHEME_SECP256K1_SCHNORR,
                    schnorr_pub.to_vec(),
                ),
            ],
        }
        .address()
    }

    /// BIP-340 Schnorr signing key over the same 32-byte scalar.
    pub fn schnorr_signing_key(&self) -> Result<k256::schnorr::SigningKey> {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&self.private_key);
        k256::schnorr::SigningKey::from_bytes(&raw)
            .map_err(|_| Error::BadKey("scalar out of range"))
    }

    /// BIP-340 x-only public key, 32 bytes.
    pub fn schnorr_pubkey(&self) -> Result<[u8; 32]> {
        Ok(self
            .schnorr_signing_key()?
            .verifying_key()
            .to_bytes()
            .into())
    }

    /// BIP-340 Schnorr signature over a 32-byte digest.
    pub fn sign_schnorr(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        use k256::schnorr::signature::hazmat::PrehashSigner;
        let sk = self.schnorr_signing_key()?;
        let sig: k256::schnorr::Signature = sk
            .sign_prehash(digest)
            .map_err(|_| Error::BadKey("schnorr signing failed"))?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        Ok(out)
    }

    /// The ML-DSA-65 signing seed, derived from this wallet's key material.
    ///
    /// Derived rather than stored, so a wallet's serialization and its
    /// post-quantum half stay in lockstep: a `Wallet` with no extra field still
    /// recovers the same ML-DSA key after a restart. The seed is a fresh
    /// domain-separated hash of the private key, not the scalar itself — the
    /// ML-DSA key generation must not depend on the secp256k1 scalar being a
    /// particular value.
    fn ml_dsa_seed(&self) -> [u8; 32] {
        use crate::hash::{sha256_dom, DOM_ADDR};
        sha256_dom(DOM_ADDR, &[b"jounit/ml-dsa-65-seed/v1", &self.private_key])
    }

    /// The ML-DSA-65 public key for this wallet, encoded (1952 bytes).
    pub fn ml_dsa_pubkey(&self) -> Result<Vec<u8>> {
        use ml_dsa::{Keypair as _, MlDsa65, SigningKey};
        let sk = SigningKey::<MlDsa65>::from_seed(&self.ml_dsa_seed().into());
        Ok(sk.verifying_key().encode().to_vec())
    }

    /// ML-DSA-65 signature over a 32-byte digest (FIPS 204, deterministic).
    pub fn sign_ml_dsa(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        use ml_dsa::{MlDsa65, SigningKey};
        let sk = SigningKey::<MlDsa65>::from_seed(&self.ml_dsa_seed().into());
        // `Signer` (the `SigningKey` wrapper) signs over a pre-hashed digest;
        // the expanded key is what offers the deterministic primitive, and it
        // is what `sign_deterministic` exists on.
        let sig = sk
            .expanded_key()
            .sign_deterministic(digest, &[])
            .map_err(|_| Error::BadKey("ml-dsa signing failed"))?;
        Ok(sig.encode().to_vec())
    }

    /// The address a **post-quantum** bundle from this wallet produces:
    /// ECDSA + Schnorr + ML-DSA-65 key components.
    ///
    /// This is the address mainnet funds should be credited at once wallets
    /// sign PQ bundles. A hybrid (1+2) address and a PQ (1+2+3) address are
    /// different addresses by construction — the address commits to the whole
    /// key set — so the two never alias and an output sent to one is not
    /// spendable under the other.
    pub fn pq_address(&self) -> Result<Address> {
        crate::sig::Bundle {
            components: vec![
                crate::sig::Component::new(
                    crate::sig::SCHEME_SECP256K1_ECDSA,
                    self.pubkey()?.to_vec(),
                ),
                crate::sig::Component::new(
                    crate::sig::SCHEME_SECP256K1_SCHNORR,
                    self.schnorr_pubkey()?.to_vec(),
                ),
                crate::sig::Component::new(crate::sig::SCHEME_ML_DSA_65, self.ml_dsa_pubkey()?),
            ],
        }
        .address()
    }
}

/// Verify a single-scheme ECDSA signature against a digest.
///
/// Kept for callers holding a bare key rather than an input bundle. Anything
/// checking a transaction must go through `Transaction::verify_input`, which
/// handles bundles and the address commitment.
pub fn verify_digest(pubkey: &[u8; 33], digest: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let key = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| Error::BadPubkey)?;
    let s = Signature::from_slice(sig).map_err(|_| Error::BadSignature { scheme: 1 })?;
    // Some(.) means the signature is high-s and therefore malleable.
    if s.normalize_s().is_some() {
        return Err(Error::BadSignature { scheme: 1 });
    }
    key.verify_prehash(digest, &s)
        .map_err(|_| Error::BadSignature { scheme: 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet() -> Wallet {
        Wallet::new_random("test")
    }

    #[test]
    fn the_credited_address_matches_what_signing_produces() {
        // The address a wallet is credited at must be the address its
        // signatures spend from, or funds become unspendable. Hybrid signing
        // commits to both schemes, so `address()` is the hybrid address and
        // differs from the ECDSA-only one.
        let w = wallet();
        let a = w.address().unwrap();
        assert_eq!(a.len(), 20);
        assert_eq!(a, w.hybrid_address().unwrap());
        assert_ne!(
            a,
            w.ecdsa_address().unwrap(),
            "the hybrid address must not equal the single-scheme one"
        );
        assert_ne!(a, wallet().address().unwrap());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let w = wallet();
        let digest = crate::hash::sha256(&[b"jounit test message"]);
        let sig = w.sign_digest(&digest).unwrap();
        verify_digest(&w.pubkey().unwrap(), &digest, &sig).unwrap();
    }

    #[test]
    fn signature_does_not_verify_for_another_key_or_message() {
        let w = wallet();
        let other = wallet();
        let digest = crate::hash::sha256(&[b"m1"]);
        let sig = w.sign_digest(&digest).unwrap();
        assert!(verify_digest(&other.pubkey().unwrap(), &digest, &sig).is_err());
        let digest2 = crate::hash::sha256(&[b"m2"]);
        assert!(verify_digest(&w.pubkey().unwrap(), &digest2, &sig).is_err());
    }

    #[test]
    fn signed_transaction_verifies_against_its_inputs() {
        let w = wallet();
        let addr = w.address().unwrap();
        let op = OutPoint {
            txid: [11u8; 32],
            index: 2,
        };
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&op)],
            vec![Output {
                value: 900,
                address: addr,
            }],
        );
        w.sign(&mut tx).unwrap();
        tx.verify_input_any(0, &addr).unwrap();
    }

    #[test]
    fn changing_an_output_invalidates_the_signature() {
        let w = wallet();
        let addr = w.address().unwrap();
        let op = OutPoint {
            txid: [12u8; 32],
            index: 0,
        };
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&op)],
            vec![Output {
                value: 900,
                address: addr,
            }],
        );
        w.sign(&mut tx).unwrap();
        tx.outputs[0].value = 1;
        assert!(matches!(
            tx.verify_input_any(0, &addr),
            Err(Error::BadSignature { .. })
        ));
    }

    #[test]
    fn rejects_bad_key_material() {
        assert!(Wallet::from_private_key_bytes(&[1u8; 31], "short").is_err());
        assert!(Wallet::from_private_key_bytes(&[0u8; 32], "zero").is_err());
        assert!(Wallet::from_private_key_bytes(&[0xffu8; 32], "max").is_err());
        assert!(Wallet::from_private_key_bytes(&[1u8; 32], "one").is_ok());
    }

    #[test]
    fn coinbase_is_never_signed() {
        let w = wallet();
        let mut cb = Transaction::coinbase(
            [0u8; 32],
            1,
            Output {
                value: 1,
                address: w.address().unwrap(),
            },
        );
        assert!(w.sign(&mut cb).is_err());
    }
}
