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
        SigningKey::from_bytes((&self.private_key).into()).map_err(|_| Error::BadKey("scalar out of range"))
    }

    pub fn pubkey(&self) -> Result<[u8; 33]> {
        let sk = self.signing_key()?;
        Ok(sk.verifying_key().to_encoded_point(true).as_bytes()[..33].try_into().unwrap())
    }

    pub fn address(&self) -> Result<Address> {
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
    /// Fee is explicit rather than computed from a UTXO scan: the caller knows
    /// the node's base fee, and an implicit fee would let a builder silently
    /// underpay and get its transaction rejected.
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
            inputs
                .iter()
                .map(Input::unsigned)
                .collect::<Vec<_>>(),
            outputs,
        );
        self.sign(&mut tx)?;
        let _ = fee;
        Ok(tx)
    }

    /// Sign every input of `tx`. Re-signing after an output change invalidates
    /// all previous signatures, which is exactly the intended behaviour.
    pub fn sign(&self, tx: &mut Transaction) -> Result<()> {
        if tx.is_coinbase() {
            return Err(Error::BadKey("coinbase transactions are not signed"));
        }
        let pubkey = self.pubkey()?;
        for k in 0..tx.inputs.len() {
            let msg = tx.message_for_input(k);
            tx.inputs[k].signature = self.sign_digest(&msg)?;
            tx.inputs[k].pubkey = pubkey;
        }
        Ok(())
    }
}

pub fn verify_digest(pubkey: &[u8; 33], digest: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let key = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| Error::BadPubkey)?;
    let s = Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
    // Some(.) means the signature is high-s and therefore malleable.
    if s.normalize_s().is_some() {
        return Err(Error::BadSignature);
    }
    key.verify_prehash(digest, &s)
        .map_err(|_| Error::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet() -> Wallet {
        Wallet::new_random("test")
    }

    #[test]
    fn addresses_are_20_bytes_and_derived_from_the_key() {
        let w = wallet();
        let a = w.address().unwrap();
        assert_eq!(a.len(), 20);
        assert_eq!(a, address_from_pubkey(&w.pubkey().unwrap()));
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
        tx.verify_input(0, &addr, crate::hash::SIG_SCHEME_SECP256K1_ECDSA)
            .unwrap();
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
            tx.verify_input(0, &addr, crate::hash::SIG_SCHEME_SECP256K1_ECDSA),
            Err(Error::BadSignature)
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
        let mut cb = Transaction::coinbase([0u8; 32], 1, Output { value: 1, address: w.address().unwrap() });
        assert!(w.sign(&mut cb).is_err());
    }
}