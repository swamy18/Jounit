//! Transactions. SPEC.md §3.1-§3.3, §9.2.
//!
//! v0.1 is scriptless by design (design doc Section 20.3: keep the consensus
//! layer small). Validity is decided by the rules in this module plus the
//! profile parameters; future primitives (bonds, certificates, channels) will
//! add new `tx_type` values, never a scripting language.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::{
    sha256_dom, Address, Hash, DOM_SIG, DOM_TX, DOM_TXBODY, SIG_SCHEME_SECP256K1_ECDSA,
};
use crate::hexserde;
use crate::ser::{Reader, Writer};

pub const TX_STANDARD: u8 = 0;
pub const TX_COINBASE: u8 = 1;

pub const INPUT_SERIALIZED_LEN: usize = 133;
pub const OUTPUT_SERIALIZED_LEN: usize = 28;

/// Gas model (SPEC.md §8). No scripts, so cost is linear in size.
pub const GAS_TX_BASE: u64 = 16_000;
pub const GAS_PER_INPUT: u64 = 1_000;
pub const GAS_PER_OUTPUT: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutPoint {
    #[serde(with = "hexserde::h32")]
    pub txid: Hash,
    pub index: u32,
}

impl OutPoint {
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut w = Writer::with_capacity(36);
        w.fixed(&self.txid).u32le(self.index);
        let v = w.into_vec();
        let mut out = [0u8; 36];
        out.copy_from_slice(&v);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    #[serde(with = "hexserde::h32")]
    pub prev_hash: Hash,
    pub prev_index: u32,
    #[serde(with = "hexserde::h64")]
    pub signature: [u8; 64],
    #[serde(with = "hexserde::h33")]
    pub pubkey: [u8; 33],
}

impl Input {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.prev_hash,
            index: self.prev_index,
        }
    }

    pub fn unsigned(prev: &OutPoint) -> Self {
        Input {
            prev_hash: prev.txid,
            prev_index: prev.index,
            signature: [0u8; 64],
            pubkey: [0u8; 33],
        }
    }

    pub fn to_bytes(&self) -> [u8; INPUT_SERIALIZED_LEN] {
        let mut w = Writer::with_capacity(INPUT_SERIALIZED_LEN);
        w.fixed(&self.prev_hash)
            .u32le(self.prev_index)
            .fixed(&self.signature)
            .fixed(&self.pubkey);
        let v = w.into_vec();
        let mut out = [0u8; INPUT_SERIALIZED_LEN];
        out.copy_from_slice(&v);
        out
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Input {
            prev_hash: r.fixed()?,
            prev_index: r.u32le()?,
            signature: r.fixed()?,
            pubkey: r.fixed()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub value: u64,
    #[serde(with = "hexserde::h20")]
    pub address: Address,
}

impl Output {
    pub fn to_bytes(&self) -> [u8; OUTPUT_SERIALIZED_LEN] {
        let mut w = Writer::with_capacity(OUTPUT_SERIALIZED_LEN);
        w.u64le(self.value).fixed(&self.address);
        let v = w.into_vec();
        let mut out = [0u8; OUTPUT_SERIALIZED_LEN];
        out.copy_from_slice(&v);
        out
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Output {
            value: r.u64le()?,
            address: r.fixed()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub tx_type: u8,
    pub lock_time: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl Transaction {
    pub fn standard(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Transaction {
            version: 1,
            tx_type: TX_STANDARD,
            lock_time: 0,
            inputs,
            outputs,
        }
    }

    pub fn coinbase(prev_hash: Hash, height: u64, output: Output) -> Self {
        Transaction {
            version: 1,
            tx_type: TX_COINBASE,
            lock_time: 0,
            inputs: vec![Input {
                prev_hash,
                prev_index: height as u32,
                signature: [0u8; 64],
                pubkey: [0u8; 33],
            }],
            outputs: vec![output],
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.tx_type == TX_COINBASE
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + self.inputs.len() * INPUT_SERIALIZED_LEN);
        w.u32le(self.version)
            .u8(self.tx_type)
            .u64le(self.lock_time)
            .u32le(self.inputs.len() as u32);
        for i in &self.inputs {
            w.raw(&i.to_bytes());
        }
        w.u32le(self.outputs.len() as u32);
        for o in &self.outputs {
            w.raw(&o.to_bytes());
        }
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let tx = Transaction::from_reader(&mut r)?;
        r.expect_end()?;
        Ok(tx)
    }

    pub fn from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.u32le()?;
        let tx_type = r.u8()?;
        let lock_time = r.u64le()?;
        let n_in = r.u32le()? as usize;
        // Guard against a tiny buffer claiming a huge input count.
        if n_in > r.remaining() {
            return Err(Error::Malformed("input_count exceeds buffer"));
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            inputs.push(Input::from_reader(r)?);
        }
        let n_out = r.u32le()? as usize;
        if n_out > r.remaining() {
            return Err(Error::Malformed("output_count exceeds buffer"));
        }
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outputs.push(Output::from_reader(r)?);
        }
        Ok(Transaction {
            version,
            tx_type,
            lock_time,
            inputs,
            outputs,
        })
    }

    pub fn txid(&self) -> Hash {
        sha256_dom(DOM_TX, &[&self.serialize()])
    }

    /// Hash of the transaction with all signatures and pubkeys blanked.
    ///
    /// Signing against this (rather than the raw body) is what stops an output
    /// being swapped after the inputs were signed — SPEC.md §1.1.
    pub fn sighash(&self) -> Hash {
        let mut blanked = self.clone();
        for i in blanked.inputs.iter_mut() {
            i.signature = [0u8; 64];
            i.pubkey = [0u8; 33];
        }
        sha256_dom(DOM_TXBODY, &[&blanked.serialize()])
    }

    /// Exact bytes signed for input `k`.
    pub fn message_for_input(&self, k: usize) -> Hash {
        let mut w = Writer::with_capacity(48);
        w.u32le(k as u32)
            .fixed(&self.sighash())
            .u32le(self.inputs[k].prev_index);
        sha256_dom(DOM_SIG, &[w.as_slice()])
    }

    /// Total value of all outputs.
    ///
    /// Saturating, and the caller must treat `u64::MAX` as overflow: a
    /// transaction can declare more output value than a `u64` holds, and
    /// summing it with `.sum()` would panic in debug builds and wrap in
    /// release ones. `check_tx` compares this against the resolved input
    /// total and rejects it, so a wrapped sum could otherwise masquerade
    /// as a transaction spending less than it creates.
    pub fn value_out(&self) -> u64 {
        self.outputs
            .iter()
            .fold(0u64, |acc, o| acc.saturating_add(o.value))
    }

    /// True when the output total cannot be represented. `check_tx` calls
    /// this before trusting `value_out`.
    pub fn value_out_overflows(&self) -> bool {
        let mut acc: u64 = 0;
        for o in &self.outputs {
            match acc.checked_add(o.value) {
                Some(next) => acc = next,
                None => return true,
            }
        }
        false
    }

    /// Sum of input values. Only meaningful once inputs have been resolved
    /// against the UTXO set; `build`/`validate` pass those values in.
    pub fn gas_used(&self) -> u64 {
        GAS_TX_BASE
            .saturating_add(GAS_PER_INPUT * self.inputs.len() as u64)
            .saturating_add(GAS_PER_OUTPUT * self.outputs.len() as u64)
    }

    pub fn has_duplicate_inputs(&self) -> bool {
        let mut seen: Vec<OutPoint> = self.inputs.iter().map(|i| i.outpoint()).collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        seen.len() != before
    }

    pub fn has_zero_value_output(&self) -> bool {
        self.outputs.iter().any(|o| o.value == 0)
    }

    /// Verify input `k` against the address that owns the spent output.
    pub fn verify_input(&self, k: usize, owner: &Address, sig_scheme: u8) -> Result<()> {
        if sig_scheme != SIG_SCHEME_SECP256K1_ECDSA {
            return Err(Error::UnsupportedSigScheme(sig_scheme));
        }
        let input = &self.inputs[k];
        let addr = crate::hash::address_from_pubkey(&input.pubkey);
        if &addr != owner {
            return Err(Error::WrongAddress);
        }
        let msg = self.message_for_input(k);
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&input.pubkey)
            .map_err(|_| Error::BadPubkey)?;
        let sig = k256::ecdsa::Signature::from_slice(&input.signature)
            .map_err(|_| Error::BadSignature)?;
        // `normalize_s` returns Some only when the signature is *high*-s, i.e.
        // malleable. Reject those so txids stay canonical.
        if sig.normalize_s().is_some() {
            return Err(Error::BadSignature);
        }
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        key.verify_prehash(&msg, &sig)
            .map_err(|_| Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::address_from_pubkey;

    fn sample_pubkey() -> [u8; 33] {
        // x = 1 generator point, a well-known valid compressed key.
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn input_and_output_have_fixed_lengths() {
        let i = Input::unsigned(&OutPoint {
            txid: [7u8; 32],
            index: 3,
        });
        assert_eq!(i.to_bytes().len(), INPUT_SERIALIZED_LEN);
        assert_eq!(
            Output {
                value: 1,
                address: [0u8; 20]
            }
            .to_bytes()
            .len(),
            OUTPUT_SERIALIZED_LEN
        );
    }

    #[test]
    fn transaction_roundtrips() {
        let tx = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [1u8; 32],
                index: 0,
            })],
            vec![Output {
                value: 500,
                address: [9u8; 20],
            }],
        );
        let bytes = tx.serialize();
        let back = Transaction::deserialize(&bytes).unwrap();
        assert_eq!(tx, back);
        assert_eq!(back.txid(), tx.txid());
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let tx = Transaction::standard(
            vec![],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        let mut bytes = tx.serialize();
        bytes.push(0);
        assert!(matches!(
            Transaction::deserialize(&bytes),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn deserialize_rejects_absurd_counts() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(TX_STANDARD);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Transaction::deserialize(&bytes).is_err());
    }

    #[test]
    fn sighash_ignores_signatures_but_covers_outputs() {
        let base = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [2u8; 32],
                index: 1,
            })],
            vec![Output {
                value: 100,
                address: [1u8; 20],
            }],
        );
        let mut signed = base.clone();
        signed.inputs[0].signature = [0xab; 64];
        signed.inputs[0].pubkey = sample_pubkey();
        assert_eq!(
            base.sighash(),
            signed.sighash(),
            "sig must not affect sighash"
        );

        let mut retargeted = base.clone();
        retargeted.outputs[0].address = [2u8; 20];
        assert_ne!(
            base.sighash(),
            retargeted.sighash(),
            "outputs must be committed"
        );
    }

    #[test]
    fn duplicate_inputs_detected() {
        let prev = OutPoint {
            txid: [5u8; 32],
            index: 0,
        };
        let tx = Transaction::standard(
            vec![Input::unsigned(&prev), Input::unsigned(&prev)],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        assert!(tx.has_duplicate_inputs());

        let tx2 = Transaction::standard(
            vec![
                Input::unsigned(&prev),
                Input::unsigned(&OutPoint {
                    txid: [5u8; 32],
                    index: 1,
                }),
            ],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        assert!(!tx2.has_duplicate_inputs());
    }

    #[test]
    fn wrong_owner_address_is_rejected() {
        let mut tx = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [1u8; 32],
                index: 0,
            })],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        tx.inputs[0].pubkey = sample_pubkey();
        let real = address_from_pubkey(&tx.inputs[0].pubkey);
        assert!(matches!(
            tx.verify_input(0, &real, SIG_SCHEME_SECP256K1_ECDSA),
            Err(Error::BadSignature)
        ));
        assert!(matches!(
            tx.verify_input(0, &[0u8; 20], SIG_SCHEME_SECP256K1_ECDSA),
            Err(Error::WrongAddress)
        ));
        assert!(matches!(
            tx.verify_input(0, &real, 99),
            Err(Error::UnsupportedSigScheme(99))
        ));
    }

    #[test]
    fn an_unrepresentable_output_total_is_detected_not_wrapped() {
        // Outputs summing past u64::MAX. `.sum()` used to panic in debug and
        // wrap in release; `value_out_overflows` is what `check_tx` consults,
        // and `value_out` saturates rather than lying about the total.
        let tx = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [0; 32],
                index: 0,
            })],
            vec![
                Output {
                    value: u64::MAX,
                    address: [1; 20],
                },
                Output {
                    value: 1,
                    address: [2; 20],
                },
            ],
        );
        assert!(tx.value_out_overflows());
        assert_eq!(tx.value_out(), u64::MAX, "must saturate, not wrap to 0");

        // And a representable total must not be reported as overflow.
        let ok = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [0; 32],
                index: 0,
            })],
            vec![
                Output {
                    value: 1_000,
                    address: [1; 20],
                },
                Output {
                    value: 2_000,
                    address: [2; 20],
                },
            ],
        );
        assert!(!ok.value_out_overflows());
        assert_eq!(ok.value_out(), 3_000);
    }

    #[test]
    fn gas_is_linear_in_size() {
        let one = Transaction::standard(
            vec![Input::unsigned(&OutPoint {
                txid: [0; 32],
                index: 0,
            })],
            vec![Output {
                value: 1,
                address: [0; 20],
            }],
        );
        assert_eq!(one.gas_used(), GAS_TX_BASE + GAS_PER_INPUT + GAS_PER_OUTPUT);
    }

    /// Byte layouts pinned in `tests/vectors/ser_vectors.json`.
    ///
    /// Section sizes alone are already asserted above; what matters for a
    /// second implementation is the exact byte order, so the full
    /// serializations are recorded rather than just their lengths.
    #[test]
    fn serialization_vectors_are_stable() {
        // Regenerate with: UPDATE_SER_VECTORS=1 cargo test -p jnt-core
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vectors/ser_vectors.json");

        let input = Input {
            prev_hash: [0xABu8; 32],
            prev_index: 0xDEAD_BEEF,
            signature: [0xCDu8; 64],
            pubkey: {
                let mut p = [0xEFu8; 33];
                p[0] = 0x02; // compressed secp256k1 prefix
                p
            },
        };
        let output = Output {
            value: 0x0123_4567_89AB_CDEF,
            address: [0x42u8; 20],
        };
        let tx = Transaction {
            version: 1,
            tx_type: TX_STANDARD,
            lock_time: 0x11_22_33_44_55_66_77_88,
            inputs: vec![input],
            outputs: vec![output],
        };

        let entries: Vec<(&str, Vec<u8>, usize)> = vec![
            ("input", input.to_bytes().to_vec(), INPUT_SERIALIZED_LEN),
            ("output", output.to_bytes().to_vec(), OUTPUT_SERIALIZED_LEN),
            ("transaction", tx.serialize(), 0),
        ];

        let mut json = String::from("{\n");
        json.push_str(
            "  \"_comment\": \"Generated from jnt-core by serialization_vectors_are_stable. \
Do not hand-edit.\",\n",
        );
        json.push_str(&format!("  \"input_len\": {INPUT_SERIALIZED_LEN},\n"));
        json.push_str(&format!("  \"output_len\": {OUTPUT_SERIALIZED_LEN},\n"));
        json.push_str("  \"items\": [\n");
        for (i, (name, bytes, declared)) in entries.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"name\": \"{name}\",\n"));
            json.push_str(&format!("      \"len\": {},\n", bytes.len()));
            if *declared > 0 {
                json.push_str(&format!("      \"declared_len\": {declared},\n"));
            }
            json.push_str(&format!("      \"hex\": \"{}\"\n", hex::encode(bytes)));
            json.push_str(if i + 1 == entries.len() {
                "    }\n"
            } else {
                "    },\n"
            });
        }
        json.push_str("  ]\n}\n");

        if std::env::var("UPDATE_SER_VECTORS").is_ok() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, json).unwrap();
            eprintln!("wrote {}", path.display());
            return;
        }

        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read {}: {e}\nregenerate with UPDATE_SER_VECTORS=1",
                path.display()
            )
        });
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["input_len"].as_u64().unwrap(), 133, "SPEC.md 3.1");
        assert_eq!(v["output_len"].as_u64().unwrap(), 28, "SPEC.md 3.2");

        let listed = v["items"].as_array().expect("items must be an array");
        assert_eq!(listed.len(), entries.len(), "vector file is stale");
        for (entry, (name, bytes, _)) in listed.iter().zip(entries.iter()) {
            assert_eq!(entry["name"], *name);
            assert_eq!(
                entry["len"].as_u64().unwrap() as usize,
                bytes.len(),
                "{name}: serialized length changed"
            );
            assert_eq!(
                entry["hex"].as_str().unwrap(),
                hex::encode(bytes),
                "{name}: serialized bytes changed -- this is a consensus change"
            );
        }
    }
}
