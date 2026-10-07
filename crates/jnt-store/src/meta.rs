//! The store's metadata: which block is canonical, and which chain this is.
//!
//! Small enough to rewrite whole, which is what makes it safe: the file is
//! replaced by writing a temporary beside it and renaming over the top, so a
//! reader sees either the previous contents or the new ones and never a partial
//! write. That is the whole reason a reorg is cheap here — it moves this file and
//! nothing else.
//!
//! A checksum is stored alongside the fields rather than relying on the rename
//! alone, because on some filesystems a rename is atomic with respect to other
//! processes but says nothing about whether the *contents* reached the disk
//! before the power went out. If the checksum does not match, the metadata is
//! treated as lost — the node falls back to a tip it can prove (see
//! [`Meta::recover_to_genesis`]) — rather than being read as fact.

use std::fs;
use std::path::{Path, PathBuf};

use jnt_core::hash::{hash_from_hex, hash_to_hex, sha256, Hash};

use crate::log::LOG_MAGIC;
use crate::StoreError;

/// Metadata format version, independent of the log's.
pub const META_VERSION: u16 = 1;

/// The store's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub version: u16,
    /// Network name, so a store cannot be opened against another chain's data.
    pub network: String,
    /// Genesis hash, which identifies the chain as much as the name does.
    pub genesis: Hash,
    /// Hash of the canonical tip.
    pub tip: Hash,
    /// Height of the canonical tip. `0` means genesis.
    pub height: u64,
    /// Binding-finalized height (Decision 12), or `0` for none/unactivated.
    /// Persisted so a restart does not "un-finalize" history the node already
    /// committed to. Restored only if the block at this height still matches
    /// `finalized_hash`.
    pub finalized_height: u64,
    /// Canonical hash finalized at `finalized_height` (zero when none).
    pub finalized_hash: Hash,
}

impl Meta {
    pub fn new(network: impl Into<String>, genesis: Hash) -> Self {
        Meta {
            version: META_VERSION,
            network: network.into(),
            genesis,
            tip: genesis,
            height: 0,
            finalized_height: 0,
            finalized_hash: [0u8; 32],
        }
    }

    /// Attach the binding-finalized point (Decision 12) for persistence.
    pub fn with_finalized(mut self, finalized_height: u64, finalized_hash: Hash) -> Self {
        self.finalized_height = finalized_height;
        self.finalized_hash = finalized_hash;
        self
    }

    /// The state a store can always prove without trusting metadata: genesis,
    /// at height 0.
    ///
    /// Used when the metadata is unreadable. It is deliberately not "the deepest
    /// chain in the log": which chain is canonical is a decision the node made and
    /// recorded, and guessing a replacement from storage would put fork choice in
    /// the storage layer.
    pub fn recover_to_genesis(&self) -> Meta {
        Meta {
            version: META_VERSION,
            network: self.network.clone(),
            genesis: self.genesis,
            tip: self.genesis,
            height: 0,
            // A recovered store proves nothing, including finality: dropping the
            // finalized point to 0 is the fail-closed choice, re-derived from
            // the depth rule until new checkpoints arrive.
            finalized_height: 0,
            finalized_hash: [0u8; 32],
        }
    }

    /// Canonical text form, checksummed. The checksum covers every field, so a
    /// truncated or partially-written file cannot be read as a shorter valid one.
    fn render(&self) -> String {
        let body = format!(
            "{{\n  \"version\": {},\n  \"network\": \"{}\",\n  \"genesis\": \"{}\",\n  \"tip\": \"{}\",\n  \"height\": {},\n  \"finalized_height\": {},\n  \"finalized_hash\": \"{}\"\n}}",
            self.version,
            escape(&self.network),
            hash_to_hex(&self.genesis),
            hash_to_hex(&self.tip),
            self.height,
            self.finalized_height,
            hash_to_hex(&self.finalized_hash)
        );
        let sum = sha256(&[body.as_bytes()]);
        format!("{body}\n{}\n", jnt_core::hash::to_hex(&sum))
    }

    fn parse(text: &str) -> Result<Meta, StoreError> {
        let mut lines = text.lines();
        let mut body = String::new();
        let mut expected: Option<&str> = None;
        for line in lines.by_ref() {
            if line.starts_with("{\"sum\"") || is_hex64(line) {
                // The checksum line is the one we broke on, not the one after
                // it: the file ends with a trailing newline, and taking the
                // *next* line read an empty string as the expected digest.
                expected = Some(line.trim());
                break;
            }
            body.push_str(line);
            body.push('\n');
        }
        let expected = expected
            .filter(|l| !l.is_empty())
            .ok_or_else(|| StoreError::BadMeta {
                detail: "no checksum line".into(),
            })?;
        let body = body.trim_end().to_string();
        let actual = jnt_core::hash::to_hex(&sha256(&[body.as_bytes()]));
        if actual != expected {
            return Err(StoreError::BadMeta {
                detail: format!(
                    "checksum mismatch: file says {expected}, contents hash to {actual}"
                ),
            });
        }
        parse_body(&body)
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Minimal field extraction, so the store does not depend on a JSON crate.
///
/// The format is written by [`Meta::render`] and read here; it is deliberately a
/// closed, trivial parser rather than a general one, because a general parser is
/// more code between a file and a consensus decision.
fn parse_body(body: &str) -> Result<Meta, StoreError> {
    let field = |name: &str| -> Result<String, StoreError> {
        let key = format!("\"{name}\":");
        let idx = body.find(&key).ok_or_else(|| StoreError::BadMeta {
            detail: format!("missing field `{name}`"),
        })?;
        let rest = &body[idx + key.len()..];
        let rest = rest.trim_start();
        if let Some(stripped) = rest.strip_prefix('"') {
            let end = stripped.find('"').ok_or_else(|| StoreError::BadMeta {
                detail: format!("unterminated string for `{name}`"),
            })?;
            Ok(stripped[..end].to_string())
        } else {
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            Ok(rest[..end].to_string())
        }
    };

    let version: u16 = field("version")?.parse().map_err(|_| StoreError::BadMeta {
        detail: "version is not a number".into(),
    })?;
    if version != META_VERSION {
        return Err(StoreError::BadMeta {
            detail: format!("metadata version {version}, this build reads {META_VERSION}"),
        });
    }
    let network = field("network")?;
    let genesis = hash_from_hex(&field("genesis")?).map_err(|e| StoreError::BadMeta {
        detail: format!("genesis hash: {e}"),
    })?;
    let tip = hash_from_hex(&field("tip")?).map_err(|e| StoreError::BadMeta {
        detail: format!("tip hash: {e}"),
    })?;
    let height: u64 = field("height")?.parse().map_err(|_| StoreError::BadMeta {
        detail: "height is not a number".into(),
    })?;
    if height == 0 && tip != genesis {
        return Err(StoreError::BadMeta {
            detail: "height 0 with a tip that is not genesis".into(),
        });
    }
    // Finality fields were added after the first metadata format. An older file
    // simply lacks them, which means "no binding finality recorded" — the same
    // as 0 — so absence is not an error and must not be read as corruption.
    let finalized_height: u64 = match optional_field(body, "finalized_height")? {
        Some(s) => s.parse().map_err(|_| StoreError::BadMeta {
            detail: "finalized_height is not a number".into(),
        })?,
        None => 0,
    };
    let finalized_hash = match optional_field(body, "finalized_hash")? {
        Some(s) => hash_from_hex(&s).map_err(|e| StoreError::BadMeta {
            detail: format!("finalized hash: {e}"),
        })?,
        None => [0u8; 32],
    };
    if finalized_height == 0 && finalized_hash != [0u8; 32] {
        return Err(StoreError::BadMeta {
            detail: "finalized_height 0 with a nonzero finalized hash".into(),
        });
    }
    if finalized_height > height {
        return Err(StoreError::BadMeta {
            detail: "finalized height is above the tip".into(),
        });
    }
    Ok(Meta {
        version,
        network,
        genesis,
        tip,
        height,
        finalized_height,
        finalized_hash,
    })
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Extract an optional field the same way `parse_body`'s closure extracts
/// required ones, but returning `None` when the key is absent. Used for fields
/// added after the first format, so an older file stays readable.
fn optional_field(body: &str, name: &str) -> Result<Option<String>, StoreError> {
    let key = format!("\"{name}\":");
    let Some(idx) = body.find(&key) else {
        return Ok(None);
    };
    let rest = body[idx + key.len()..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"').ok_or_else(|| StoreError::BadMeta {
            detail: format!("unterminated string for `{name}`"),
        })?;
        Ok(Some(stripped[..end].to_string()))
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        Ok(Some(rest[..end].to_string()))
    }
}

/// The metadata file.
#[derive(Debug)]
pub struct MetaFile {
    path: PathBuf,
}

impl MetaFile {
    pub fn new(path: impl AsRef<Path>) -> Self {
        MetaFile {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the metadata, or `None` if the file does not exist.
    ///
    /// A *damaged* file is an error, not `None`: "no metadata" and "metadata that
    /// does not verify" call for different responses, and collapsing them would
    /// let a corrupt tip silently become an empty store.
    pub fn load(&self) -> Result<Option<Meta>, StoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                // Non-UTF-8 bytes are damage to a text-format file, not an OS
                // failure: report them as BadMeta rather than leaking a raw
                // `InvalidData` IO error. (Found by the fuzz-invariant tests,
                // which feed binary garbage to the parser.)
                let text = String::from_utf8(bytes).map_err(|_| StoreError::BadMeta {
                    detail: "meta.json is not valid utf-8".into(),
                })?;
                Meta::parse(&text).map(Some)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::io(&self.path, e)),
        }
    }

    /// Replace the metadata atomically.
    ///
    /// Write beside, flush, then rename over the top. The rename is the commit
    /// point: before it the old metadata is authoritative, after it the new one
    /// is, and there is no moment in between.
    pub fn save(&self, meta: &Meta) -> Result<(), StoreError> {
        use std::io::Write;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
            }
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp).map_err(|e| StoreError::io(&tmp, e))?;
            f.write_all(meta.render().as_bytes())
                .map_err(|e| StoreError::io(&tmp, e))?;
            // The data must be on disk *before* the rename, or a crash can leave
            // the new name pointing at content that never landed.
            f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| StoreError::io(&self.path, e))
    }

    /// Whether the file starts with this store's magic, so a foreign file is
    /// recognised rather than parsed.
    pub fn looks_like_store(&self) -> bool {
        match fs::read(&self.path) {
            Ok(bytes) => bytes.len() >= 4 && bytes[..4] == LOG_MAGIC,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jnt-store-meta-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn genesis() -> Hash {
        [0xAB; 32]
    }

    #[test]
    fn metadata_round_trips() {
        let f = MetaFile::new(tmp("meta1.json"));
        let m = Meta {
            version: META_VERSION,
            network: "mini".into(),
            genesis: genesis(),
            tip: [7u8; 32],
            height: 42,
            finalized_height: 0,
            finalized_hash: [0u8; 32],
        };
        f.save(&m).unwrap();
        assert_eq!(f.load().unwrap(), Some(m));
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let f = MetaFile::new(tmp("absent.json"));
        let _ = fs::remove_file(f.path());
        assert_eq!(f.load().unwrap(), None);
    }

    /// **A damaged metadata file is refused, not guessed at.** Reading a corrupt
    /// tip as fact would make the store's answer depend on a bad sector.
    #[test]
    fn a_damaged_metadata_file_is_an_error() {
        let f = MetaFile::new(tmp("meta2.json"));
        f.save(&Meta::new("mini", genesis())).unwrap();
        let mut text = fs::read_to_string(f.path()).unwrap();
        // Change the tip without touching the checksum.
        text = text.replace(&hash_to_hex(&genesis()), &hash_to_hex(&[0x11; 32]));
        fs::write(f.path(), text).unwrap();
        assert!(matches!(f.load(), Err(StoreError::BadMeta { .. })));
    }

    /// A file truncated mid-write cannot be read as a shorter valid one, because
    /// the checksum covers every field.
    #[test]
    fn a_truncated_metadata_file_is_an_error() {
        let f = MetaFile::new(tmp("meta3.json"));
        f.save(&Meta {
            version: META_VERSION,
            network: "mini".into(),
            genesis: genesis(),
            tip: [3u8; 32],
            height: 9,
            finalized_height: 0,
            finalized_hash: [0u8; 32],
        })
        .unwrap();
        let text = fs::read_to_string(f.path()).unwrap();
        fs::write(f.path(), &text[..text.len() / 2]).unwrap();
        assert!(matches!(f.load(), Err(StoreError::BadMeta { .. })));
    }

    /// Height 0 with a tip that is not genesis is a contradiction, and the
    /// parser refuses it rather than picking one field to believe.
    #[test]
    fn height_zero_with_a_non_genesis_tip_is_refused() {
        let body = "{\n  \"version\": 1,\n  \"network\": \"mini\",\n  \"genesis\": \"abababababababababababababababababababababababababababababababab\",\n  \"tip\": \"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\n  \"height\": 0\n}";
        let sum = jnt_core::hash::to_hex(&sha256(&[body.as_bytes()]));
        let text = format!("{body}\n{sum}\n");
        assert!(matches!(
            Meta::parse(&text),
            Err(StoreError::BadMeta { .. })
        ));
    }

    /// Recovery falls back to genesis, not to the deepest block in the log:
    /// which chain is canonical is a decision the node made and recorded.
    #[test]
    fn recovery_returns_to_genesis() {
        let m = Meta {
            version: META_VERSION,
            network: "mini".into(),
            genesis: genesis(),
            tip: [9u8; 32],
            height: 100,
            finalized_height: 60,
            finalized_hash: [0xAB; 32],
        };
        let r = m.recover_to_genesis();
        assert_eq!(r.tip, genesis());
        assert_eq!(r.height, 0);
        assert_eq!(r.finalized_height, 0, "recovery drops finality");
        assert_eq!(r.finalized_hash, [0u8; 32]);
        assert_eq!(r.genesis, genesis());
        assert_eq!(r.network, "mini");
    }
}
