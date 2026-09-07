//! Publisher-authenticated, precomposed dependency closures. This is separate
//! from the legacy manifest checksum: possession of bytes is not admission.
use crate::Hash;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"celln.dev/closure-v1\0";
const COMPOSITION_DOMAIN: &[u8] = b"celln.dev/closure-v2\0";

#[path = "composition.rs"]
pub mod composition;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Closure {
    pub api_version: String,
    /// Hash of the entire immutable ext2 filesystem, including loader paths.
    pub toolfs: String,
    pub entrypoint: String,
    pub interpreter: bool,
    /// Every admitted code file, keyed by canonical absolute path. Dependencies
    /// name other members; composition never consults a host library directory.
    pub members: BTreeMap<String, Member>,
    /// v2 only: exact signed v1 inputs, runtime first. Keeping these inside the
    /// signed message preserves source identity and withdrawal checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<composition::Source>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Member {
    pub hash: String,
    pub dependencies: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedClosure {
    pub closure: Closure,
    /// Lowercase hex Ed25519 public key, matched against separate host policy.
    pub publisher: String,
    pub signature: String,
}

fn hash(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub fn canonical_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 1024
        && path[1..].split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
        })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid closure key/signature encoding".into());
    }
    let mut bytes = [0; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| "invalid hex")?;
    }
    Ok(bytes)
}

impl Closure {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.api_version.as_str(),
            "celln.dev/closure-v1" | "celln.dev/closure-v2"
        ) || (self.api_version == "celln.dev/closure-v1" && !self.sources.is_empty())
            || !hash(&self.toolfs)
            || self.members.is_empty()
            || self.members.len() > 256
            || !self.members.contains_key(&self.entrypoint)
        {
            return Err("invalid closure identity, version, or entrypoint".into());
        }
        for (path, member) in &self.members {
            if !canonical_path(path)
                || !hash(&member.hash)
                || member
                    .dependencies
                    .iter()
                    .any(|p| !self.members.contains_key(p))
            {
                return Err("invalid closure member or unresolved dependency".into());
            }
        }
        // Cycles are legal (real shared libraries can depend on one another),
        // unreachable extras are not: they must not accidentally gain authority.
        let mut seen = BTreeSet::new();
        let mut pending = vec![self.entrypoint.as_str()];
        while let Some(path) = pending.pop() {
            if seen.insert(path) {
                pending.extend(self.members[path].dependencies.iter().map(String::as_str));
            }
        }
        if seen.len() != self.members.len() {
            return Err("closure contains unreachable code members".into());
        }
        if self.api_version == "celln.dev/closure-v2" {
            let expected = composition::compose(self.sources.clone(), &Hash(self.toolfs.clone()))?;
            if self.entrypoint != expected.entrypoint
                || self.interpreter != expected.interpreter
                || self.members != expected.members
            {
                return Err("composed closure differs from its signed source graph".into());
            }
        }
        Ok(())
    }

    fn message(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut message = if self.api_version == "celln.dev/closure-v2" {
            COMPOSITION_DOMAIN
        } else {
            DOMAIN
        }
        .to_vec();
        message.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(message)
    }

    /// Offline publisher operation. Dispatch never needs this private key.
    pub fn sign(self, seed: &[u8; 32]) -> Result<SignedClosure, String> {
        let key = SigningKey::from_bytes(seed);
        let signature = hex(&key.sign(&self.message()?).to_bytes());
        Ok(SignedClosure {
            closure: self,
            publisher: hex(&key.verifying_key().to_bytes()),
            signature,
        })
    }
}

impl SignedClosure {
    pub fn verify(&self, publishers: &BTreeSet<String>) -> Result<(), String> {
        if !publishers.contains(&self.publisher) {
            return Err("closure publisher is not authorized".into());
        }
        for source in &self.closure.sources {
            source.parse()?.verify(publishers)?;
        }
        let key = VerifyingKey::from_bytes(&decode(&self.publisher)?)
            .map_err(|_| "invalid closure publisher key")?;
        key.verify_strict(
            &self.closure.message()?,
            &Signature::from_bytes(&decode(&self.signature)?),
        )
        .map_err(|_| "closure signature verification failed".into())
    }

    pub fn identity(&self) -> Result<Hash, String> {
        Ok(Hash::of(
            &serde_json::to_vec(self).map_err(|e| e.to_string())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Closure {
        Closure {
            api_version: "celln.dev/closure-v1".into(),
            sources: Vec::new(),
            toolfs: Hash::of(b"filesystem").0,
            entrypoint: "/bin/program".into(),
            interpreter: false,
            members: BTreeMap::from([
                (
                    "/bin/program".into(),
                    Member {
                        hash: Hash::of(b"program").0,
                        dependencies: BTreeSet::from(["/lib/loader.so".into()]),
                    },
                ),
                (
                    "/lib/loader.so".into(),
                    Member {
                        hash: Hash::of(b"loader").0,
                        dependencies: BTreeSet::new(),
                    },
                ),
            ]),
        }
    }
    #[test]
    fn authenticates_publisher_and_every_authority_field() {
        let signed = fixture().sign(&[42; 32]).unwrap();
        let policy = BTreeSet::from([signed.publisher.clone()]);
        assert!(signed.verify(&policy).is_ok());
        assert!(signed.verify(&BTreeSet::new()).is_err());
        let mut mutations = Vec::new();
        let mut c = signed.clone();
        c.closure.toolfs = Hash::of(b"replacement").0;
        mutations.push(c);
        let mut c = signed.clone();
        c.closure.interpreter = true;
        mutations.push(c);
        let mut c = signed.clone();
        c.closure.members.get_mut("/lib/loader.so").unwrap().hash = Hash::of(b"evil").0;
        mutations.push(c);
        let mut c = signed.clone();
        c.signature = hex(&[0; 64]);
        mutations.push(c);
        for mutation in mutations {
            assert!(mutation.verify(&policy).is_err());
        }
    }
    #[test]
    fn graph_and_paths_fail_closed() {
        for path in [
            "relative",
            "/../bin",
            "/bin//program",
            "/bin/./program",
            "/bin/a\ncommand",
            "/",
        ] {
            assert!(!canonical_path(path));
        }
        let mut c = fixture();
        c.members.remove("/lib/loader.so");
        assert!(c.validate().is_err());
        let mut c = fixture();
        c.members
            .get_mut("/bin/program")
            .unwrap()
            .dependencies
            .clear();
        assert!(c.validate().is_err());
    }
}
