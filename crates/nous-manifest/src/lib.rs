//! Shared Nouscell types.
//!
//! This crate is the vocabulary of the system, in code form. It mirrors
//! `NAMES_AND_CONVENTIONS.md`:
//!   * a **mote** is the substrate at rest; a **cell** is a sealed, tool-loaned mote.
//!   * the **tool lane** is attested (host-lent); the **data lane** is born-in-cell.
//!   * trust **tiers** are Forged (1) / Verified (2) / Unsealed (3).
//!
//! Nothing here needs KVM, so it is fully unit-tested and is the trust core the
//! rest of the POC is built on.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// A content address. Exec-by-hash means the filesystem has no authority to run
/// code — only a `Hash` present in a signed [`Manifest`] can be executed.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash(pub String);

impl Hash {
    /// BLAKE3 of the given bytes, rendered as `blake3:<hex>`.
    pub fn of(bytes: &[u8]) -> Self {
        let h = blake3::hash(bytes);
        Hash(format!("blake3:{}", h.to_hex()))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.0)
    }
}

/// Trust tier of an artifact. Higher assurance = lower number.
///
/// The rule the whole design turns on: **serve fast, upgrade trust async.**
/// A cold request is served at `Verified` in seconds while a `Forged` rebuild
/// runs in the background; the manifest records which tier a cell actually got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    /// Rebuilt from source and byte-compared. Earned when `Entry::recipe`
    /// is set; merely asserted when it is not.
    Forged = 1,
    /// Upstream binary hash-pinned, scanned, signed. Seconds; the cold path.
    Verified = 2,
    /// No attestation, still hardware-isolated. Instant; onboarding / escape hatch.
    Unsealed = 3,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Tier::Forged => "forged",
            Tier::Verified => "verified",
            Tier::Unsealed => "unsealed",
        };
        f.write_str(s)
    }
}

/// Provenance lane. The single bit tracked per file/exec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lane {
    /// Manifest-attested, hypervisor-sealed. Full (small) cell authority.
    Tool,
    /// Born inside the cell. Runs in the bounded agent lane.
    Data,
}

impl fmt::Display for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Lane::Tool => "tool",
            Lane::Data => "data",
        })
    }
}

/// Who wrote the source these bytes were built from.
///
/// This is **not** the same question as [`Tier`], and conflating the two is a
/// laundering route. Tier asks *how were these bytes produced, and can we
/// reproduce them* — provenance of the build. Author asks *whose intent do
/// they encode* — authority to act.
///
/// A program an agent wrote and we then compiled hermetically is legitimately
/// `Forged` **and** `Agent`-authored. Those are not in tension; they answer
/// different questions. Reading authority off the tier alone means a compiler
/// launders agent-authored code into the tool lane — the same move the
/// laundering ban stops at runtime, done ahead of time instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Author {
    /// Supplied by the host operator: a distro binary, a vendored source tree.
    #[default]
    Host,
    /// Written by an agent. Never carries tool-lane authority, at any tier.
    Agent,
}

impl fmt::Display for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Author::Host => "host",
            Author::Agent => "agent",
        })
    }
}

/// One attested artifact in a manifest: a name alias, its content hash, the
/// tier at which it was admitted, who authored it, and whether it is an
/// interpreter (relevant to the laundering ban — see [`resolve_exec_lane`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Path-style alias, e.g. `/usr/bin/python`. A naming convenience only —
    /// authority comes from `hash`, never the path.
    pub alias: String,
    pub hash: Hash,
    pub tier: Tier,
    /// True for interpreters (python, sh, node, …). An interpreter fed tainted
    /// input is demoted for that invocation.
    pub interpreter: bool,
    /// Defaulted so manifests written before this field existed still parse —
    /// and default to the safe answer only because host-authored is what every
    /// one of those entries actually was.
    #[serde(default)]
    pub author: Author,
    /// Set only when [`Tier::Forged`] was **earned**: the hash of the recipe an
    /// independent rebuild reproduced these exact bytes from.
    ///
    /// `None` at `Forged` means the tier was asserted by whoever admitted it
    /// and nothing rebuilt anything — which is what every entry looked like
    /// before a build plane existed. Keeping the distinction visible in the
    /// manifest is the point: a reader can tell a checked claim from a stated
    /// one without trusting the tool that wrote it.
    #[serde(default)]
    pub recipe: Option<Hash>,
}

/// A signed manifest: the set of hashes a cell is permitted to execute, plus a
/// revocation set. Revocation is authoritative and immediate — a hash in
/// `revoked` cannot run even if it is still listed in `entries`.
///
/// The signature here is a stand-in (a hash of the canonical body). A real
/// system signs with an offline key held only by the build plane; that is out
/// of scope for the local POC and called out in the build plan.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    entries: BTreeMap<Hash, Entry>,
    revoked: std::collections::BTreeSet<Hash>,
    /// Stand-in signature over the canonical body.
    pub signature: Option<String>,
}

/// Why an exec was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecDenied {
    #[error("unattested hash: {0} is not present in the manifest")]
    Unattested(Hash),
    #[error("revoked hash: {0} was revoked and can no longer execute")]
    Revoked(Hash),
}

impl Manifest {
    pub fn new() -> Self {
        Manifest::default()
    }

    /// Admit an artifact. Returns the prior entry for this hash, if any.
    pub fn admit(&mut self, entry: Entry) -> Option<Entry> {
        self.signature = None; // body changed; re-sign required
        self.entries.insert(entry.hash.clone(), entry)
    }

    /// Revoke a hash fleet-wide. Idempotent.
    pub fn revoke(&mut self, hash: &Hash) {
        self.signature = None;
        self.revoked.insert(hash.clone());
    }

    pub fn is_revoked(&self, hash: &Hash) -> bool {
        self.revoked.contains(hash)
    }

    pub fn get(&self, hash: &Hash) -> Option<&Entry> {
        self.entries.get(hash)
    }

    /// Resolve a path-style alias to its attested entry, if any.
    pub fn resolve_alias(&self, alias: &str) -> Option<&Entry> {
        self.entries.values().find(|e| e.alias == alias)
    }

    /// The exec-by-hash gate. An exec is permitted iff the hash is attested and
    /// not revoked. Revocation is checked first so a revoked-but-still-listed
    /// hash is refused.
    pub fn permit_exec(&self, hash: &Hash) -> Result<&Entry, ExecDenied> {
        if self.is_revoked(hash) {
            return Err(ExecDenied::Revoked(hash.clone()));
        }
        self.entries
            .get(hash)
            .ok_or_else(|| ExecDenied::Unattested(hash.clone()))
    }

    /// Canonical body bytes (deterministic — BTree ordering) for signing.
    pub fn canonical_body(&self) -> Vec<u8> {
        // entries + revoked, without the signature field.
        let mut tmp = self.clone();
        tmp.signature = None;
        serde_json::to_vec(&tmp).expect("manifest serializes")
    }

    /// Stand-in signing: record a hash of the canonical body. A real build plane
    /// replaces this with an offline asymmetric signature.
    pub fn sign_standin(&mut self) {
        let body = self.canonical_body();
        self.signature = Some(Hash::of(&body).0);
    }

    /// Verify the stand-in signature matches the current body.
    pub fn verify_standin(&self) -> bool {
        match &self.signature {
            None => false,
            Some(sig) => *sig == Hash::of(&self.canonical_body()).0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Whether a piece of input carries taint (was born in the cell / came from
/// outside the attestation gate). Mirrors the many channels named in the build
/// plan — this POC models file and argv-string channels explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// A file the cell is being asked to run/interpret, with its lane.
    File(Lane),
    /// An inline string argument, e.g. `python -c "<...>"`. Its lane.
    ArgString(Lane),
    /// No interpreted input (e.g. `ls`).
    None,
}

/// The laundering ban, as a pure function.
///
/// Given the entry being exec'd and the input it is being fed, decide the lane
/// the invocation actually runs in. An attested (tool-lane) interpreter fed
/// tainted (data-lane) input is **demoted to the data lane for that call** —
/// `python evil.py` and `python -c "<tainted>"` both run in the agent lane even though
/// python itself is attested.
pub fn resolve_exec_lane(entry: &Entry, input: Input) -> Lane {
    let tainted_input = matches!(
        input,
        Input::File(Lane::Data) | Input::ArgString(Lane::Data)
    );
    if entry.author == Author::Agent {
        // Agent-authored code never carries tool-lane authority, however it was
        // built. Compiling it is not a way to launder it: `rustc` fed agent
        // source is `python` fed agent source with the interpretation moved
        // earlier, and the ban has to catch both or it catches neither.
        Lane::Data
    } else if entry.interpreter && tainted_input {
        Lane::Data // demotion
    } else if entry.tier == Tier::Unsealed {
        // Unsealed artifacts never carry tool-lane authority.
        Lane::Data
    } else {
        Lane::Tool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(alias: &str, body: &[u8], interp: bool, tier: Tier) -> Entry {
        Entry {
            alias: alias.into(),
            hash: Hash::of(body),
            tier,
            interpreter: interp,
            author: Author::Host,
            recipe: None,
        }
    }

    #[test]
    fn agent_authored_code_never_reaches_the_tool_lane() {
        // The laundering route this closes: an agent writes source, we compile
        // it hermetically, and the Forged tier would otherwise hand the result
        // full authority. `rustc` fed agent source is `python` fed agent source
        // with the interpretation moved earlier.
        let mut written = tool("/agent/program", b"from agent source", false, Tier::Forged);
        written.author = Author::Agent;
        assert_eq!(resolve_exec_lane(&written, Input::None), Lane::Data);

        // Byte-identical, host-authored, at the same tier: tool lane. So the
        // author bit is what decided it, not the tier or the interpreter flag.
        let host = tool("/usr/bin/ls", b"from agent source", false, Tier::Forged);
        assert_eq!(resolve_exec_lane(&host, Input::None), Lane::Tool);
    }

    #[test]
    fn author_defaults_to_host_for_manifests_written_before_the_field() {
        let e: Entry = serde_json::from_str(
            r#"{"alias":"/usr/bin/ls","hash":"blake3:ab","tier":"Verified","interpreter":false}"#,
        )
        .expect("legacy entry parses");
        assert_eq!(e.author, Author::Host);
    }

    #[test]
    fn hash_is_stable_and_prefixed() {
        let a = Hash::of(b"hello");
        let b = Hash::of(b"hello");
        assert_eq!(a, b);
        assert!(a.0.starts_with("blake3:"));
        assert_ne!(Hash::of(b"hello"), Hash::of(b"world"));
    }

    #[test]
    fn exec_by_hash_gate() {
        let mut m = Manifest::new();
        let py = tool("/usr/bin/python", b"python-bytes", true, Tier::Forged);
        m.admit(py.clone());

        // attested hash runs
        assert!(m.permit_exec(&py.hash).is_ok());
        // unknown hash refused
        let ghost = Hash::of(b"never-admitted");
        assert_eq!(
            m.permit_exec(&ghost).unwrap_err(),
            ExecDenied::Unattested(ghost)
        );
    }

    #[test]
    fn revocation_is_immediate_and_wins_over_listing() {
        let mut m = Manifest::new();
        let curl = tool("/usr/bin/curl", b"curl-bytes", false, Tier::Verified);
        m.admit(curl.clone());
        assert!(m.permit_exec(&curl.hash).is_ok());

        m.revoke(&curl.hash);
        // still listed in entries, but revocation wins
        assert!(m.get(&curl.hash).is_some());
        assert_eq!(
            m.permit_exec(&curl.hash).unwrap_err(),
            ExecDenied::Revoked(curl.hash)
        );
    }

    #[test]
    fn alias_resolves_but_authority_is_the_hash() {
        let mut m = Manifest::new();
        let py = tool("/usr/bin/python", b"python-bytes", true, Tier::Forged);
        m.admit(py.clone());
        let resolved = m.resolve_alias("/usr/bin/python").unwrap();
        assert_eq!(resolved.hash, py.hash);
        assert!(m.resolve_alias("/usr/bin/nope").is_none());
    }

    #[test]
    fn laundering_ban_demotes_interpreter_on_tainted_file() {
        let py = tool("/usr/bin/python", b"python-bytes", true, Tier::Forged);
        // python evil.py  (evil.py is data-lane)
        assert_eq!(resolve_exec_lane(&py, Input::File(Lane::Data)), Lane::Data);
        // python trusted_stdlib.py  (a tool-lane file) stays tool
        assert_eq!(resolve_exec_lane(&py, Input::File(Lane::Tool)), Lane::Tool);
    }

    #[test]
    fn laundering_ban_covers_arg_string_channel() {
        let py = tool("/usr/bin/python", b"python-bytes", true, Tier::Forged);
        // python -c "<tainted>"  — the sharp channel that file-only tracking misses
        assert_eq!(
            resolve_exec_lane(&py, Input::ArgString(Lane::Data)),
            Lane::Data
        );
    }

    #[test]
    fn non_interpreter_keeps_tool_lane_even_with_data_arg() {
        // `ls somefile` does not *interpret* the file, so no demotion.
        let ls = tool("/usr/bin/ls", b"ls-bytes", false, Tier::Forged);
        assert_eq!(resolve_exec_lane(&ls, Input::File(Lane::Data)), Lane::Tool);
    }

    #[test]
    fn unsealed_never_carries_tool_authority() {
        let x = tool("/usr/bin/x", b"x", false, Tier::Unsealed);
        assert_eq!(resolve_exec_lane(&x, Input::None), Lane::Data);
    }

    #[test]
    fn signature_roundtrip() {
        let mut m = Manifest::new();
        m.admit(tool("/usr/bin/python", b"py", true, Tier::Forged));
        assert!(!m.verify_standin(), "unsigned manifest must not verify");
        m.sign_standin();
        assert!(m.verify_standin());
        // mutating the body invalidates the signature
        m.admit(tool("/usr/bin/node", b"node", true, Tier::Verified));
        assert!(!m.verify_standin());
    }
}
