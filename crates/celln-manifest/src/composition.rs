//! Deterministic signed-source graph composition; no I/O or authority defaults.
use super::{Closure, Member, SignedClosure};
use crate::Hash;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub hash: String,
    /// Exact original JSON bytes, not a reserialized descriptor identity.
    pub descriptor: String,
}

impl Source {
    pub fn parse(&self) -> Result<SignedClosure, String> {
        if self.descriptor.len() > 262144 || Hash::of(self.descriptor.as_bytes()).0 != self.hash {
            return Err("composition source identity or byte limit mismatch".into());
        }
        let signed: SignedClosure =
            serde_json::from_str(&self.descriptor).map_err(|_| "invalid composition source")?;
        // No recursive/nested composition: bounded provenance stays directly
        // inspectable, and an input cannot smuggle a second authority graph.
        if signed.closure.api_version != "celln.dev/closure-v1"
            || !signed.closure.sources.is_empty()
        {
            return Err("composition requires original v1 signed sources".into());
        }
        signed.verify(&BTreeSet::from([signed.publisher.clone()]))?;
        Ok(signed)
    }
}

/// Runtime first, followed by explicitly selected tool closures. Shared members
/// must agree in bytes AND dependencies. No relocation or host library lookup.
/// This checks signatures, not caller authorization: the host must independently
/// authorize every source publisher and check current revocation policy.
pub fn compose(sources: Vec<Source>, toolfs: &Hash) -> Result<Closure, String> {
    if sources.is_empty() || sources.len() > 17 || !super::hash(&toolfs.0) {
        return Err("composition requires 1..17 sources and a filesystem hash".into());
    }
    let source_bytes = serde_json::to_vec(&sources).map_err(|_| "invalid sources")?;
    if source_bytes.len() > 196608 {
        return Err("composition source envelope exceeds 192 KiB".into());
    }
    let signed = sources
        .iter()
        .map(Source::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let mut roots = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for (source, descriptor) in sources.iter().zip(&signed) {
        if !roots.insert(descriptor.closure.entrypoint.clone()) || !identities.insert(&source.hash)
        {
            return Err("duplicate composition source or entrypoint".into());
        }
    }
    let mut members: BTreeMap<String, Member> = BTreeMap::new();
    for source in &signed {
        for (path, member) in &source.closure.members {
            if roots.contains(path) && path != &source.closure.entrypoint {
                return Err("selected entrypoint collides with another source dependency".into());
            }
            if let Some(existing) = members.get(path) {
                if existing != member {
                    return Err("composition member hash or dependency collision".into());
                }
            } else {
                members.insert(path.clone(), member.clone());
                if members.len() > 256 {
                    return Err("composed graph exceeds 256 members".into());
                }
            }
        }
    }
    let entrypoint = signed[0].closure.entrypoint.clone();
    for path in members.keys() {
        let mut parent = path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if members.contains_key(prefix) {
                return Err("composition file collides with a parent directory".into());
            }
            parent = prefix;
        }
    }
    members
        .get_mut(&entrypoint)
        .unwrap()
        .dependencies
        .extend(signed.iter().skip(1).map(|s| s.closure.entrypoint.clone()));
    let composed = Closure {
        api_version: "celln.dev/closure-v2".into(),
        toolfs: toolfs.0.clone(),
        entrypoint,
        interpreter: signed.iter().any(|s| s.closure.interpreter),
        members,
        sources,
    };
    if serde_json::to_vec(&composed)
        .map_err(|_| "invalid composition")?
        .len()
        > 262144 - 512
    {
        return Err("composed descriptor exceeds signed delivery envelope".into());
    }
    Ok(composed)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(path: &str, library: &[u8], seed: u8) -> Source {
        let members = BTreeMap::from([
            (
                path.into(),
                Member {
                    hash: Hash::of(path.as_bytes()).0,
                    dependencies: BTreeSet::from(["/lib/shared.so".into()]),
                },
            ),
            (
                "/lib/shared.so".into(),
                Member {
                    hash: Hash::of(library).0,
                    dependencies: BTreeSet::new(),
                },
            ),
        ]);
        let signed = Closure {
            api_version: "celln.dev/closure-v1".into(),
            toolfs: Hash::of(path.as_bytes()).0,
            entrypoint: path.into(),
            interpreter: false,
            members,
            sources: vec![],
        }
        .sign(&[seed; 32])
        .unwrap();
        let descriptor = serde_json::to_string_pretty(&signed).unwrap();
        Source {
            hash: Hash::of(descriptor.as_bytes()).0,
            descriptor,
        }
    }

    #[test]
    fn composition_preserves_sources_graph_and_independent_publishers() {
        let sources = vec![
            source("/harness", b"library", 1),
            source("/tool", b"library", 2),
        ];
        let mut publishers: BTreeSet<_> = sources
            .iter()
            .map(|s| s.parse().unwrap().publisher)
            .collect();
        let input_publisher = sources[1].parse().unwrap().publisher;
        let closure = compose(sources, &Hash::of(b"new filesystem")).unwrap();
        assert_eq!(closure.members.len(), 3);
        assert!(closure.members["/harness"].dependencies.contains("/tool"));
        let signed = closure.sign(&[3; 32]).unwrap();
        publishers.insert(signed.publisher.clone());
        signed.verify(&publishers).unwrap();
        publishers.remove(&input_publisher);
        assert!(
            signed.verify(&publishers).is_err(),
            "composer signature cannot replace source approval"
        );
        let mut tampered = signed.clone();
        publishers.insert(input_publisher);
        tampered.closure.sources[0].descriptor.push(' ');
        assert!(tampered.verify(&publishers).is_err());
    }

    #[test]
    fn conflicting_graphs_nested_inputs_and_downgraded_taint_refuse() {
        let runtime = source("/harness", b"library", 1);
        assert!(compose(
            vec![runtime.clone(), source("/tool", b"different", 2)],
            &Hash::of(b"fs")
        )
        .is_err());
        assert!(compose(vec![runtime.clone(), runtime.clone()], &Hash::of(b"fs")).is_err());
        assert!(compose(
            vec![runtime.clone(), source("/harness/child", b"library", 2)],
            &Hash::of(b"fs")
        )
        .is_err());
        let mut tool = source("/tool", b"library", 2).parse().unwrap().closure;
        tool.interpreter = true;
        let descriptor = serde_json::to_string(&tool.sign(&[2; 32]).unwrap()).unwrap();
        let tainted = Source {
            hash: Hash::of(descriptor.as_bytes()).0,
            descriptor,
        };
        let mut composed = compose(vec![runtime.clone(), tainted], &Hash::of(b"fs")).unwrap();
        assert!(composed.interpreter);
        composed.interpreter = false;
        assert!(composed.sign(&[3; 32]).is_err());
        let signed = compose(vec![runtime], &Hash::of(b"fs"))
            .unwrap()
            .sign(&[3; 32])
            .unwrap();
        let descriptor = serde_json::to_string(&signed).unwrap();
        assert!(Source {
            hash: Hash::of(descriptor.as_bytes()).0,
            descriptor
        }
        .parse()
        .is_err());
    }

    #[test]
    fn legacy_signature_encoding_remains_unchanged_and_v1_cannot_hide_sources() {
        let original = source("/harness", b"library", 1);
        let signed = original.parse().unwrap();
        assert!(!serde_json::to_string(&signed).unwrap().contains("sources"));
        let mut illegal = signed.closure;
        illegal.sources.push(original);
        assert!(illegal.sign(&[1; 32]).is_err());
    }
}
