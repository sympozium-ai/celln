//! Read-only sealed-member verification protocol. This is not an execution
//! request and carries no path/alias fallback understood by older pilots.
use celln_manifest::{closure::Member, Hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PREFIX: &str = "CELLN:closure-members=";
pub const VERSION: &str = "celln.dev/sealed-members-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub verify_closure: Request,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: String,
    pub challenge: String,
    pub members: BTreeMap<String, Member>,
}

impl Request {
    pub fn valid(&self) -> bool {
        fn hash(s: &str) -> bool {
            s.len() == 71
                && s.starts_with("blake3:")
                && s.as_bytes()[7..]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        }
        self.version == VERSION
            && hash(&self.challenge)
            && !self.members.is_empty()
            && self.members.len() <= 256
            && self.members.iter().all(|(path, member)| {
                celln_manifest::closure::canonical_path(path)
                    && path.len() <= 256
                    && hash(&member.hash)
                    && member.dependencies.len() <= 256
                    && member
                        .dependencies
                        .iter()
                        .all(|p| self.members.contains_key(p))
            })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: String,
    pub challenge: String,
    pub request_hash: String,
    pub verified: bool,
    pub member_count: usize,
}

impl Report {
    pub fn matches(&self, request: &Envelope, bytes: &[u8]) -> bool {
        request.verify_closure.valid()
            && self.version == VERSION
            && self.challenge == request.verify_closure.challenge
            && self.request_hash == Hash::of(bytes).0
            && self.verified
            && self.member_count == request.verify_closure.members.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_binds_challenge_request_and_complete_member_set() {
        let request = Envelope {
            verify_closure: Request {
                version: VERSION.into(),
                challenge: Hash::of(b"challenge").0,
                members: BTreeMap::from([(
                    "/tool".into(),
                    Member {
                        hash: Hash::of(b"bytes").0,
                        dependencies: Default::default(),
                    },
                )]),
            },
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let mut report = Report {
            version: VERSION.into(),
            challenge: request.verify_closure.challenge.clone(),
            request_hash: Hash::of(&bytes).0,
            verified: true,
            member_count: 1,
        };
        assert!(report.matches(&request, &bytes));
        report.verified = false;
        assert!(!report.matches(&request, &bytes));
        report.verified = true;
        report.member_count = 0;
        assert!(!report.matches(&request, &bytes));
        report.member_count = 1;
        assert!(!report.matches(&request, b"different request"));
        report.challenge = Hash::of(b"replayed").0;
        assert!(!report.matches(&request, &bytes));
    }
    #[test]
    fn mixed_execution_and_verification_refuses() {
        assert!(serde_json::from_str::<Envelope>(r#"{"verify_closure":{"version":"x","challenge":"x","members":{}},"path":"/evil","alias":"/evil"}"#).is_err());
        let request = Request {
            version: VERSION.into(),
            challenge: Hash::of(b"nonce").0,
            members: BTreeMap::new(),
        };
        assert!(!request.valid());
    }
}
