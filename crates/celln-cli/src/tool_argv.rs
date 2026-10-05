//! Reviewed argv bindings of borrowed commands, for the scoped receiver.
//!
//! A `celln.argv/v1` tool's argv binding decides how a model's validated
//! arguments become a command line. On the fleet path it travels inside the
//! node's own reviewed native template. A scoped (mediated) run builds its
//! worker template from signed catalogue material instead, which names the
//! tool's executable and schemas but carries no binding. The binding therefore
//! comes from this node's authority root, where `starter-configure` records it
//! from the operator-approved package: never from a request, a decision or any
//! other caller-supplied bytes. A material whose exact path, executable and
//! schemas this node never reviewed has no binding and is refused.
use anyhow::{ensure, Result};
use celln_manifest::Hash;
use pilot::json_harness::Argv;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const API_VERSION: &str = "celln.reviewed-argv-tool/v1";
const DIRECTORY: &str = "tool-argv";
const MAX_RECORD_BYTES: usize = 65536;

/// One reviewed binding and the exact tool identity it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    api_version: String,
    path: String,
    hash: String,
    input_schema: String,
    output_schema: String,
    argv: Argv,
}

/// The exact identity a binding is looked up by.
pub(crate) struct Identity<'a> {
    pub path: &'a str,
    pub hash: &'a str,
    pub input_schema: &'a str,
    pub output_schema: &'a str,
}

impl Identity<'_> {
    fn file(&self, root: &Path) -> PathBuf {
        let key = Hash::of(
            serde_json::to_string(&[self.path, self.hash, self.input_schema, self.output_schema])
                .expect("strings serialize")
                .as_bytes(),
        );
        root.join(DIRECTORY).join(format!("{}.json", &key.0[7..]))
    }

    fn record(&self, argv: &Argv) -> Record {
        Record {
            api_version: API_VERSION.into(),
            path: self.path.into(),
            hash: self.hash.into(),
            input_schema: self.input_schema.into(),
            output_schema: self.output_schema.into(),
            argv: argv.clone(),
        }
    }
}

/// Records a reviewed binding. The same binding may be recorded again (one
/// package configures several backends); a different binding for the same
/// identity is refused rather than replaced.
pub(crate) fn publish(root: &Path, identity: &Identity<'_>, argv: &Argv) -> Result<()> {
    let directory = root.join(DIRECTORY);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let path = identity.file(root);
    let bytes = serde_json::to_vec(&identity.record(argv))?;
    if path.try_exists()? {
        ensure!(
            read(&path)? == bytes,
            "a different argv binding is already recorded for {}",
            identity.path
        );
        return Ok(());
    }
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(&path) {
        Ok(_) => {}
        // A concurrent configuration recorded it first: it must agree.
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => ensure!(
            read(&path)? == bytes,
            "a different argv binding is already recorded for {}",
            identity.path
        ),
        Err(e) => return Err(e.error.into()),
    }
    fs::File::open(&directory)?.sync_all()?;
    Ok(())
}

/// The reviewed binding of exactly this tool identity, if this node has one.
pub(crate) fn lookup(root: &Path, identity: &Identity<'_>) -> Result<Argv, String> {
    let bytes =
        read(&identity.file(root)).map_err(|_| "argv tool binding was never reviewed here")?;
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|_| "reviewed argv binding unreadable")?;
    // The file name is only an index: the record itself must name exactly
    // this identity.
    if record != identity.record(&record.argv) {
        return Err("reviewed argv binding belongs to another tool".into());
    }
    Ok(record.argv)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "regular binding record required"
    );
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_RECORD_BYTES, "oversized binding record");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity<'a>(path: &'a str, hash: &'a str) -> Identity<'a> {
        Identity {
            path,
            hash,
            input_schema: "blake3:in",
            output_schema: "blake3:out",
        }
    }

    #[test]
    fn a_binding_is_found_only_by_its_exact_reviewed_identity() {
        let root = tempfile::tempdir().unwrap();
        let grep = Argv {
            args: vec!["grep".into(), "-e".into(), "{pattern}".into()],
            stdin: Some("text".into()),
        };
        publish(root.path(), &identity("/grep", "blake3:a"), &grep).unwrap();
        // Recording the same binding again (another backend) is a no-op.
        publish(root.path(), &identity("/grep", "blake3:a"), &grep).unwrap();
        assert_eq!(
            lookup(root.path(), &identity("/grep", "blake3:a")).unwrap(),
            grep
        );
        for other in [identity("/grep", "blake3:b"), identity("/sed", "blake3:a")] {
            assert!(lookup(root.path(), &other).is_err());
        }
        let mut schema = identity("/grep", "blake3:a");
        schema.input_schema = "blake3:other";
        assert!(lookup(root.path(), &schema).is_err());
        // A different binding for a reviewed identity is never replaced.
        let shell = Argv {
            args: vec!["-c".into(), "{pattern}".into()],
            stdin: None,
        };
        assert!(publish(root.path(), &identity("/grep", "blake3:a"), &shell).is_err());
        assert_eq!(
            lookup(root.path(), &identity("/grep", "blake3:a")).unwrap(),
            grep
        );
    }

    #[test]
    fn a_record_moved_to_another_identity_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let argv = Argv {
            args: vec!["cat".into()],
            stdin: Some("text".into()),
        };
        publish(root.path(), &identity("/cat", "blake3:a"), &argv).unwrap();
        let from = identity("/cat", "blake3:a").file(root.path());
        let to = identity("/sh", "blake3:a").file(root.path());
        fs::rename(from, &to).unwrap();
        assert!(lookup(root.path(), &identity("/sh", "blake3:a")).is_err());
    }
}
