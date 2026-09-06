//! Opt-in dispatcher reporting. Pilot owns the console; workload stdout and
//! stderr go through a pipe and are encoded as data, never control records.
use serde::{Deserialize, Serialize};

pub const PREFIX: &str = "CELLN:dispatch=";
pub const PROTOCOL: &str = "CELLN:dispatch-protocol=2";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    Output { bytes: Vec<u8> },
    Exit { code: i32 },
    Signal { signal: i32 },
    Failed { reason: String },
}

pub fn emit(frame: Frame) {
    println!(
        "{PREFIX}{}",
        serde_json::to_string(&frame).expect("frame serializes")
    );
}
