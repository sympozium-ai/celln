//! Host-side Celln authorization primitives. Verification alone never bypasses
//! the dispatcher publisher/closure/ABI checks or durable ownership admission.
mod tenancy_contract;
pub mod tenancy_credentials;
pub mod tenancy_model_context;
#[cfg(target_os = "linux")]
pub mod tenancy_model_relay;
