#![allow(
    clippy::result_large_err,
    clippy::collapsible_if,
    clippy::manual_flatten,
    clippy::derivable_impls
)]

pub mod omni_proto {
    tonic::include_proto!("omni.messaging.v1");
}

pub mod binary_audit;
pub mod mem_audit;
pub mod ebpf_tracer;
pub mod agent;
