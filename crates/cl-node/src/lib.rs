//! cl-node: the launcher of the eight services. It generates their systemd units ([`units`])
//! and, for containers without systemd, runs them as its children ([`launch`], Linux). It holds
//! no state. It links no service crate (ADR-001): everything it knows about a service is in
//! [`units::Service`].

pub mod cli;
#[cfg(target_os = "linux")]
pub mod launch;
pub mod units;
