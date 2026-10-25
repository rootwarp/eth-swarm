//! The `eth2` field of a node record (EIP-778), read from the reference node's
//! `/eth/v1/node/identity`: [`cl_p2p::enr_text`], the reader that cl-p2p also reads cl-discv5's
//! own record with.

pub use cl_p2p::enr_text::eth2_fork_id;

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) use cl_p2p::testkit::{ENR_BPO2, ENR_GLOAS};
}
