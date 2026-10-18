//! `rpc_chunk`: see `ethswarm_fuzz::rpc_chunk`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::rpc_chunk(data));
