//! `columns_by_root_req`: see `ethswarm_fuzz::columns_by_root_req`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::columns_by_root_req(data));
