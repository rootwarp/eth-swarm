//! `columns_by_range_req`: see `ethswarm_fuzz::columns_by_range_req`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::columns_by_range_req(data));
