//! `column_contract`: see `ethswarm_fuzz::column_contract`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::column_contract(data));
