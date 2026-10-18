//! `enr_fields`: see `ethswarm_fuzz::enr_fields`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::enr_fields(data));
