//! `status_v2`: see `ethswarm_fuzz::status_v2`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::status_v2(data));
