//! `metadata_v3`: see `ethswarm_fuzz::metadata_v3`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::metadata_v3(data));
