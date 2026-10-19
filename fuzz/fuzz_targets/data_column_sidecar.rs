//! `data_column_sidecar`: see `ethswarm_fuzz::data_column_sidecar`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::data_column_sidecar(data));
