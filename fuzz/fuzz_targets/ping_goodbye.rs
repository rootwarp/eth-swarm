//! `ping_goodbye`: see `ethswarm_fuzz::ping_goodbye`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::ping_goodbye(data));
