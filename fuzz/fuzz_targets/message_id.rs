//! `message_id`: see `ethswarm_fuzz::message_id`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::message_id(data));
