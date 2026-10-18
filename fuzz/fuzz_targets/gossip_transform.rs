//! `gossip_transform`: see `ethswarm_fuzz::gossip_transform`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| ethswarm_fuzz::gossip_transform(data));
