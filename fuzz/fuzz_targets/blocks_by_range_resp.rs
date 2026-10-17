//! `blocks_by_range_resp`: see `ethswarm_fuzz::blocks_by_range_resp`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    ethswarm_fuzz::blocks_by_range_resp(data);
});
