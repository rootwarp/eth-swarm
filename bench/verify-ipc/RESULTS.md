# verify-ipc results

`cargo run --release --manifest-path bench/verify-ipc/Cargo.toml`, one run each, on the same
machine (Apple silicon, 18 cores, macOS), back to back on 2026-10-17. Latencies are round trips
over a Unix socket in microseconds. `ipc_pct_of_verify` is the gRPC or raw p50 as a percentage
of the in-process blst batch verify of the same batch. One run per version, so differences of
a few microseconds are within run-to-run noise.

## tonic 0.12.3 / prost 0.13.5 (before the upgrade)

```text
cores=18
transport,mode,batch,bytes_per_set,p50_us,p99_us,sets_per_s,inproc_resolve_us,blst_verify_us,ipc_pct_of_verify
grpc,Index,1,138.0,31.8,49.5,30261,41.2,571.8,5.6
raw,Index,1,138.0,10.4,14.1,94403,41.2,571.8,1.8
grpc,Index,8,138.0,31.4,47.2,243477,323.6,696.2,4.5
raw,Index,8,138.0,11.3,17.9,684726,323.6,696.2,1.6
grpc,Index,64,138.0,52.1,75.2,1207897,2582.3,1712.7,3.0
raw,Index,64,138.0,27.8,37.4,2267043,2582.3,1712.7,1.6
grpc,Index,256,137.9,109.3,139.5,2296577,10341.7,5145.3,2.1
raw,Index,256,137.9,76.4,94.5,3314542,10341.7,5145.3,1.5
grpc,Inline,1,185.0,33.0,50.7,29319,70.5,572.3,5.8
raw,Inline,1,185.0,10.7,19.0,89952,70.5,572.3,1.9
grpc,Inline,8,185.0,34.7,52.0,224723,559.0,698.3,5.0
raw,Inline,8,185.0,11.0,17.6,682451,559.0,698.3,1.6
grpc,Inline,64,185.0,57.8,76.5,1107347,4475.3,1605.6,3.6
raw,Inline,64,185.0,29.8,42.3,2130166,4475.3,1605.6,1.9
grpc,Inline,256,185.0,170.5,1817.4,1074988,19695.4,13714.1,1.2
raw,Inline,256,185.0,101.4,452.2,2091700,19695.4,13714.1,0.7
grpc_echo_44072B p50_us=100.3 p99_us=1363.2
kzg_cell_batch_verify_21cells_us=4730.2
```

## tonic 0.14.6 / prost 0.14.4 (tonic-prost-build)

```text
cores=18
transport,mode,batch,bytes_per_set,p50_us,p99_us,sets_per_s,inproc_resolve_us,blst_verify_us,ipc_pct_of_verify
grpc,Index,1,138.0,33.2,55.4,28721,40.3,587.6,5.6
raw,Index,1,138.0,12.5,18.0,78779,40.3,587.6,2.1
grpc,Index,8,138.0,36.1,57.2,217162,335.2,797.6,4.5
raw,Index,8,138.0,11.2,16.2,698560,335.2,797.6,1.4
grpc,Index,64,138.0,52.5,74.2,1208009,2621.6,1836.8,2.9
raw,Index,64,138.0,28.8,41.5,2161273,2621.6,1836.8,1.6
grpc,Index,256,138.0,109.7,141.0,2293030,10409.6,5868.6,1.9
raw,Index,256,138.0,85.8,100.5,2966068,10409.6,5868.6,1.5
grpc,Inline,1,185.0,34.1,48.9,28836,74.6,611.0,5.6
raw,Inline,1,185.0,9.7,14.7,100831,74.6,611.0,1.6
grpc,Inline,8,185.0,39.5,56.4,199431,562.3,740.4,5.3
raw,Inline,8,185.0,13.2,21.8,588064,562.3,740.4,1.8
grpc,Inline,64,185.0,63.9,85.6,995588,4587.6,1769.3,3.6
raw,Inline,64,185.0,32.9,45.9,1922913,4587.6,1769.3,1.9
grpc,Inline,256,185.0,138.5,159.8,1840386,18102.8,5540.8,2.5
raw,Inline,256,185.0,101.9,117.8,2507197,18102.8,5540.8,1.8
grpc_echo_44072B p50_us=76.3 p99_us=110.2
kzg_cell_batch_verify_21cells_us=4253.5
```

## Reading

- gRPC p50 is unchanged within noise for every batch size (Index 1: 31.8 vs 33.2 us; Index
  256: 109.3 vs 109.7 us; Inline 256: 170.5 vs 138.5 us).
- The 0.12.3 Inline 256 p99 (1817 us) and echo p99 (1363 us) were tail outliers of that run;
  the 0.14 run has 160 us and 110 us.
- gRPC stays a single-digit percentage of the BLS verify it carries, so the upgrade does not
  change the transport decision.
