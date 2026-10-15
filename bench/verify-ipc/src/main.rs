//! `verify-ipc server <sock>` / `verify-ipc bench`.
use std::time::{Duration, Instant};

use anyhow::Result;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tonic::transport::{Endpoint, Server, Uri};
use verify_ipc::pb::verify_client::VerifyClient;
use verify_ipc::pb::verify_server::{Verify, VerifyServer};
use verify_ipc::pb::{BlobBatch, VerifyBatchRequest, VerifyBatchResponse};
use verify_ipc::{resolve, verify, Fixture, Mode};

const REGISTRY: usize = 4096;
const BATCHES: [usize; 4] = [1, 8, 64, 256];

struct Svc {
    cache: Vec<blst::min_pk::PublicKey>,
}

fn handle(cache: &[blst::min_pk::PublicKey], req: &VerifyBatchRequest) -> VerifyBatchResponse {
    if !req.resolve {
        // transport-only: decode happened, skip key/sig work
        return VerifyBatchResponse {
            valid: true,
            count: req.sets.len() as u32,
        };
    }
    let valid = match resolve(&req.sets, cache) {
        Ok(r) => !req.verify || verify(&r),
        Err(_) => false,
    };
    VerifyBatchResponse {
        valid,
        count: req.sets.len() as u32,
    }
}

#[tonic::async_trait]
impl Verify for Svc {
    async fn verify_batch(
        &self,
        r: tonic::Request<VerifyBatchRequest>,
    ) -> Result<tonic::Response<VerifyBatchResponse>, tonic::Status> {
        Ok(tonic::Response::new(handle(&self.cache, r.get_ref())))
    }
    async fn echo(
        &self,
        r: tonic::Request<BlobBatch>,
    ) -> Result<tonic::Response<VerifyBatchResponse>, tonic::Status> {
        Ok(tonic::Response::new(VerifyBatchResponse {
            valid: true,
            count: r.get_ref().payload.len() as u32,
        }))
    }
}

async fn serve(dir: String) -> Result<()> {
    let cache = Fixture::new(REGISTRY).pks;
    let raw = UnixListener::bind(format!("{dir}/raw.sock"))?;
    let raw_cache = cache.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = raw.accept().await {
            let cache = raw_cache.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let Ok(n) = s.read_u32().await else { return };
                    buf.resize(n as usize, 0);
                    if s.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let Ok(req) = VerifyBatchRequest::decode(buf.as_slice()) else {
                        return;
                    };
                    let out = handle(&cache, &req).encode_to_vec();
                    if s.write_u32(out.len() as u32).await.is_err()
                        || s.write_all(&out).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let uds = UnixListener::bind(format!("{dir}/grpc.sock"))?;
    Server::builder()
        .add_service(VerifyServer::new(Svc { cache }).max_decoding_message_size(64 << 20))
        .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(uds))
        .await?;
    Ok(())
}

fn pct(v: &mut [Duration], p: f64) -> f64 {
    v.sort();
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)].as_secs_f64() * 1e6
}

fn iters(b: usize) -> usize {
    (20_000 / b).clamp(200, 5000)
}

async fn bench() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("vipc-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let d = dir.to_string_lossy().to_string();
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["server", &d])
        .spawn()?;
    while !dir.join("grpc.sock").exists() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let fx = Fixture::new(REGISTRY);
    let p = d.clone();
    let ch = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let p = format!("{p}/grpc.sock");
            async move {
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(UnixStream::connect(p).await?))
            }
        }))
        .await?;
    let mut grpc = VerifyClient::new(ch).max_encoding_message_size(64 << 20);
    let mut raw = UnixStream::connect(dir.join("raw.sock")).await?;
    println!("cores={}", std::thread::available_parallelism()?.get());
    println!("transport,mode,batch,bytes_per_set,p50_us,p99_us,sets_per_s,inproc_resolve_us,blst_verify_us,ipc_pct_of_verify");
    for mode in [Mode::Index, Mode::Inline] {
        for b in BATCHES {
            let sets = fx.sets(b, mode);
            let req = VerifyBatchRequest {
                sets: sets.clone(),
                verify: false,
                resolve: false,
            };
            let bytes = req.encoded_len() as f64 / b as f64;
            // in-process baselines
            let n = iters(b).min(500);
            let t = Instant::now();
            for _ in 0..n {
                std::hint::black_box(resolve(&sets, &fx.pks).unwrap());
            }
            let res_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
            let r = resolve(&sets, &fx.pks).unwrap();
            let t = Instant::now();
            for _ in 0..n {
                assert!(verify(&r));
            }
            let ver_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
            for tr in ["grpc", "raw"] {
                let it = iters(b);
                let mut lat = Vec::with_capacity(it);
                let enc = req.encode_to_vec();
                for k in 0..it + 50 {
                    let t = Instant::now();
                    if tr == "grpc" {
                        assert_eq!(
                            grpc.verify_batch(req.clone()).await?.get_ref().count as usize,
                            b
                        );
                    } else {
                        let enc = req.encode_to_vec();
                        raw.write_u32(enc.len() as u32).await?;
                        raw.write_all(&enc).await?;
                        let n = raw.read_u32().await?;
                        let mut o = vec![0; n as usize];
                        raw.read_exact(&mut o).await?;
                    }
                    if k >= 50 {
                        lat.push(t.elapsed());
                    }
                }
                let _ = enc;
                let mean: f64 = lat.iter().map(|d| d.as_secs_f64()).sum::<f64>() / it as f64;
                let p50 = pct(&mut lat, 0.5);
                let p99 = pct(&mut lat, 0.99);
                // transport-only = RTT minus the resolve work in-process would do anyway
                let ipc = p50;
                println!("{tr},{mode:?},{b},{bytes:.1},{p50:.1},{p99:.1},{:.0},{res_us:.1},{ver_us:.1},{:.1}",
                    b as f64 / mean, 100.0 * ipc / ver_us);
            }
        }
    }
    // KZG: one column sidecar of IPC payload + cell-proof batch verify
    let echo = BlobBatch {
        payload: vec![0xab; 44_072],
    };
    let mut lat = Vec::new();
    for k in 0..2050 {
        let t = Instant::now();
        grpc.echo(echo.clone()).await?;
        if k >= 50 {
            lat.push(t.elapsed());
        }
    }
    println!(
        "grpc_echo_44072B p50_us={:.1} p99_us={:.1}",
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99)
    );
    kzg_bench();
    child.kill()?;
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

fn kzg_bench() {
    use c_kzg::{Blob, Bytes48, KzgSettings};
    let s: &KzgSettings = c_kzg::ethereum_kzg_settings(0);
    let mut rng = rand::thread_rng();
    let (mut comms, mut cells, mut proofs) = (vec![], vec![], vec![]);
    for _ in 0..21 {
        let mut b = [0u8; 131072];
        rand::RngCore::fill_bytes(&mut rng, &mut b);
        for i in (0..b.len()).step_by(32) {
            b[i] = 0;
        }
        let blob = Blob::new(b);
        let c = s.blob_to_kzg_commitment(&blob).unwrap();
        let (cs, ps) = s.compute_cells_and_kzg_proofs(&blob).unwrap();
        comms.push(Bytes48::from(*c.to_bytes().as_ref()));
        cells.push(cs[0]);
        proofs.push(Bytes48::from(*ps[0].to_bytes().as_ref()));
    }
    let idx = vec![0u64; 21];
    let t = Instant::now();
    let n = 50;
    for _ in 0..n {
        assert!(s
            .verify_cell_kzg_proof_batch(&comms, &idx, &cells, &proofs)
            .unwrap());
    }
    println!(
        "kzg_cell_batch_verify_21cells_us={:.1}",
        t.elapsed().as_secs_f64() * 1e6 / n as f64
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("server") => serve(a[2].clone()).await,
        _ => bench().await,
    }
}
