//! A response that was produced in time but waits in the server's response queue past its
//! request's deadline (behind a backlog the peer has not read yet) leaves as DEADLINE_EXCEEDED,
//! still carrying the fences of the request it answers.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use cl_verify::client::bls_verdicts;
use cl_verify::proto::common::Verdict;
use cl_verify::proto::verify::verify_service_client::VerifyServiceClient;
use cl_verify::proto::verify::{verify_bls_response, BlsSet, VerifyBlsResponseBody, VerifyStatus};
use common::*;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};

/// The HTTP/2 window the client grants: the 65,535-byte protocol default (hyper's client would
/// grant 2 MiB).
const WINDOW: u32 = 65_535;

/// A channel to the harness socket whose stream and connection windows are [`WINDOW`].
async fn small_window(path: std::path::PathBuf) -> Channel {
    Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .initial_stream_window_size(WINDOW)
        .initial_connection_window_size(WINDOW)
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap()
}

/// A set whose signature does not decode: answered DECODE_ERROR at once, but still one fenced
/// result in the response.
fn undecodable(i: u8) -> BlsSet {
    BlsSet {
        signature: vec![0xff; 96],
        ..valid_set(0, i)
    }
}

/// Requests of this many sets fill the HTTP/2 window towards a client that does not read.
const FILLER_SETS: usize = 256;
/// Fillers (about 14 KiB of response each): far more than the client's window plus tonic's
/// encode buffer, and fewer than the server's response queue, so the last request's response
/// waits in that queue.
const FILLERS: u64 = 20;

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_response_queued_past_its_deadline_leaves_as_deadline_exceeded() {
    let clock = Arc::new(SteppedClock::default());
    let mut h = start_with(Options {
        cache: cache_of(1),
        clock: clock.clone(),
        ..Options::default()
    })
    .await;
    h.client = VerifyServiceClient::new(small_window(h.socket.clone()).await);
    let mut s = bls_open(&mut h).await;
    let mut out = s.outstanding();
    let mut tags = HashMap::new();
    for _ in 0..FILLERS {
        let sets = (0..FILLER_SETS).map(|i| undecodable(i as u8)).collect();
        let (tag, body) = file_bls(&mut out, bls_request(0, sets));
        tags.insert(tag.request_id, (tag, FILLER_SETS));
        s.send(bls_body(body)).await;
    }
    // Answered VALID well within its deadline, then held in the queue behind the fillers.
    let (last, body) = file_bls(&mut out, bls_request(0, vec![valid_set(0, 1)]));
    tags.insert(last.request_id, (last, 1));
    s.send(bls_body(body)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Every deadline is now past on the wall clock the server judges them by.
    clock.jump(3_600_000);

    let mut answers: HashMap<u64, VerifyBlsResponseBody> = HashMap::new();
    while answers.len() < tags.len() {
        match s.next().await.unwrap().unwrap().frame {
            Some(verify_bls_response::Frame::Body(b)) => {
                answers.insert(b.request_id, b);
            }
            other => panic!("expected a body: {other:?}"),
        }
    }
    let answer = answers.remove(&last.request_id).unwrap();
    assert_eq!(outcomes(&answer), vec![Ok(VerifyStatus::DeadlineExceeded)]);
    // Downgraded, not unfenced: it still settles against its request.
    assert_eq!(
        bls_verdicts(Ok(answer), &mut out, last, 1),
        vec![Verdict::Ignore]
    );
    assert!(!out.is_closed(), "the downgraded answer is well fenced");
    for (id, body) in answers {
        let (tag, n) = tags[&id];
        assert!(outcomes(&body)
            .iter()
            .all(|o| *o != Ok(VerifyStatus::Valid)));
        let _ = bls_verdicts(Ok(body), &mut out, tag, n);
        assert!(!out.is_closed(), "request {id}: fences kept");
    }
}
