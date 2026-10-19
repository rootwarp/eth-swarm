//! The timed req/resp codec (`cl_p2p::rpc::codec`) on one in-memory stream, as the binaries run
//! it: [`RpcCodec`] writes our request and reads its response (an outbound stream), and
//! [`InboundCodec`] reads a peer's request (an inbound stream), both under the production
//! [`Deadlines`]. The deadlines are tokio timers, so the codec runs on a current-thread runtime
//! with the time driver; an in-memory stream is always ready, so none of them can pass unless one
//! input takes seconds to decode.

use crate::{contexts, E};
use cl_p2p::rpc::codec::{Deadlines, InboundCodec, ReceivedChunk, RpcCodec, RpcRequest};
use futures::io::Cursor;
use libp2p::request_response::Codec;
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::protocols::{Protocol, Request};
use std::io;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime with the time driver")
    })
}

/// The fixture context table, shared by every codec over it.
fn fixture_table() -> &'static Arc<ContextTable> {
    static TABLE: OnceLock<Arc<ContextTable>> = OnceLock::new();
    TABLE.get_or_init(|| Arc::new(contexts().clone()))
}

/// The codec over `table`, with the production deadlines.
fn codec_over(table: &Arc<ContextTable>) -> RpcCodec<E> {
    RpcCodec::new(Arc::clone(table), Deadlines::default())
}

/// The codec over the fixture context table.
fn codec() -> RpcCodec<E> {
    codec_over(fixture_table())
}

/// Reads `wire` as the response to `request`: the codec writes the request first, which sets
/// the response's chunk limit, as on an outbound stream.
pub fn read_response(request: Request, wire: &[u8]) -> io::Result<Vec<ReceivedChunk<E>>> {
    read_response_in(fixture_table(), request, wire)
}

/// [`read_response`] with the context bytes looked up in `table`.
pub fn read_response_in(
    table: &Arc<ContextTable>,
    request: Request,
    wire: &[u8],
) -> io::Result<Vec<ReceivedChunk<E>>> {
    let protocol = request.protocol();
    let mut codec = codec_over(table);
    runtime().block_on(async {
        codec
            .write_request(
                &protocol,
                &mut Cursor::new(Vec::new()),
                RpcRequest::Valid(request),
            )
            .await
            .expect("our own request is written");
        codec.read_response(&protocol, &mut Cursor::new(wire)).await
    })
}

/// Reads `wire` as a peer's request on `protocol`, as the probe's inbound streams do.
pub fn read_request(protocol: Protocol, wire: &[u8]) -> io::Result<RpcRequest> {
    let mut codec = InboundCodec::new(codec());
    runtime().block_on(codec.read_request(&protocol, &mut Cursor::new(wire)))
}
