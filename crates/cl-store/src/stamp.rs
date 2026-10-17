//! The read stamp every cl-store response carries, and the client that insists on it
//! ([`StoreReader`], which also applies the envelope rules and a message limit).
//!
//! cl-store follows cl-chain's sequenced head events, so a head read can be one write behind.
//! `ReadMeta (as_of_seq, as_of_root, as_of_slot)` names the chain head event the read was
//! opened after; callers compare it with chain's latest event to see the lag and use the root
//! to see a reorg between reads. A response without the full stamp cannot be placed and is a
//! contract violation (`store.proto`).
//!
//! proto3 gives scalar fields no presence, so a missing field reads as its zero value:
//! `as_of_seq` 0 (event seqs start at 1), an `as_of_root` that is not 32 bytes, and
//! `as_of_slot` 0 all count as missing. A head at slot 0 therefore cannot be stamped; that is
//! only a network whose genesis is at Fulu, before its first block.

use ethswarm_proto::common::Envelope;
use ethswarm_proto::store::{self as pb, store_service_client::StoreServiceClient, ReadMeta};
use ipc::envelope::Envelopes;
use ipc::frame::{HelloField, InFrame, Inbound};
use ipc::{ContractError, Link};
use tonic::codegen::{Body, Bytes, StdError};

/// `Root` length.
const ROOT_BYTES: usize = 32;

/// A store response (or stream body) with a read stamp.
pub trait Stamped {
    fn read_meta(&self) -> Option<&ReadMeta>;
}

macro_rules! stamped {
    ($($ty:ident),* $(,)?) => {
        $(impl Stamped for pb::$ty {
            fn read_meta(&self) -> Option<&ReadMeta> {
                self.meta.as_ref()
            }
        })*
    };
}

stamped!(
    GetBlockResponse,
    GetStateResponse,
    GetPayloadEnvelopeResponse,
    GetChainHeadResponse,
    GetDataColumnsResponseBody,
    GetBlocksByRangeResponseBody,
    GetDataColumnsByRangeResponseBody,
);

/// The stamp of `response`, or the contract violation of a missing one.
pub fn check_read_meta<T: Stamped>(response: &T) -> Result<&ReadMeta, ContractError> {
    let meta = response
        .read_meta()
        .ok_or_else(|| ContractError::violation("store response has no ReadMeta"))?;
    if meta.as_of_seq == 0 {
        return Err(ContractError::violation("ReadMeta has no as_of_seq"));
    }
    if meta.as_of_root.len() != ROOT_BYTES {
        return Err(ContractError::violation(format!(
            "ReadMeta as_of_root is {} bytes, not {ROOT_BYTES}",
            meta.as_of_root.len()
        )));
    }
    if meta.as_of_slot == 0 {
        return Err(ContractError::violation("ReadMeta has no as_of_slot"));
    }
    Ok(meta)
}

/// `MAX_PAYLOAD_SIZE` (`phase0/p2p-interface.md`, 10 MiB): the largest SSZ object in a store
/// response envelope (`store.proto`).
pub const MAX_SSZ_BYTES: usize = 10_485_760;

/// The largest JSON sub-resource in a `GetStateResponse` (16 MiB, `store.proto`).
pub const MAX_JSON_BYTES: usize = 16_777_216;

/// Room for everything around the largest field: tags, lengths, the read stamp, the envelope's
/// root, digest and trace id, and an `Error` detail (at most 1,024 bytes).
pub const PROTOBUF_OVERHEAD_BYTES: usize = 64 * 1024;

/// The default message limit of a [`StoreReader`]: the largest documented response field plus
/// [`PROTOBUF_OVERHEAD_BYTES`]. tonic's own default (4 MiB) would refuse a valid 10 MiB block.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = MAX_JSON_BYTES + PROTOBUF_OVERHEAD_BYTES;

/// A store response or streamed body with at most one envelope.
pub trait StoreItem: Stamped {
    /// The envelope field, if the message has one.
    fn envelope_slot(&mut self) -> Option<&mut Option<Envelope>>;
}

macro_rules! store_items {
    ($($ty:ident => $field:ident),* $(,)?) => {
        $(impl StoreItem for pb::$ty {
            fn envelope_slot(&mut self) -> Option<&mut Option<Envelope>> {
                Some(&mut self.$field)
            }
        })*
    };
}

store_items!(
    GetBlockResponse => block,
    GetStateResponse => state,
    GetPayloadEnvelopeResponse => envelope,
    GetDataColumnsResponseBody => column,
    GetBlocksByRangeResponseBody => item,
    GetDataColumnsByRangeResponseBody => column,
);

impl StoreItem for pb::GetChainHeadResponse {
    fn envelope_slot(&mut self) -> Option<&mut Option<Envelope>> {
        None
    }
}

/// A `StoreService` client that holds every response to the contract: the full read stamp on
/// each response and streamed body, and the envelope rules on each envelope (through `link`):
/// `seq` 0 on a unary response and strictly from 1 on a stream, a zero `payload_type` fails the
/// call, an unknown type or a mismatched fork digest drops the envelope (the field comes back
/// empty). Streams also get the hello exchange and frame discipline.
#[derive(Clone, Debug)]
pub struct StoreReader<T> {
    inner: StoreServiceClient<T>,
    link: Link,
}

impl<T> StoreReader<T>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// A reader with [`DEFAULT_MAX_MESSAGE_BYTES`].
    pub fn new(transport: T, link: Link) -> Self {
        Self::with_max_message_bytes(transport, link, DEFAULT_MAX_MESSAGE_BYTES)
    }

    /// A reader that refuses (as a contract violation) any message over `max_message_bytes`.
    pub fn with_max_message_bytes(transport: T, link: Link, max_message_bytes: usize) -> Self {
        Self {
            inner: StoreServiceClient::new(transport)
                .max_decoding_message_size(max_message_bytes)
                .max_encoding_message_size(max_message_bytes),
            link,
        }
    }

    fn refused(&self, err: ContractError) -> ContractError {
        self.link.record(&err);
        err
    }

    /// Stamp, then the envelope rules of a unary call.
    fn unary<R: StoreItem>(
        &self,
        response: Result<tonic::Response<R>, tonic::Status>,
    ) -> Result<R, ContractError> {
        let mut response = response
            .map_err(|s| ContractError::from_status(&s))?
            .into_inner();
        check_read_meta(&response).map_err(|e| self.refused(e))?;
        if let Some(slot) = response.envelope_slot() {
            if let Some(envelope) = slot.as_ref() {
                let dropped = self.link.check_unary(&[envelope])?;
                if dropped.first().is_some_and(Option::is_some) {
                    *slot = None;
                }
            }
        }
        Ok(response)
    }

    /// The hello exchange, then every body: stamp and envelope rules.
    async fn stream<M>(
        &self,
        response: Result<tonic::Response<tonic::Streaming<M>>, tonic::Status>,
    ) -> Result<Vec<M::Body>, ContractError>
    where
        M: InFrame,
        M::Body: Envelopes + StoreItem,
    {
        let stream = response
            .map_err(|s| ContractError::from_status(&s))?
            .into_inner();
        let mut guarded = self.link.open(Inbound::from_server(stream)).await?;
        let mut bodies = Vec::new();
        while let Some(accepted) = guarded.body().await? {
            let mut body = accepted.body;
            check_read_meta(&body).map_err(|e| self.refused(e))?;
            if !accepted.dropped.is_empty() {
                if let Some(slot) = body.envelope_slot() {
                    *slot = None;
                }
            }
            bodies.push(body);
        }
        Ok(bodies)
    }

    fn with_hello<R: HelloField>(&self, mut request: R) -> R {
        request.set_hello_field(Some(self.link.local().clone()));
        request
    }

    pub async fn get_block(
        &mut self,
        request: pb::GetBlockRequest,
    ) -> Result<pb::GetBlockResponse, ContractError> {
        let r = self.inner.get_block(request).await;
        self.unary(r)
    }

    pub async fn get_state(
        &mut self,
        request: pb::GetStateRequest,
    ) -> Result<pb::GetStateResponse, ContractError> {
        let r = self.inner.get_state(request).await;
        self.unary(r)
    }

    pub async fn get_payload_envelope(
        &mut self,
        request: pb::GetPayloadEnvelopeRequest,
    ) -> Result<pb::GetPayloadEnvelopeResponse, ContractError> {
        let r = self.inner.get_payload_envelope(request).await;
        self.unary(r)
    }

    pub async fn get_chain_head(&mut self) -> Result<pb::GetChainHeadResponse, ContractError> {
        let r = self.inner.get_chain_head(pb::GetChainHeadRequest {}).await;
        self.unary(r)
    }

    /// Every body of the stream; the request's hello is set from the link.
    pub async fn get_data_columns(
        &mut self,
        request: pb::GetDataColumnsRequest,
    ) -> Result<Vec<pb::GetDataColumnsResponseBody>, ContractError> {
        let request = self.with_hello(request);
        let r = self.inner.get_data_columns(request).await;
        self.stream(r).await
    }

    /// Every body of the stream; the request's hello is set from the link.
    pub async fn get_blocks_by_range(
        &mut self,
        request: pb::GetBlocksByRangeRequest,
    ) -> Result<Vec<pb::GetBlocksByRangeResponseBody>, ContractError> {
        let request = self.with_hello(request);
        let r = self.inner.get_blocks_by_range(request).await;
        self.stream(r).await
    }

    /// Every body of the stream; the request's hello is set from the link.
    pub async fn get_data_columns_by_range(
        &mut self,
        request: pb::GetDataColumnsByRangeRequest,
    ) -> Result<Vec<pb::GetDataColumnsByRangeResponseBody>, ContractError> {
        let request = self.with_hello(request);
        let r = self.inner.get_data_columns_by_range(request).await;
        self.stream(r).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::common::ErrorCode;

    fn meta(seq: u64, root: usize, slot: u64) -> Option<ReadMeta> {
        Some(ReadMeta {
            as_of_seq: seq,
            as_of_root: vec![7; root],
            as_of_slot: slot,
            ..Default::default()
        })
    }

    #[test]
    fn full_stamp_is_accepted() {
        let r = pb::GetBlockResponse {
            meta: meta(3, 32, 100),
            ..Default::default()
        };
        assert_eq!(check_read_meta(&r).unwrap().as_of_seq, 3);
    }

    #[test]
    fn any_missing_part_is_a_contract_violation() {
        for (what, m) in [
            ("no meta", None),
            ("no seq", meta(0, 32, 100)),
            ("no root", meta(3, 0, 100)),
            ("short root", meta(3, 31, 100)),
            ("no slot", meta(3, 32, 0)),
        ] {
            let r = pb::GetDataColumnsResponseBody {
                meta: m,
                ..Default::default()
            };
            let err = check_read_meta(&r).unwrap_err();
            assert_eq!(err.code(), ErrorCode::ContractViolation, "{what}");
        }
    }
}
