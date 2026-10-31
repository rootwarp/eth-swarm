# cl-engine

The ordered Engine API transport between cl-chain and one execution client. It is the only
holder of the JWT secret. It does not decode consensus types (ADR-007): a call's JSON params
are forwarded as the JSON-RPC `params`, and a result is copied back into the proto message.

`EngineStub` (`src/lib.rs`) is what `tests/contract.rs` drives (contract checks, then
`UNIMPLEMENTED`). `src/server.rs` is the `engine.v1` Unix-socket server in front of the
queue (below). The binary does not serve yet.

## JWT

`src/jwt.rs`. HS256 via `hmac` and `sha2`, header `{"alg":"HS256","typ":"JWT"}`, claim `iat`.
`alg` `none` and every other `alg` are rejected, including a token whose HMAC would match
under a different `alg`, and a header with two `alg` keys. `iat` outside ±60 s is rejected
(`authentication.md`). Tokens we produce use `iat` = now.

The secret is 32 bytes, hex-encoded (optional `0x`, optional trailing newline) in the systemd
credential `jwtsecret` (`LoadCredential=jwtsecret:<path>`, `$CREDENTIALS_DIRECTORY/jwtsecret`).
The file is opened with `O_NOFOLLOW` and checked on the open file descriptor. An owned file
must be mode `0600` or `0400` (nothing looser than `0600`) with no ACL. A root-owned file is
accepted only with systemd's read ACL, from this unit's read-only credentials mount, the same
shape as the node key. The secret is zeroized on drop. `Debug` and `Display` print
`<redacted>`. Errors and logs name the path, never the bytes.

## Capability gate

`src/capabilities.rs`. Before the first call, and again after every reconnect,
`engine_exchangeCapabilities` must list `engine_newPayloadV5` and
`engine_forkchoiceUpdatedV4`. An older method is not a substitute. The spec makes the call
optional; this crate does not. The exchange offers every method the server routes (Fulu and
Gloas versions of newPayload, forkchoiceUpdated, getPayload and getBlobs), and every other
call is checked against the list the EL returned: a method it did not list is refused
(`MissingCaps`) before anything is sent.

## Client

`src/client.rs`. hyper 1, HTTP/1.1, one connection, `Authorization: Bearer <jwt>` minted per
request (`authentication.md` says the JWT is in an HTTP header and does not name it; Bearer is
what execution clients check). The URL must be loopback (`127.0.0.0/8`, `::1`, or an
IPv4-mapped loopback address) unless `EngineEndpoint::parse` is given `allow_non_loopback`.
A response larger than the cap (48 MiB, the proto's `GetBlobs` bound) fails the call, whether
`Content-Length` says so or the body streams past it. A dial (TCP connect plus handshake) is
bounded by 1 s. Each call has a timeout:

| method | wait |
| --- | --- |
| `engine_newPayloadV5` | 6 s (`amsterdam.md`) |
| `engine_newPayloadV4` | 8 s (`prague.md`) |
| `engine_forkchoiceUpdated` | 8 s |
| `engine_getBlobs`, `engine_exchangeCapabilities` | 1 s |
| `engine_getPayload` | 1 s (ours: no spec timeout since execution-apis #958) |

A timeout is an error the caller sees, never `VALID`. JSON-RPC `id`s must match.

## Queue and reconnect

`src/queue.rs`. One worker per EL. Calls run in `seq` order, one at a time. The connection
generation starts at 1 and increases on reconnect. A body that arrives for an older generation
is counted and dropped; it is not the call's result.

A call in flight when its connection fails, times out or is replaced resolves as an error to
its caller and is not sent again: the EL may already have applied it, and cl-chain decides
what to resubmit. The connection is dropped; the next call reconnects (generation bump, then
the capability check) inside its own deadline, so one failure does not hold the queue.

The queue is bounded: a caller waits for room among 256 queued calls (backpressure), and at
most 256 calls may wait for an earlier `seq` before new ones fail with `Overloaded`. A buffer
full of released `seq`s behind a gap skips the gap (nothing else would). No lock is held
across an `.await`.

A job is claimed right before it goes on the wire, once the connection can take it: a job
whose deadline passed or whose caller went away meanwhile is never sent. One call can take up
to twice its timeout: queued (and waiting for the connection) up to the timeout, then the
EL's full response timeout from the send.

Reconnect dials immediately, then with exponential backoff from 200 ms capped at 5 s (the
spec does not set this), up to 5 attempts. A missing capability does not install the new
connection.

## engine.v1 server

`EngineServer` maps each `engine.v1` RPC onto one queue call; `serve` runs it on a Unix socket
bound by `ipc::uds::bind`. It is a trust boundary:

- Every accepted connection has its `SO_PEERCRED` read before anything is read from it. An
  unreadable credential, or a UID that is not a caller in the method ACL from config
  (`/etc/ethswarm/cl-engine.toml`; only cl-chain may be listed), closes it. Each handler checks
  the UID again from the connection info.
- `ipc::acl::AclLayer` runs before the service: exact method paths, deny by default, so an
  unknown or unlisted method is `PERMISSION_DENIED` before the body is decoded.
- `Limits`: a request message over 32 MiB + 64 KiB is refused from its gRPC length prefix
  (`OUT_OF_RANGE`) before a buffer is allocated; responses are capped at 48 MiB + 64 KiB. Each
  request has a 10 s deadline (body read included), a connection silent for 30 s is closed,
  one whose first request has not arrived 10 s after the accept is closed however steadily it
  sends, at most 4 connections and 16 in-flight requests per connection.
- Requests the EL could not take as specified are refused (`INVALID_ARGUMENT`) before the
  queue, and their `seq` is released: a `payload_id` that is not 8 bytes, a versioned hash that
  is not 32 bytes, more than 128 of them, an `indices_bitarray` that is not 16 bytes for
  getBlobsV4 (or set at all for V2/V3), a `custody_columns` that is not 16 bytes or empty for
  forkchoiceUpdatedV4 (or set at all for V3).
- A caller's `timeout_ms` may raise the spec wait (up to the 10 s request deadline), never
  shorten it (`common.md`: the CL MUST wait the method's timeout). An EL error, timeout, a
  `forkchoiceUpdated` result without `payloadStatus`, or a `latestValidHash`/`payloadId` that is
  not `null` or exactly 32/8 bytes is an `EngineError`, never `VALID`.
- Errors and logs carry codes, UIDs and fixed text, never the secret or a payload.

`tests/server.rs` serves the mock EL over a socket: a wrong-UID peer, unknown and near-miss
methods, an oversize frame, an oversize length prefix alone, a body that never finishes,
stalled and trickling writers, malformed getBlobs/getPayload requests and the connection cap.

Tests use the hyper mock in `tests/common`, bound to `127.0.0.1:0`. Nothing is dialed that the
test did not start.
