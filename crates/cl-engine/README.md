# cl-engine

The ordered Engine API transport between cl-chain and one execution client. It is the only
holder of the JWT secret. It does not decode consensus types (ADR-007): a call's JSON params
are forwarded as the JSON-RPC `params`, and a result is copied back into the proto message.

`EngineStub` (`src/lib.rs`) is what `tests/contract.rs` drives (contract checks, then
`UNIMPLEMENTED`). The `engine.v1` Unix-socket server in front of the queue is a separate
change. The binary does not serve yet.

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
optional; this crate does not.

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
| `engine_newPayload` | 8 s (`paris.md`; the proto comment says 6 s) |
| `engine_forkchoiceUpdated` | 8 s |
| `engine_getPayload`, `engine_getBlobs`, `engine_exchangeCapabilities` | 1 s |

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
most 256 calls may wait for an earlier `seq` before new ones fail with `Overloaded`. No lock
is held across an `.await`.

Reconnect dials immediately, then with exponential backoff from 200 ms capped at 5 s (the
spec does not set this), up to 5 attempts. A missing capability does not install the new
connection.

Tests use the hyper mock in `tests/common`, bound to `127.0.0.1:0`. Nothing is dialed that the
test did not start.
