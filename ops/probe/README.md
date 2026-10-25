# Probe systemd units

`ethswarm-p2p.service`, `ethswarm-discv5.service` and `ethswarm-chain.service` run the probe's
services, each as its own OS user, each starting only after two independent beacon API
providers agree on the checkpoint anchor.

| Unit | `User=` | Node key | State dir (only writable path) | Socket dir |
|---|---|---|---|---|
| `ethswarm-p2p.service` | `ethswarm-p2p` | credential `nodekey` | `/var/lib/ethswarm-p2p` | `/run/ethswarm/cl-p2p` |
| `ethswarm-discv5.service` | `ethswarm-discv5` | credential `nodekey` | `/var/lib/ethswarm-discv5` | `/run/ethswarm/cl-discv5` |
| `ethswarm-chain.service` | `ethswarm-chain` | none | `/var/lib/ethswarm-chain` | `/run/ethswarm/cl-chain` |

## Requirements

- **systemd 247 or later.** `LoadCredential=` (the node key) and `ProtectProc=`/`ProcSubset=`
  need 247; everything else the units set is older (`MemoryMax=` 231, `MemorySwapMax=` 232,
  `OOMPolicy=` 243). An older systemd logs an unknown key and runs the
  unit without it, so it would start unhardened or without its key: do not install there.
- **The unified cgroup hierarchy (cgroup v2)** with the memory controller. On cgroup v1 systemd
  ignores `MemorySwapMax=`, so the memory ceiling would not hold.

## Install

```bash
for u in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
  useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
done
install -m 0755 target/release/{cl-p2p,cl-discv5,cl-chain,anchor-fetch} /usr/local/bin/
install -d -m 0700 /etc/ethswarm/credentials
# The 32-byte secp256k1 secret, root-owned.
install -m 0600 node.key /etc/ethswarm/credentials/nodekey
install -m 0600 anchor-check.env /etc/ethswarm/anchor-check.env
# Each service's config and the topic list: root-owned, readable, no secret (see "Services").
install -m 0644 cl-chain.toml cl-discv5.toml cl-p2p.toml /etc/ethswarm/
install -m 0644 ops/probe/gossip-topics.toml /etc/ethswarm/gossip-topics.toml
# cl-p2p calls cl-chain and cl-discv5 on their sockets (directories 0750, sockets 0660), and
# cl-chain calls cl-verify on its socket (here cl-verify's group is ethswarm-verify).
usermod -a -G ethswarm-chain ethswarm-p2p
usermod -a -G ethswarm-discv5 ethswarm-p2p
usermod -a -G ethswarm-verify ethswarm-chain
# The three units by name, never a glob: only these three are linted.
install -m 0644 ops/probe/ethswarm-p2p.service ops/probe/ethswarm-discv5.service ops/probe/ethswarm-chain.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now ethswarm-chain ethswarm-discv5 ethswarm-p2p
```

The `install -m 0644` line above is the only line in this README that writes into a systemd
unit directory. `ops/probe/tests/probe-units.test.sh` holds it byte for byte and refuses any
other line that names systemd's configuration directory under `/etc` or a unit directory under
`/etc`, `/run`, `/lib`, `/usr/lib` or `/usr/local/lib`, whatever command it runs (`cp` with a
glob, `sudo install`, `ln -s`, `rsync`, a redirect, a `cd` there first). It also refuses any
other line that names a path through a `systemd` directory and holds a `..` anywhere: a parent
alias (from systemd's user unit directory up and into its system one, or a `cd` into one and a
relative path after) reaches a unit directory without spelling it, so such a line is refused,
not resolved.

## Services

The units pass no argument to the binaries. Each binary reads one fixed config file,
`/etc/ethswarm/<service>.toml`, and serves its gRPC package on its own Unix socket.

- **The config file.** The binary reads the file only if root owns it and every directory on
  its path, and the service user can write none of them. The path is walked from `/`, and a
  symlink on it is refused (`svc_runtime::owned`, the same walk as `m2a-session`). The file holds
  no secret, so mode 0644 is correct. The node key never goes in a config file.
- **The keys that every service shares** (`svc_runtime::config`): `network` (a pinned network)
  or `network_dir` (a devnet's `config.yaml` and `genesis.ssz`), `metrics_port` (`/metrics` on
  `127.0.0.1`), `[socket] group`, `[callers]` and `[methods]` (the method ACL). Each service also
  has its own table: `[chain]`, `[discv5]` or `[p2p]`. A table of another service is refused.
- **The sockets.** A service binds `/run/ethswarm/<service>/<service>.sock` in its
  `RuntimeDirectory=`, directory 0750 and socket 0660, owned by the service user and the
  `[socket] group`. Set that group to the service's own group. A caller can connect only if it
  is a member, so the install adds `ethswarm-p2p` to `ethswarm-chain` and `ethswarm-discv5`,
  and cl-chain's user to the group of cl-verify's socket. The units do not change: systemd
  gives a `User=` its groups from the user database, and the lint refuses
  `SupplementaryGroups=`. The method ACL then checks the caller's UID on each call.
- **`/metrics`.** The runtime's own metrics have the prefix `ethswarm_`. The service's metrics
  keep their names without a prefix (`probe_column_dropped_total`, and from cl-p2p
  `topic_msg_*`, `p2p_peers` and `p2p_goodbye_received_total`), because the run reports read
  those names.

### cl-chain

cl-chain runs probe mode (`cl_chain::probe::service`, `cl_chain::service`). It stores the
custody columns in `/var/lib/ethswarm-chain/columns` and opens the same store after a restart,
so the custody group count and `cgc_set_slot` of the first start stay. It follows the
reference node's events (the canonical chain, the finalize and retention prunes). It asks
cl-verify for the KZG checks, and refuses a cl-verify server that runs as another UID. Only
cl-p2p's UID can call its four methods: `ReqRespService/GetStatus`, `DataColumnsByRange`,
`DataColumnsByRoot` and `GossipService/WatchSubscriptions`.

```toml
# /etc/ethswarm/cl-chain.toml
network_dir = "/etc/ethswarm/network"   # or: network = "sepolia"
metrics_port = 9102

[socket]
group = 990                             # the GID of ethswarm-chain

[callers]
cl-p2p = 991                            # the UID of ethswarm-p2p

[methods]                               # exactly these four, to cl-p2p only
"/ethswarm.chain.v1.ReqRespService/GetStatus" = ["cl-p2p"]
"/ethswarm.chain.v1.ReqRespService/DataColumnsByRange" = ["cl-p2p"]
"/ethswarm.chain.v1.ReqRespService/DataColumnsByRoot" = ["cl-p2p"]
"/ethswarm.chain.v1.GossipService/WatchSubscriptions" = ["cl-p2p"]

[chain]
reference_api_url = "http://127.0.0.1:5052"   # localhost, loopback or a private address
node_id = "0x<64 hex digits>"                 # the probe's discv5 node ID (public)
verify_socket = "/run/ethswarm/cl-verify/cl-verify.sock"
verify_uid = 993                              # the UID that cl-verify runs as
# columns_dir = "/var/lib/ethswarm-chain/columns"
# verify_timeout_ms = 5000
# verify_wait_ms = 30000
```

| Exit | Meaning | Restarted |
|---|---|---|
| 0 | SIGTERM: the watch streams end, in-flight calls drain, the socket is removed; during the wait for cl-verify, at once | no |
| 1 | a start that a restart cannot fix: the store, the socket's bind, an ACL of unserved methods, a cl-verify directory open to others (or still another user's at the end of the wait), a cl-verify server of another user | no |
| 2 | the config was refused, or the store holds the custody of another `node_id` (or of an unrecorded one) | no |
| 64 | an argument (the unit passes none) | no |
| 69 | cl-verify's directory or socket was not there within `verify_wait_ms`, or the clock is before genesis | yes |
| 70 | a fault of the run that a restart can fix: the server task, a drain past its deadline, `/metrics`, the service manager, a store that did not close within 10 s | yes |
| 71 | the log writer could not start | yes |

The store keeps the node ID of its first start (`node-id` in `columns_dir`, mode 0600, the
directory synced after it). A start with another `node_id` exits 2, because the custody columns
follow the node ID: remove the store's directory to start with the new one. A store of an older
build, with custody but no `node-id`, exits 2 too. After the drain, the store gets 10 s to
close, so the stop ends within the unit's stop timeout; a store that does not close in time
exits 70 and logs how many columns were still on their way.

The wait for cl-verify (`verify_wait_ms`) covers its directory too. A directory that is not
there yet, or that another user still owns (systemd makes it, then gives it to its user), is
waited for. A directory, or one above it, that other users can write is refused at once.

**The reference API.** `reference_api_url` is plain HTTP. On a private address of a shared
network, anyone on that network can read and change what cl-chain gets, and the reference
decides which block roots cl-chain stores. Prefer an SSH tunnel to a loopback port
(`ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:5052:127.0.0.1:5052 <reference host>`).
Use a private address only on a network that only the probe and the reference share, such as
the Kurtosis enclave network.

### The hellos follow the clock

Every chain.v1 and discv5.v1 stream carries the fork digest of the wall-clock epoch at its
start (`ipc::Link::network`), on both ends. So a service that starts after a fork or BPO
digest change is accepted by a service that started before it, and no restart is needed at a
change. A peer that still sends the old digest is refused with `VERSION_MISMATCH`.

### cl-discv5

cl-discv5 runs discv5 with the node key (`cl_discv5::process`). Its record carries the fork
fields of the wall clock and takes the new ones at each digest change. It logs its node ID and
its record at start: both are public, and cl-chain's `node_id` is that node ID. It starts its
routing table from `bootnodes` and does a lookup every `lookup_interval_ms`. At a digest change
it keeps the records that announce the new digest as their next one (`nfd`), and keeps the
records of the old digest for one epoch, while peers update their records. Only cl-p2p's UID
can call its two methods: `WatchPeers` (the table's records, then each record found) and
`GetLocalEnr`. Its `cgc` must be cl-chain's custody group count: cl-p2p refuses another.

```toml
# /etc/ethswarm/cl-discv5.toml
network_dir = "/etc/ethswarm/network"   # or: network = "sepolia"
metrics_port = 9103

[socket]
group = 992                             # the GID of ethswarm-discv5

[callers]
cl-p2p = 991                            # the UID of ethswarm-p2p

[methods]                               # exactly these two, to cl-p2p only
"/ethswarm.discv5.v1.DiscoveryService/WatchPeers" = ["cl-p2p"]
"/ethswarm.discv5.v1.DiscoveryService/GetLocalEnr" = ["cl-p2p"]

[discv5]
mode = "public"                  # public, devnet or local: the routing table's IP rules
bootnodes = ["enr:<record>"]
# listen_ip = "0.0.0.0"  udp_port = 9000  tcp_port = 9000  (cl-p2p's port, in our record)
# enr_ip = "<our IPv4 address>"  cgc = 4  lookup_interval_ms = 30000  lookup_peers = 16
```

### cl-p2p

cl-p2p runs the swarm (`cl_p2p::service`). At start it waits for cl-chain (`chain_wait_ms`)
and for its first custody subscriptions, and refuses to start (exit 2) if those columns are not
the custody columns of its own node key: cl-chain's `node_id` is then another key's. It holds
each later subscriptions body to the same key and group count (exit 2). It subscribes the
ignore-all gossipsub to the topics of `gossip_topics` and to the custody column subnets, under
every fork digest that cl-chain names, and to the topics of a new digest ahead of its change.
The topics of a digest that cl-chain no longer names leave one epoch after the change, so the
topic set stays within its bound (418 topics) at every fork and BPO change. Its Status, its
column answers and its custody come from cl-chain. Before each `WatchPeers` stream it reads
cl-discv5's record (`GetLocalEnr`) and stops (exit 2) if its `cgc` is not cl-chain's custody
group count. It dials cl-discv5's candidates, their addresses held to the IP rule of `mode`
(the value of cl-discv5's `mode`), up to `target_peers` of its own dials, the `static_peers`
first and always, once it has a Status. Inbound peers do not count toward `target_peers`: they
have their own 128 slots, and the 32 outbound slots stay ours. It feeds the Goodbye ledger and
ticks it every 60 s; an event that does not fit the feed is dropped and counted on
`p2p_ledger_feed_dropped_total`, but a disconnect is never dropped. On SIGTERM it sends Goodbye
1 (client shutdown) to every peer and gives that 1 s before it exits.

```toml
# /etc/ethswarm/cl-p2p.toml
network_dir = "/etc/ethswarm/network"   # or: network = "sepolia"
metrics_port = 9101

[socket]
group = 991                             # the GID of ethswarm-p2p

[callers]                               # the p2p.v1 stub's ACL: its future callers
cl-sync = 994

[methods]
"/ethswarm.p2p.v1.NetworkService/ListPeers" = ["cl-sync"]

[p2p]
chain_uid = 990                         # the UID of ethswarm-chain
discv5_uid = 992                        # the UID of ethswarm-discv5
# listen = ["/ip4/0.0.0.0/tcp/9000"]
# chain_socket = "/run/ethswarm/cl-chain/cl-chain.sock"
# discv5_socket = "/run/ethswarm/cl-discv5/cl-discv5.sock"
# gossip_topics = "/etc/ethswarm/gossip-topics.toml"   (read only if root owns it)
# target_peers = 32  (1 to 32: our own dials)  static_peers = []
# answer_prefix_v4 = 24  answer_prefix_v6 = 48  chain_wait_ms = 30000
# mode = "public"                       # public, devnet or local: as cl-discv5's mode
# [p2p.goodbye_ledger]  goodbye3_threshold_pct = 2.0
```

cl-discv5 and cl-p2p use the exit codes of cl-chain, with 1 also for a refused credential. The
credential is checked before the config. cl-p2p exits 2 also for custody columns of another
key or of another group count, at the start or later, and for a cl-discv5 record of another
`cgc`; 69 when cl-chain (its directory included) did not accept or send its subscriptions within
`chain_wait_ms`, and 1 when the server on cl-chain's socket runs as another user. Both exit 70
for a fault of the run that a restart can fix. A server of another user on cl-discv5's socket
does not stop cl-p2p: it is logged at ERROR at each try, and cl-p2p dials only its static
peers.

## Node key

The key reaches cl-p2p and cl-discv5 only as
`LoadCredential=nodekey:/etc/ethswarm/credentials/nodekey`; no config file or argument names
it. The source stays root-owned 0600. systemd copies it into the unit's own read-only mount at
`/run/credentials/<unit>` (`$CREDENTIALS_DIRECTORY`), and the binary reads
`$CREDENTIALS_DIRECTORY/nodekey` (crate `node-key`). It refuses to run as root, opens the
file without following a symlink, and accepts exactly the two shapes systemd's
`write_credential()` leaves:

- **ACL-granted** (tmpfs with `noswap`, kernel 6.3 and later, the usual case): owned by root,
  mode 0400 (`stat` shows 0440: the group bits are the ACL mask), with exactly the ACL
  `user::r--`, `user:<service uid>:r--`, `group::---`, `mask::r--`, `other::---`. Accepted only
  in `/run/credentials/<this unit>` on a read-only tmpfs or ramfs.
- **Owned** (ramfs, where there are no ACLs, so systemd `chown`s instead): owned by the
  service's user, mode 0400 or 0600, no ACL.

Anything else is refused, and the file must hold exactly a valid 32-byte secp256k1 secret.
The bytes are zeroized, every key type prints `<redacted>`, and no log line carries them
(`crates/node-key/tests/log_capture.rs`, `crates/cl-p2p/tests/identity_log.rs`). Both shapes
are exercised on a real read-only tmpfs by `crates/node-key/tests/credential_acl.rs` (root, CI
job `credential-root-tests`). cl-p2p and cl-discv5 share the key: the ENR and the libp2p peer
ID are one identity. cl-chain never gets it.

## Anchor check

`ExecStartPre=/usr/local/bin/anchor-fetch --providers ${ANCHOR_PROVIDERS} --check` runs as the
unit's user before the service starts. `/etc/ethswarm/anchor-check.env` holds the providers:

```bash
ANCHOR_PROVIDERS=https://beacon.provider-a.example,https://beacon.provider-b.example
```

They must be two independent providers. One host given twice, two hosts under one domain (the
same last two DNS labels; a heuristic, not a public-suffix check), or two names that resolve
to a common address exit 2; every request then dials exactly the addresses that check saw
(TLS and `Host` still use the name), so a later DNS answer cannot move a provider. Beyond that, operator independence rests on the operator's word:
nothing here can tell that two domains belong to one operator. The check exits 0 only if both
providers report the same finalized checkpoint, agree on its block root and header, the block
from A hashes to that root, the block's `state_root` is the headers', and the state from B
hashes to that state root. Otherwise it exits non-zero and the unit does not start (1 a check
failed, 2 a config refused, 3 a provider unreachable, 4 local I/O, 64 a usage error; `--help`
next to any other argument is a usage error, so an empty or hostile `ANCHOR_PROVIDERS` cannot
pass the gate). It writes nothing: the bodies stay in a private directory under the unit's
`PrivateTmp=` `/tmp`, removed before exit, also when systemd stops the unit (SIGTERM, exit
143). The journal records both providers by origin only. A URL path is shown as `/…`, and a
query is refused. Arguments are visible in the process list, so use provider URLs that carry
no key.

`TimeoutStartSec=70min` covers the check's worst case with anchor-fetch's defaults (four JSON
requests at 30 s, two bodies at 30 s + 1800 s: 3780 s). A failed start is retried after
`RestartSec=5min`, at most `StartLimitBurst=3` times in `StartLimitIntervalSec=6h`, then the
unit stays failed. `RestartPreventExitStatus=1 2 64` stops restarts of the service itself on a
refused credential or a failed start (1), a refused config or the stub's exit (2) and a usage
error (64); systemd applies it to the
main process only, so a failing `ExecStartPre=` check is bounded by the start limit instead.

Exit 71 (`EXIT_NO_LOG_WRITER`, `EX_OSERR`) is deliberately not in that list, so it is
restarted. cl-p2p and cl-discv5 exit 71 at once when their log-writer thread cannot start, and
they write nothing to stderr on purpose (stderr may be the cause), so the journal shows only
the exit status (`systemctl status`, `journalctl -u <unit>`). A thread limit can lift, so the
restart may succeed. If it keeps failing, check the limits systemd gives the unit, not those of
a login shell (`LimitNPROC=` comes from the unit or the manager's `DefaultLimitNPROC=`):
`systemctl show -p TasksMax,TasksCurrent,LimitNPROC,LimitNPROCSoft <unit>`, and the host's free
memory. Once the start limit is used up (`StartLimitBurst=3` in `StartLimitIntervalSec=6h`) the
unit stays failed even after the cause is gone; once it is fixed, recover the unit with
`systemctl reset-failed <unit> && systemctl start <unit>`.

## Resource limits

Every unit carries a memory ceiling: plain resource containment for a process whose memory
grows past what it should ever need. It applies to the unit's whole cgroup, so the
`ExecStartPre=` anchor check is under it too. At `MemoryMax=` the kernel OOM-kills the unit.
`MemorySwapMax=0` keeps the ceiling from being dodged through swap. The sizes are estimates, to
be checked against each unit's peak (`memory.peak` in its cgroup, kernel 5.19 and later) once
the services run for real.

There is deliberately no `MemoryHigh=`. Past it the kernel throttles the unit and reclaims its
memory, but without swap there is little to reclaim, and it never OOM-kills: a probe there
stalls instead. On systemd 247 a unit past `MemoryHigh=` stayed throttled, and was not killed,
for more than 10 minutes. A stalled probe skews the measurement more than a restart does, so
`MemoryMax=` alone is the ceiling, and the lint refuses a `MemoryHigh=` line. For an early
warning, watch the unit's cgroup instead: `memory.current` against `MemoryMax=`, and
`memory.events` (its `max` and `oom_kill` counters).

| Unit | `MemoryMax=` | What sets it |
|---|---|---|
| `ethswarm-p2p.service` | 7G | peer state, req/resp and gossip buffers |
| `ethswarm-discv5.service` | 4G | the anchor check |
| `ethswarm-chain.service` | 4G | the anchor check |

- **The anchor check, every unit's floor.** anchor-fetch reads the anchor state's SSZ (S bytes)
  into memory and decodes it into a tree that holds about 2.5 S (the validator list dominates:
  one tree leaf per 121-byte validator, plus the internal nodes and their cached hashes). The
  body also sits in the unit's `PrivateTmp=` `/tmp`, which is memory, charged to the unit and
  not reclaimable without swap, when the host's `/tmp` is a tmpfs. The peak is then about
  S + S + 2.5 S = 4.5 S: about 1.3 GiB for a state of 300 MiB, a mainnet-scale state today,
  and 2.3 GiB for 512 MiB. `MemoryMax=4G` leaves room for a state of up to about 900 MiB. A
  state near anchor-fetch's 1 GiB body cap (`max_body_bytes`), about 4.5 GiB, would not fit
  under 4G; the check would be OOM-killed, which fails the start like any other failed check.
- **cl-discv5** itself needs tens of MiB: a routing table of at most 256 × 16 records of up to
  300 bytes, its sessions and 1280-byte packets. **cl-chain** in probe mode samples the
  reference API and holds no state. Both are set by the check's floor; when cl-chain starts
  importing (states, fork choice), its ceiling is revisited with the pinned line.
- **cl-p2p**, from the caps in `crates/cl-p2p`: up to 160 established connections
  (`ConnectionCaps`, 128 inbound), each a few MiB of transport buffers and yamux windows in
  normal operation (about 0.3 GiB); the req/resp responses one session may hold, 2 × 256 MiB
  (`MAX_CONCURRENT_REQUESTS` × `MAX_RESPONSE_BYTES`); a quarter of the connections holding
  their full 32 MiB mplex budget (`DEFAULT_CONNECTION_BYTES`) at once, 1.25 GiB; and 256 MiB
  for gossip caches. That is about 2.3 GiB in normal operation. The worst case the transport
  still bounds is every connection's mplex budget full at once, 160 × 32 MiB = 5 GiB, plus the
  responses (0.5 GiB), the gossip caches (0.25 GiB) and the baseline (about 0.3 GiB): about
  6.05 GiB. `MemoryMax=7G` sits about 0.95 GiB above that, so the transport's own budgets,
  which close a connection, act before the ceiling, which kills the process. The ceiling
  catches what those budgets do not bound.

An OOM kill is a signal (SIGKILL), not an exit status. With `OOMPolicy=stop`, set in the unit
rather than left to the host's `DefaultOOMPolicy=`, systemd stops the unit with result
`oom-kill`, a failure, and `Restart=on-failure` restarts it after `RestartSec=5min`, counted by
the same start limit (3 starts in 6 h, then the unit stays failed). `RestartPreventExitStatus=`
lists exit codes only (the lint refuses a signal name there), so it never turns the kill into a
stop. The same holds for an OOM kill of the anchor check during the start.

## Hardening

Every unit sets `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp=yes`, `PrivateDevices=yes`, an empty `CapabilityBoundingSet=`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service` and
`~@privileged`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=yes`, the
`Protect*`/`Restrict*` set in the files, `UMask=0077`, and `ReadWritePaths=` its state dir only
(plus the systemd-managed runtime dir for its socket).

**The lint pins the units exactly.** `ops/probe/tests/probe-units.test.sh` (CI, `workflows`
job) accepts a unit only if every line systemd reads (not blank, not a comment) equals, in
order and byte for byte, the line recorded for it in `EXPECTED` in `lint_units.py`. The only
exception is `Description=`. There is no case folding, no whitespace tolerance and no joining of
assignments, and no key or value can be added, changed, moved or dropped. Any change to a unit
is therefore a reviewed change to both the unit and the lint's expected data, in one commit.

The older rule checks stay in place as defence in depth and for clearer messages. They read
the units as systemd does (an empty assignment resets a list, a later assignment overrides an
earlier one). The lint is also an allow-list: each section may
hold only the keys the three committed units use (listed in `ALLOWED` in `lint_units.py`), and
any other key or section fails it, so a directive that changes how the reviewed lines run
(`PermissionsStartOnly=`, which runs `ExecStartPre=` as root; `SuccessExitStatus=`, which
turns a failed check into a start; `SupplementaryGroups=`, `ExecCondition=`, ...) cannot slip
in. Adding a directive to a unit means adding it to the lint, after review. It requires
`Group=` to be the unit's own user, and a variable in the check's arguments to be braced
(`${ANCHOR_PROVIDERS}`, one word; an unbraced `$VAR` would be split). It fails if any of
these, `User=`,
`LoadCredential=nodekey` (and its absence from cl-chain), the `ExecStartPre=` check and its
argument allow-list, `TimeoutStartSec=` or the restart limits is missing or weakened, or if
any `Exec*=` line carries a `+`, `!` or `!!` prefix (which would run it as root outside the
sandbox) or a `|` prefix. Fail-closed, it also refuses any `Exec*=` value with a quote, a
backslash or a bare `;` word: systemd unquotes, unescapes and splits those before it reads the
prefixes, so they could hide one. It reads each unit as bytes and refuses the whole file on any
byte outside tab, newline and printable ASCII (NUL, CR, VT, FF, U+2028 and every other
non-ASCII byte), on any backslash (so no continuation or escape exists to model), and on any
line that is not blank, a comment, a `[section]` or a `key=value` inside a section. It refuses
a unit over 64 KiB, and any line over 2047 bytes (the longest committed line is under 100):
a systemd that reads unit files through `fgets()` into a 2048-byte buffer reads the rest of a
longer line as a line of its own, so a long comment could hide a setting, while current
systemd refuses a line of 1 MiB or more. At 2047 bytes every systemd reads the lint's lines,
whatever its version. It also refuses any `*.d` drop-in directory next to the units, and any
`*.service` other than the three: it checks the files in this directory only, not what a host
adds.

## Gossip topics

`gossip-topics.toml` is the probe's configured gossip topic list (Sepolia): the exit-14 set of
`gloas/p2p-interface.md` (`beacon_block`, `execution_payload`, `execution_payload_bid`,
`payload_attestation_message`, `beacon_aggregate_and_proof`, the sampled
`beacon_attestation_{subnet_id}` and the custody `data_column_sidecar_{subnet_id}`). cl-p2p
reads it as data (`cl_p2p::gossip::TopicList`): every name goes through p2p-wire's
`GossipTopic::parse`, and a name it does not handle refuses the whole file. The probe
subscribes each name under every fork digest it follows (two at most, around a fork) and
reports IGNORE for every message, so it forwards none.

The file records its bounds and byte budget, and cl-p2p's tests check them against it: 11
topics per digest (22 under two) within the 418 subscriptions one RPC may carry, a
subscription whitelist that starts as these topics plus all 128
`data_column_sidecar_{subnet_id}` subnets of each fork digest (270 topics under two, also
within 418), every name a Gloas topic name so the
control-message size (46,898 bytes, computed for the two-fork set of every topic) still fits
without a recompute, and each topic's decompressed cap on Sepolia (largest message 10 MiB, one
message of every topic 21,362,195 bytes). Set the attestation subnets to the ones the probe
samples before a run. cl-p2p also subscribes the custody column subnets that cl-chain names
(`WatchSubscriptions`), so the custody subnets need not be in the file: a column subnet of the
file that is not a custody subnet is still subscribed, and cl-chain drops its columns.

## Not covered here

- A journal grep of every probe unit after a 10-minute devnet run (neither the key hex nor its
  base64 appears) needs the Kurtosis devnet and running probe services.
- The host check for the Sepolia exit run: on the real host, `stat` and `getfacl` of
  `/run/credentials/ethswarm-p2p.service/nodekey` (and discv5's) show one of the two shapes
  above. On a current kernel that is root-owned 0440 with `user:ethswarm-p2p:r--` and
  `mask::r--`, the mount read-only (`findmnt /run/credentials/ethswarm-p2p.service`). The
  source `/etc/ethswarm/credentials/nodekey` stays root-owned 0600.
- The installed units and any drop-ins on the host (an `ethswarm-*.service.d/` directory in any
  unit directory under `/etc` or `/run`, `systemctl edit`) are part of #38's host check. The lint checks only
  the files in this directory. On the host, the output of `systemctl cat ethswarm-p2p` (and the
  other two) is byte-compared with the committed unit: it must show that file and no drop-in.
