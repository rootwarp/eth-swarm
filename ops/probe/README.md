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
  need 247; everything else the units set is older (`MemoryHigh=`/`MemoryMax=` 231,
  `MemorySwapMax=` 232, `OOMPolicy=` 243). An older systemd logs an unknown key and runs the
  unit without it, so it would start unhardened or without its key: do not install there.
- **The unified cgroup hierarchy (cgroup v2)** with the memory controller. On cgroup v1 systemd
  ignores `MemoryHigh=` and `MemorySwapMax=`, so the memory ceiling would not hold.

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
# The three units by name, never a glob: only these three are linted.
install -m 0644 ops/probe/ethswarm-p2p.service ops/probe/ethswarm-discv5.service ops/probe/ethswarm-chain.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now ethswarm-chain ethswarm-discv5 ethswarm-p2p
```

The `install -m 0644` line above is the only line in this README that writes into a systemd
unit directory. `ops/probe/tests/probe-units.test.sh` holds it byte for byte and refuses any
other line that names systemd's configuration directory under `/etc` or a unit directory under
`/etc`, `/run`, `/lib`, `/usr/lib` or `/usr/local/lib`, whatever command it runs (`cp` with a
glob, `sudo install`, `ln -s`, `rsync`, a redirect, a `cd` there first).

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
refused credential (1), the stub's exit (2) and a usage error (64); systemd applies it to the
main process only, so a failing `ExecStartPre=` check is bounded by the start limit instead.

## Resource limits

Every unit carries a memory ceiling: plain resource containment for a process whose memory
grows past what it should ever need. It applies to the unit's whole cgroup, so the
`ExecStartPre=` anchor check is under it too. Above `MemoryHigh=` the kernel throttles the
unit and reclaims its memory; at `MemoryMax=` it OOM-kills. `MemorySwapMax=0` keeps the ceiling
from being dodged through swap. Without swap, little of a growing process's memory can be
reclaimed, so past `MemoryHigh=` it is throttled hard and may take minutes, or longer, to reach
`MemoryMax=` and be killed; a unit stuck there shows high `memory.pressure` in its cgroup. The sizes are estimates, to be checked against each unit's
peak (`memory.peak` in its cgroup, kernel 5.19 and later) once the services run for real.

| Unit | `MemoryHigh=` | `MemoryMax=` | What sets it |
|---|---|---|---|
| `ethswarm-p2p.service` | 4G | 6G | peer state, req/resp and gossip buffers |
| `ethswarm-discv5.service` | 3G | 4G | the anchor check |
| `ethswarm-chain.service` | 3G | 4G | the anchor check |

- **The anchor check, every unit's floor.** anchor-fetch reads the anchor state's SSZ (S bytes)
  into memory and decodes it into a tree that holds about 2.5 S (the validator list dominates:
  one tree leaf per 121-byte validator, plus the internal nodes and their cached hashes). The
  body also sits in the unit's `PrivateTmp=` `/tmp`, which is memory, charged to the unit and
  not reclaimable without swap, when the host's `/tmp` is a tmpfs. The peak is then about
  S + S + 2.5 S = 4.5 S: about 1.3 GiB for a state of 300 MiB, a mainnet-scale state today,
  and 2.3 GiB for 512 MiB. `MemoryHigh=3G` leaves room for a state of over 600 MiB. A state near
  anchor-fetch's 1 GiB body cap (`max_body_bytes`) would not fit; the check would be OOM-killed,
  which fails the start like any other failed check.
- **cl-discv5** itself needs tens of MiB: a routing table of at most 256 × 16 records of up to
  300 bytes, its sessions and 1280-byte packets. **cl-chain** in probe mode samples the
  reference API and holds no state. Both are set by the check's floor; when cl-chain starts
  importing (states, fork choice), its ceiling is revisited with the pinned line.
- **cl-p2p**, from the caps in `crates/cl-p2p`: up to 160 established connections
  (`ConnectionCaps`, 128 inbound), each a few MiB of transport buffers and yamux windows in
  normal operation (about 0.3 GiB); the req/resp responses one session may hold, 2 × 256 MiB
  (`MAX_CONCURRENT_REQUESTS` × `MAX_RESPONSE_BYTES`); a quarter of the connections holding
  their full 32 MiB mplex budget (`DEFAULT_CONNECTION_BYTES`) at once, 1.25 GiB; and 256 MiB
  for gossip caches. That is about 2.3 GiB, under `MemoryHigh=4G`. `MemoryMax=6G` sits above
  every connection's mplex budget full at once (160 × 32 MiB = 5 GiB) plus the responses, so
  the transport's own budgets, which close a connection, act before the ceiling, which kills the
  process. The ceiling catches what those budgets do not bound.

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
