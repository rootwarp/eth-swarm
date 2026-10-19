"""Verdicts on beacon API answers from the Kurtosis Gloas devnet (testing/kurtosis).

Called by check-devnet.sh, which fetches every CL's answers into DIR/<service>/<name>.json
(a missing file is a request that failed). Each command prints its evidence on stdout, one
`<service>: <key> <value>` line per value and one `- <reason>` line per failure, and exits 0 on
a pass, 1 on a fail, 2 on a usage error. Standard library only, run with `python3 -I`.

    genesis DIR [--reference FILE] [--record FILE] SERVICE...
        /eth/v1/beacon/genesis (genesis_time, genesis_validators_root, genesis_fork_version) and
        /eth/v1/beacon/headers/genesis (the genesis block root and its state_root): every CL
        must report the same five values. With --reference (a record an earlier run wrote), each
        must equal the reference's; with --record, the agreed values are written to FILE as
        JSON (only when every CL answered and agreed). Prints `genesis: PASS (...)` or
        `genesis: FAIL`.

    forks DIR SERVICE...
        /eth/v1/config/fork_schedule, /eth/v1/config/spec and /eth/v1/node/identity: for each
        CL, GLOAS_FORK_EPOCH is 0, the schedule holds GLOAS_FORK_VERSION at epoch 0, and the
        fork in force at epoch 0 (the last schedule entry at epoch 0) is Gloas. Every CL must
        serve the same scheduled forks (entries at FAR_FUTURE_EPOCH, forks a client knows but
        has not scheduled, are dropped before the comparison; Gloas there still fails the
        epoch-0 check) and advertise the same fork digest: the first 4 bytes of the
        `eth2` entry (ENRForkID) of its own ENR, which is the digest it uses on the wire. The
        ENR signature is not checked; the record comes from the node's own API. Versions
        compare case-insensitively. Prints `fork_schedule: PASS (...)` or `fork_schedule: FAIL`.

    pair [--record FILE] NAME_A RECORD_A NAME_B RECORD_B
        Two enclaves' genesis records (the --record files of their `genesis` runs; a missing
        file is an enclave whose genesis check failed) must hold the same five values. With
        --record, the pair's one genesis is written to FILE (only when they agree). Prints
        `pair genesis: PASS (...)` or `pair genesis: FAIL`.

    finality DIR MIN_EPOCH SERVICE...
        /eth/v1/beacon/states/head/finality_checkpoints: every CL's finalized epoch is at least
        MIN_EPOCH, and every CL reports the same finalized (epoch, root). Prints no verdict line
        (check-devnet.sh polls it and prints one).

    goodbye3 DIR ARGS --log FILE [--log FILE...] SERVICE...
        Exit 10 (b): no Goodbye with reason 3 from any CL during the probe's run. For each CL:
        its client and pinned image, from participant <n> of the ethereum-package args file
        ARGS (service cl-<n>-<client>-...: one node per participant, its cl_type the client,
        its cl_image pinned as repo:tag@sha256:<64 hex>); its peer ID (/eth/v1/node/identity
        peer_id); and, from the probe's svc-runtime JSON logs, the `goodbye_received` lines
        from that peer by reason and how long the logs observed it: the longest window one log
        gives, first to last line naming it (fields.peer) in that log. Each log is one probe run,
        so windows are never joined across logs (two short runs an hour apart are not an hour
        of observation), and one run must cover 2 epochs on its own. An epoch is SLOTS_PER_EPOCH slots of SLOT_DURATION_MS (or
        SECONDS_PER_SLOT), from /eth/v1/config/spec. Fails on any reason-3 Goodbye from a CL, a
        CL the logs never name, two CLs with one peer ID, and a log that cannot prove there was
        none: an empty one, a line that is not JSON or has no timestamp, a "log lines dropped"
        summary, or a goodbye_received line without a peer ID (12D3KooW…, 16Uiu2HA… or Qm…, base58)
        or an integer reason. A CL
        observed for under 2 epochs, with none, is DIAGNOSTIC (exit 3). Prints
        `goodbye3: PASS (...)`, `goodbye3: FAIL` or `goodbye3: DIAGNOSTIC (...)`.
"""

import argparse
import base64
import datetime
import json
import os
import re
import sys

GENESIS_FIELDS = (
    "genesis_block_root",
    "genesis_fork_version",
    "genesis_state_root",
    "genesis_time",
    "genesis_validators_root",
)
MAX_ENR_TEXT = 4096
# The epoch of a fork a client knows but has not scheduled (2^64 - 1). Clients differ on whether
# /eth/v1/config/fork_schedule lists such forks (Lodestar lists Heze there, Lighthouse does not).
FAR_FUTURE_EPOCH = 2**64 - 1


class Bad(Exception):
    """An answer that does not hold what the check needs."""


def load(directory, service, name):
    path = os.path.join(directory, service, name + ".json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise Bad("no answer") from None
    except (OSError, ValueError) as e:
        raise Bad(f"{name} answer is not JSON: {e}") from None


def data_of(answer, what):
    data = answer.get("data") if isinstance(answer, dict) else None
    if data is None:
        raise Bad(f"{what} answer has no data")
    return data


def hex_bytes(value, size, what):
    """`value` as lower-case 0x hex of exactly `size` bytes."""
    if not isinstance(value, str) or value[:2].lower() != "0x":
        raise Bad(f"{what} {json.dumps(value)} is not {size}-byte hex")
    body = value[2:].lower()
    if len(body) != 2 * size or any(c not in "0123456789abcdef" for c in body):
        raise Bad(f"{what} {json.dumps(value)} is not {size}-byte hex")
    return "0x" + body


def uint(value, what):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Bad(f"{what} {json.dumps(value)} is not an integer")
    text = str(value)
    if not text.isdigit() or not text.isascii():
        raise Bad(f"{what} {json.dumps(value)} is not an integer")
    return int(text)


def field(data, key, what):
    if not isinstance(data, dict) or key not in data:
        raise Bad(f"{key} missing from {what}")
    return data[key]


# --- genesis ------------------------------------------------------------------------------------


def genesis_of(directory, service):
    g = data_of(load(directory, service, "genesis"), "/eth/v1/beacon/genesis")
    h = data_of(load(directory, service, "header"), "/eth/v1/beacon/headers/genesis")
    what = "/eth/v1/beacon/genesis"
    message = field(field(h, "header", "the genesis header"), "message", "the genesis header")
    return {
        "genesis_time": str(uint(field(g, "genesis_time", what), "genesis_time")),
        "genesis_validators_root": hex_bytes(
            field(g, "genesis_validators_root", what), 32, "genesis_validators_root"
        ),
        "genesis_fork_version": hex_bytes(
            field(g, "genesis_fork_version", what), 4, "genesis_fork_version"
        ),
        "genesis_block_root": hex_bytes(
            field(h, "root", "the genesis header"), 32, "genesis_block_root"
        ),
        "genesis_state_root": hex_bytes(
            field(message, "state_root", "the genesis header"), 32, "genesis_state_root"
        ),
    }


def cmd_genesis(args):
    failures = []
    seen = {}
    for service in args.services:
        try:
            record = genesis_of(args.dir, service)
        except Bad as e:
            failures.append(f"{service}: {e}")
            continue
        seen[service] = record
        for key in GENESIS_FIELDS:
            print(f"{service}: {key} {record[key]}")
    agreed = {}
    for key in GENESIS_FIELDS:
        values = {s: r[key] for s, r in seen.items()}
        if len(set(values.values())) > 1:
            listed = ", ".join(f"{s} {v}" for s, v in values.items())
            failures.append(f"{key}: CLs disagree: {listed}")
        elif values:
            agreed[key] = next(iter(values.values()))
    complete = len(seen) == len(args.services) and len(agreed) == len(GENESIS_FIELDS)
    note = "no reference run given"
    if args.reference:
        note = f"matches the reference run {args.reference}"
        failures.extend(against_reference(args.reference, agreed if complete else None))
    for f in failures:
        print(f"- {f}")
    if failures:
        print("genesis: FAIL")
        return 1
    if args.record:
        with open(args.record, "w", encoding="utf-8") as f:
            f.write(json.dumps(agreed, sort_keys=True) + "\n")
        print(f"genesis: record written to {args.record}")
    print(f"genesis: PASS ({len(seen)} CLs agree; {note})")
    return 0


def against_reference(path, agreed):
    try:
        with open(path, encoding="utf-8") as f:
            reference = json.load(f)
    except (OSError, ValueError) as e:
        return [f"reference {path} is not a JSON genesis record: {e}"]
    if not isinstance(reference, dict):
        return [f"reference {path} is not a JSON genesis record"]
    if agreed is None:
        return ["the CLs gave no single genesis to compare with the reference"]
    out = []
    for key in GENESIS_FIELDS:
        if key not in reference:
            out.append(f"{key}: missing from the reference {path}")
        elif str(reference[key]).lower() != agreed[key]:
            out.append(f"{key}: reference {reference[key]}, this run {agreed[key]}")
    return out


def read_record(name, path):
    """An enclave's genesis record: the five GENESIS_FIELDS; raises Bad when it is unusable."""
    try:
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
    except FileNotFoundError:
        raise Bad(f"{name}: no genesis record (its genesis check failed)") from None
    except (OSError, ValueError) as e:
        raise Bad(f"{name}: genesis record {path} is not JSON: {e}") from None
    if not isinstance(record, dict):
        raise Bad(f"{name}: genesis record {path} is not a JSON object")
    missing = [key for key in GENESIS_FIELDS if not isinstance(record.get(key), str)]
    if missing:
        raise Bad(f"{name}: genesis record {path} has no {', '.join(missing)}")
    return {key: record[key].lower() for key in GENESIS_FIELDS}


def cmd_pair(args):
    failures = []
    records = {}
    for name, path in ((args.name_a, args.record_a), (args.name_b, args.record_b)):
        try:
            records[name] = read_record(name, path)
        except Bad as e:
            failures.append(str(e))
    if len(records) == 2:
        a, b = records[args.name_a], records[args.name_b]
        for key in GENESIS_FIELDS:
            if a[key] == b[key]:
                print(f"pair: {key} {a[key]} (both enclaves)")
            else:
                failures.append(f"{key}: {args.name_a} {a[key]}, {args.name_b} {b[key]}")
    for f in failures:
        print(f"- {f}")
    if failures:
        print("pair genesis: FAIL")
        return 1
    if args.record:
        with open(args.record, "w", encoding="utf-8") as f:
            f.write(json.dumps(records[args.name_a], sort_keys=True) + "\n")
        print(f"pair genesis: record written to {args.record}")
    print(f"pair genesis: PASS ({args.name_a} and {args.name_b}: one genesis)")
    return 0


# --- fork schedule ------------------------------------------------------------------------------


def rlp_item(raw, i):
    """One RLP item at raw[i]: (bytes or list, next index)."""
    if i >= len(raw):
        raise Bad("ENR: RLP is truncated")
    prefix = raw[i]
    if prefix < 0x80:
        return raw[i : i + 1], i + 1
    is_list = prefix >= 0xC0
    short, base = (0xF7, 0xC0) if is_list else (0xB7, 0x80)
    if prefix <= short:
        start, size = i + 1, prefix - base
    else:
        width = prefix - short
        start = i + 1 + width
        if start > len(raw):
            raise Bad("ENR: RLP is truncated")
        size = int.from_bytes(raw[i + 1 : start], "big")
    end = start + size
    if end > len(raw):
        raise Bad("ENR: RLP is truncated")
    if not is_list:
        return raw[start:end], end
    items = []
    j = start
    while j < end:
        item, j = rlp_item(raw, j)
        items.append(item)
    if j != end:
        raise Bad("ENR: RLP list overruns its length")
    return items, end


def enr_fork_digest(text):
    """The fork digest (0x hex) in the `eth2` entry of an ENR text record."""
    if not isinstance(text, str) or not text.startswith("enr:"):
        raise Bad("ENR: does not start with enr:")
    if len(text) > MAX_ENR_TEXT:
        raise Bad(f"ENR: longer than {MAX_ENR_TEXT} characters")
    body = text[4:].translate(str.maketrans("-_", "+/"))
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except ValueError as e:
        raise Bad(f"ENR: not base64url: {e}") from None
    record, end = rlp_item(raw, 0)
    if end != len(raw):
        raise Bad("ENR: trailing bytes after the record")
    if not isinstance(record, list) or len(record) < 2 or len(record) % 2:
        raise Bad("ENR: not [signature, seq, key, value, ...]")
    pairs = record[2:]
    eth2 = None
    for k, v in zip(pairs[0::2], pairs[1::2]):
        if k == b"eth2":
            eth2 = v
    if eth2 is None:
        raise Bad("ENR: no eth2 entry")
    if not isinstance(eth2, bytes) or len(eth2) != 16:
        raise Bad("ENR: eth2 entry is not a 16-byte ENRForkID")
    return "0x" + eth2[:4].hex()


def forks_of(directory, service):
    """((gloas version, scheduled entries), unscheduled count, problems, digest) for one CL;
    raises Bad when an answer is unusable. The scheduled entries are the schedule without its
    FAR_FUTURE_EPOCH entries."""
    spec = data_of(load(directory, service, "spec"), "/eth/v1/config/spec")
    where = "/eth/v1/config/spec"
    gloas = hex_bytes(field(spec, "GLOAS_FORK_VERSION", where), 4, "GLOAS_FORK_VERSION")
    problems = []
    gloas_epoch = uint(field(spec, "GLOAS_FORK_EPOCH", where), "GLOAS_FORK_EPOCH")
    if gloas_epoch != 0:
        problems.append(f"GLOAS_FORK_EPOCH {gloas_epoch}, not 0")
    entries = data_of(load(directory, service, "fork_schedule"), "/eth/v1/config/fork_schedule")
    if not isinstance(entries, list) or not entries:
        raise Bad("the fork schedule is not a non-empty list")
    schedule = []
    for n, e in enumerate(entries):
        what = f"fork schedule entry {n}"
        schedule.append(
            (
                hex_bytes(field(e, "previous_version", what), 4, f"{what} previous_version"),
                hex_bytes(field(e, "current_version", what), 4, f"{what} current_version"),
                uint(field(e, "epoch", what), f"{what} epoch"),
            )
        )
    gloas_entries = [e for e in schedule if e[1] == gloas]
    if not gloas_entries:
        problems.append(f"Gloas ({gloas}) is not in the fork schedule")
    elif gloas_entries[0][2] != 0:
        problems.append(f"Gloas ({gloas}) at epoch {gloas_entries[0][2]}, not 0")
    at_genesis = [e for e in schedule if e[2] == 0]
    if gloas_entries and at_genesis and at_genesis[-1][1] != gloas:
        problems.append(
            f"the fork in force at epoch 0 is {at_genesis[-1][1]}, not Gloas ({gloas})"
        )
    identity = data_of(load(directory, service, "identity"), "/eth/v1/node/identity")
    digest = enr_fork_digest(identity.get("enr") if isinstance(identity, dict) else None)
    scheduled = [e for e in schedule if e[2] != FAR_FUTURE_EPOCH]
    return (gloas, scheduled), len(schedule) - len(scheduled), problems, digest


def cmd_forks(args):
    failures = []
    schedules = {}
    digests = {}
    for service in args.services:
        try:
            schedule, unscheduled, problems, digest = forks_of(args.dir, service)
        except Bad as e:
            failures.append(f"{service}: {e}")
            continue
        failures.extend(f"{service}: {p}" for p in problems)
        schedules[service] = schedule
        digests[service] = digest
        print(f"{service}: gloas_fork_version {schedule[0]}")
        ignored = f" ({unscheduled} at FAR_FUTURE_EPOCH ignored)" if unscheduled else ""
        print(f"{service}: fork_schedule {len(schedule[1])} scheduled entries{ignored}")
        print(f"{service}: fork_digest {digest}")
    names = list(schedules)
    for other in names[1:]:
        if schedules[other] != schedules[names[0]]:
            failures.append(f"fork schedules differ: {names[0]} and {other}")
    if len(set(digests.values())) > 1:
        listed = ", ".join(f"{s} {d}" for s, d in digests.items())
        failures.append(f"fork digests differ: {listed}")
    for f in failures:
        print(f"- {f}")
    if failures:
        print("fork_schedule: FAIL")
        return 1
    digest = next(iter(digests.values()))
    print(f"fork_schedule: PASS ({len(names)} CLs: Gloas at epoch 0, fork digest {digest})")
    return 0


# --- finality -----------------------------------------------------------------------------------


def cmd_finality(args):
    failures = []
    checkpoints = {}
    for service in args.services:
        try:
            data = data_of(
                load(args.dir, service, "finality"),
                "/eth/v1/beacon/states/head/finality_checkpoints",
            )
            fin = field(data, "finalized", "finality_checkpoints")
            epoch = uint(field(fin, "epoch", "the finalized checkpoint"), "finalized epoch")
            root = hex_bytes(field(fin, "root", "the finalized checkpoint"), 32, "finalized root")
        except Bad as e:
            failures.append(f"{service}: {e}")
            continue
        checkpoints[service] = (epoch, root)
        print(f"{service}: finalized epoch {epoch} root {root}")
    for service, (epoch, _) in checkpoints.items():
        if epoch < args.min_epoch:
            failures.append(f"finalized epoch {epoch} is below {args.min_epoch} on {service}")
    if len(set(checkpoints.values())) > 1:
        listed = ", ".join(f"{s} {e}/{r}" for s, (e, r) in checkpoints.items())
        failures.append(f"finalized checkpoints differ: {listed}")
    for f in failures:
        print(f"- {f}")
    return 1 if failures else 0


# --- goodbye3 -------------------------------------------------------------------------------------

GOODBYE_FAULT = 3
MIN_EPOCHS = 2
PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
SERVICE = re.compile(r"^cl-([0-9]+)-([a-z0-9]+)(-[a-z0-9]+)*$")
# A libp2p peer ID as text: an identity multihash of an ed25519 (12D3KooW…, 52 chars) or
# secp256k1 (16Uiu2HA…, 53) key, or a sha256 one (Qm…, 46), in the base58 alphabet.
PEER_ID = re.compile(r"^(12D3KooW|16Uiu2HA|Qm)[1-9A-HJ-NP-Za-km-z]{40,52}$")
TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d{1,9})?(Z|[+-]\d\d:\d\d)$")
DROPPED = "log lines dropped"


def strip_comment(line):
    """`line` without a YAML comment (a `#` at its start or after whitespace)."""
    for i, c in enumerate(line):
        if c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def participants(path):
    """The participants of an ethereum-package args file, in order, each a dict of its plain
    `key: value` entries. Reads the YAML subset the repo's args files use: a top-level
    `participants:` block list whose items are `- key: value` lines followed by `key: value`
    lines at the item's indentation; deeper lines (nested lists and maps) are skipped."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise Bad(f"args file {path}: {e.strerror}") from None
    items, inside, dash, keys = [], False, None, None
    for raw in lines:
        line = strip_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0:
            if inside:
                break
            inside = body == "participants:"
            continue
        if not inside:
            continue
        if body.startswith("- ") or body == "-":
            if dash is None:
                dash = indent
            if indent != dash:
                continue
            items.append({})
            keys = indent + 2
            body = body[1:].strip()
            if not body:
                continue
        elif keys is None or indent != keys:
            continue
        key, sep, value = body.partition(":")
        if sep and value.strip():
            items[-1][key.strip()] = unquote(value.strip())
    if not items:
        raise Bad(f"args file {path} has no participants")
    return items


def image_of(args_path, items, service):
    """(client, pinned cl_image) of `service` from its participant."""
    m = SERVICE.match(service)
    if not m:
        raise Bad("not a cl-<n>-<client>-... service name")
    n, client = int(m.group(1)), m.group(2)
    if not 1 <= n <= len(items):
        raise Bad(f"no participant {n} in {args_path}")
    item = items[n - 1]
    count = item.get("count", "1")
    if count != "1":
        raise Bad(f"participant {n} of {args_path} has count {count}; one node per participant is needed")
    if item.get("cl_type") != client:
        raise Bad(f"participant {n} of {args_path} runs {item.get('cl_type')}, not {client}")
    image = item.get("cl_image", "")
    if not PINNED_IMAGE.match(image):
        raise Bad(f"cl_image {image or '(none)'} of participant {n} is not pinned by digest")
    return client, image


def epoch_seconds(directory, service):
    spec = data_of(load(directory, service, "spec"), "/eth/v1/config/spec")
    where = "/eth/v1/config/spec"
    slots = uint(field(spec, "SLOTS_PER_EPOCH", where), "SLOTS_PER_EPOCH")
    if isinstance(spec, dict) and "SLOT_DURATION_MS" in spec:
        slot_ms = uint(spec["SLOT_DURATION_MS"], "SLOT_DURATION_MS")
    else:
        slot_ms = 1000 * uint(field(spec, "SECONDS_PER_SLOT", where), "SECONDS_PER_SLOT")
    if slots == 0 or slot_ms == 0:
        raise Bad("an epoch of 0 s in /eth/v1/config/spec")
    return slots * slot_ms / 1000


def peer_of(directory, service):
    identity = data_of(load(directory, service, "identity"), "/eth/v1/node/identity")
    peer = field(identity, "peer_id", "/eth/v1/node/identity")
    if not isinstance(peer, str) or not PEER_ID.fullmatch(peer):
        raise Bad(f"peer_id {json.dumps(peer)} is not a base58 peer ID")
    return peer


def seconds(stamp):
    """An RFC 3339 timestamp as Unix seconds; None if it is not one."""
    m = TIMESTAMP.match(stamp) if isinstance(stamp, str) else None
    if not m:
        return None
    try:
        t = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    zone = m.group(3)
    offset = 0
    if zone != "Z":
        sign = -1 if zone[0] == "-" else 1
        offset = sign * (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60)
    t = t.replace(tzinfo=datetime.timezone.utc)
    return t.timestamp() - offset + float(m.group(2) or 0)


def reason_of(fields):
    """A goodbye_received line's reason: a JSON integer, never a string, float or bool."""
    reason = fields.get("reason")
    return reason if type(reason) is int and reason >= 0 else None


def scan_logs(paths, peers):
    """Per peer of `peers`: {"window": the longest span one log observed it, in seconds, or
    None if no log names it; "logs": how many logs name it; "faults": reason-3 Goodbyes;
    "others": Goodbyes of other reasons}, and the problems that keep the logs from proving there
    was no reason-3 Goodbye. Each log is one run: a peer's window is first to last line naming
    it within that log, never across logs, so runs with a gap between them are not one window."""
    seen = {p: {"window": None, "logs": 0, "faults": 0, "others": 0} for p in peers}
    problems = []
    for path in paths:
        lines = 0
        spans = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for no, raw in enumerate(f, 1):
                    if not raw.strip():
                        continue
                    lines += 1
                    try:
                        line = json.loads(raw)
                    except ValueError:
                        line = None
                    if not isinstance(line, dict) or not isinstance(line.get("fields"), dict):
                        problems.append(f"{path} line {no}: not a JSON log line")
                        continue
                    t = seconds(line.get("timestamp"))
                    if t is None:
                        problems.append(f"{path} line {no}: no RFC 3339 timestamp")
                        continue
                    fields = line["fields"]
                    message = fields.get("message")
                    if isinstance(message, str) and message.startswith(DROPPED):
                        problems.append(
                            f"{path} line {no}: the probe dropped {fields.get('dropped')} log "
                            "lines; a Goodbye may be among them"
                        )
                    peer = fields.get("peer")
                    goodbye = message == "goodbye_received"
                    reason = reason_of(fields) if goodbye else None
                    # Checked before the reference peers are picked out: a line whose peer is no
                    # peer ID could be any CL's.
                    if goodbye and not (isinstance(peer, str) and PEER_ID.fullmatch(peer)):
                        problems.append(f"{path} line {no}: goodbye_received without a peer ID")
                        continue
                    if goodbye and reason is None:
                        problems.append(
                            f"{path} line {no}: goodbye_received without an integer reason"
                        )
                        continue
                    if not isinstance(peer, str) or peer not in seen:
                        continue
                    first, last = spans.get(peer, (t, t))
                    spans[peer] = (min(first, t), max(last, t))
                    if goodbye:
                        seen[peer]["faults" if reason == GOODBYE_FAULT else "others"] += 1
        except OSError as e:
            problems.append(f"{path}: {e.strerror}")
            continue
        if lines == 0:
            problems.append(f"{path}: no log lines")
        for peer, (first, last) in spans.items():
            s = seen[peer]
            s["logs"] += 1
            s["window"] = max(s["window"] or 0.0, last - first)
    return seen, problems


def cmd_goodbye3(args):
    failures, short, peers = [], [], {}
    try:
        items = participants(args.args)
    except Bad as e:
        items = None
        failures.append(str(e))
    owner = {}
    for service in args.services:
        try:
            client, image = image_of(args.args, items, service) if items else (None, None)
            peer = peer_of(args.dir, service)
            if peer in owner:
                raise Bad(f"peer_id {peer} is {owner[peer]}'s too")
            owner[peer] = service
            peers[service] = (peer, epoch_seconds(args.dir, service))
        except Bad as e:
            failures.append(f"{service}: {e}")
            continue
        if image:
            print(f"{service}: image {image}")
    seen, problems = scan_logs(args.log, [p for p, _ in peers.values()])
    failures.extend(problems)
    for service, (peer, epoch) in peers.items():
        s = seen[peer]
        faults, others, observed = s["faults"], s["others"], s["window"]
        if observed is None:
            failures.append(f"{service}: peer {peer} is not in the probe log")
            continue
        epochs = observed / epoch
        print(
            f"{service}: goodbye3 {faults} (other Goodbyes {others}) in {epochs:.1f} epochs "
            f"({observed:.1f} s in one log, peer {peer})"
        )
        if faults:
            plural = "" if faults == 1 else "s"
            failures.append(
                f"{service}: {faults} reason-3 Goodbye{plural} from {peer}; exit 10 (b) wants none"
            )
        elif epochs < MIN_EPOCHS:
            short.append(
                f"{service}: observed {epochs:.1f} epochs, under the {MIN_EPOCHS} an acceptance "
                "run needs"
            )
    for f in failures:
        print(f"- {f}")
    if failures:
        print("goodbye3: FAIL")
        return 1
    for d in short:
        print(f"- {d}")
    if short:
        print(f"goodbye3: DIAGNOSTIC (no reason-3 Goodbye; {len(short)} CL(s) under {MIN_EPOCHS} epochs)")
        return 3
    print(
        f"goodbye3: PASS ({len(peers)} CLs: no reason-3 Goodbye, each over at least "
        f"{MIN_EPOCHS} epochs)"
    )
    return 0


def main(argv):
    parser = argparse.ArgumentParser(prog="devnet.py")
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("genesis")
    g.add_argument("dir")
    g.add_argument("--reference")
    g.add_argument("--record")
    g.add_argument("services", nargs="+")
    f = sub.add_parser("forks")
    f.add_argument("dir")
    f.add_argument("services", nargs="+")
    p = sub.add_parser("pair")
    p.add_argument("--record")
    p.add_argument("name_a")
    p.add_argument("record_a")
    p.add_argument("name_b")
    p.add_argument("record_b")
    n = sub.add_parser("finality")
    n.add_argument("dir")
    n.add_argument("min_epoch", type=int)
    n.add_argument("services", nargs="+")
    b = sub.add_parser("goodbye3")
    b.add_argument("dir")
    b.add_argument("args")
    b.add_argument("--log", action="append", required=True)
    b.add_argument("services", nargs="+")
    args = parser.parse_args(argv)
    run = {
        "genesis": cmd_genesis,
        "forks": cmd_forks,
        "pair": cmd_pair,
        "finality": cmd_finality,
        "goodbye3": cmd_goodbye3,
    }[args.command]
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
