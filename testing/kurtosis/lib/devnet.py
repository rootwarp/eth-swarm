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
"""

import argparse
import base64
import json
import os
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
    args = parser.parse_args(argv)
    run = {
        "genesis": cmd_genesis,
        "forks": cmd_forks,
        "pair": cmd_pair,
        "finality": cmd_finality,
    }[args.command]
    return run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
