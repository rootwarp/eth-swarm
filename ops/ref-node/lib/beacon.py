"""Verdicts on beacon API answers for the reference node (ops/ref-node, Sepolia or Hoodi).

Shared by preflight.sh (against the checkpoint-sync providers) and collect-run-log.sh (against
the local node). Every command reads files the caller fetched, prints its evidence on stdout
and exits 0 on a pass, 1 on a fail, 2 on a usage or input error. Standard library only, run
with `python3 -I`.

    spec-diff PINNED_YAML SPEC_JSON
        /eth/v1/config/spec against the pinned network-config YAML: every *_FORK_VERSION and
        *_FORK_EPOCH key of the pinned file must be on the node with the same value, and
        BLOB_SCHEDULE must hold the same (EPOCH, MAX_BLOBS_PER_BLOCK) entries. A fork key the
        node has and the pinned file lacks fails unless its epoch is FAR_FUTURE_EPOCH (an
        unscheduled fork). The schedule's order does not matter: the spec reads it sorted by
        epoch (get_blob_parameters), so it is compared as a set keyed by epoch, and an epoch
        listed twice fails. Fork versions compare case-insensitively, epochs as integers.

    syncing SYNCING_JSON GENESIS_JSON SPEC_JSON NOW
        One /eth/v1/node/syncing sample: is_syncing, is_optimistic and el_offline must each be
        JSON false, and head_slot within 2 slots (either way) of the wall-clock slot
        floor((NOW - genesis_time) / SECONDS_PER_SLOT), genesis_time from
        /eth/v1/beacon/genesis and SECONDS_PER_SLOT (else SLOT_DURATION_MS) from the spec.

    finalized HEADER_JSON DATABASE_INFO_JSON
        The finalized slot (/eth/v1/beacon/headers/finalized) must be at least 128 slots past
        the oldest stored block: Lighthouse's /lighthouse/database/info `anchor.oldest_block_slot`.
        An anchor that is absent, null or without `oldest_block_slot` proves nothing about the
        oldest block, so it fails (closed: never read as "blocks from genesis").

    identity IDENTITY_JSON PUBLIC_IP P2P_PORT
        /eth/v1/node/identity: peer_id (base58), p2p_addresses and metadata.custody_group_count,
        and the m2a-session multiaddr /ip4/<ip>/tcp/<P2P_PORT>/p2p/<peer_id> (P2P_PORT is
        Lighthouse's configured libp2p TCP port). <ip> is PUBLIC_IP when it is not empty, else
        the first global IPv4 address among p2p_addresses. Value lines are `key: value`;
        anything wrong is an `error: ...` line, never a value line.

    anchor-compare HEADER_1_JSON HEADER_2_JSON
        Two checkpoint providers agree on the anchor: HEADER_1 is provider 1's
        /eth/v1/beacon/headers/finalized, HEADER_2 provider 2's /eth/v1/beacon/headers/<that
        slot>. Both must name the same slot, block root and header state_root, and both must
        hold the header as canonical. A root that is not 32 bytes of hex, or a header
        without a slot, is an input error.

    header-slot HEADER_JSON
        The slot of a /eth/v1/beacon/headers answer (decimal), for fetching provider 2's
        header at provider 1's finalized slot.

    container INSPECT_JSON SERVICE DATA_ROOT UID GID PINNED_IMAGE_ID
        One running container (`docker inspect <id>`) against what compose.yaml asks for, one
        line per check: the pinned image ID; Config.User is exactly UID:GID, neither 0;
        ReadonlyRootfs; CapDrop holds ALL and CapAdd is empty; SecurityOpt is exactly
        no-new-privileges:true (so no seccomp or AppArmor profile is switched off); not
        Privileged; NetworkMode host; no GroupAdd and no Devices; PidMode and IpcMode neither
        host nor another container's, UTSMode not host, and CgroupnsMode exactly "private"
        (compose.yaml sets cgroup: private; without it a cgroup v1 engine reports "host", and
        an engine that reports none is not checkable); MaskedPaths and ReadonlyPaths both
        non-empty (security_opt systempaths=unconfined empties them and does not show in
        SecurityOpt); exactly two mounts, DATA_ROOT/SERVICE/data on /data
        (read-write) and DATA_ROOT/SERVICE/jwt.hex on /secrets/jwt.hex (read-only), besides a
        /tmp tmpfs; and exactly one tmpfs, /tmp, mounted noexec, nosuid and nodev (none of
        exec, suid or dev after them). An override file that loosens any of these fails here.
"""

import ipaddress
import json
import re
import sys

FAR_FUTURE_EPOCH = 2**64 - 1
FORK_KEY = re.compile(r"^[A-Z][A-Z0-9_]*_FORK_(VERSION|EPOCH)$")
TOP_LEVEL = re.compile(r"^([A-Z][A-Z0-9_]*):(?:[ \t]+(.*))?$")
ITEM_FIELD = re.compile(r"^[ \t]*(-[ \t]+)?([A-Z][A-Z0-9_]*):[ \t]+(\S+)$")
SCHEDULE_FIELDS = {"EPOCH", "MAX_BLOBS_PER_BLOCK"}


class InputError(Exception):
    """An input that cannot be judged: exit 2, never a pass."""


def strip_comment(line):
    """The line without a `#` comment (at the start or after whitespace) and trailing space."""
    return re.sub(r"(^|[ \t])#.*$", "", line).rstrip()


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def parse_pinned(text):
    """The top-level `KEY: value` scalars and the BLOB_SCHEDULE entries of a config YAML.

    Only the shape network-config uses is accepted: top-level scalars, and lists of flat
    `- KEY: value` items. Anything else is an InputError rather than a guess.
    """
    scalars, schedule = {}, None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = strip_comment(lines[i])
        i += 1
        if not line.strip():
            continue
        if line[0] in " \t-":
            raise InputError(f"pinned config line {i}: indented line outside a list")
        m = TOP_LEVEL.match(line)
        if not m:
            raise InputError(f"pinned config line {i}: not KEY: value")
        key, value = m.group(1), (m.group(2) or "").strip()
        if key in scalars or (key == "BLOB_SCHEDULE" and schedule is not None):
            raise InputError(f"pinned config line {i}: {key} appears twice")
        if value and value != "[]":
            scalars[key] = unquote(value)
            continue
        items = []
        while i < len(lines):
            item = strip_comment(lines[i])
            if item.strip() and item[0] not in " \t":
                break
            i += 1
            if not item.strip():
                continue
            f = ITEM_FIELD.match(item)
            if not f:
                raise InputError(f"pinned config line {i}: not a flat list item")
            if f.group(1):
                items.append({})
            elif not items:
                raise InputError(f"pinned config line {i}: list field before the first item")
            items[-1][f.group(2)] = unquote(f.group(3))
        if value == "[]" and items:
            raise InputError(f"pinned config: {key}: [] followed by items")
        if key == "BLOB_SCHEDULE":
            schedule = items
        else:
            scalars[key] = items
    if schedule is None:
        raise InputError("pinned config has no BLOB_SCHEDULE")
    pinned_schedule = {}
    for n, entry in enumerate(schedule, 1):
        if set(entry) != SCHEDULE_FIELDS:
            raise InputError(f"pinned BLOB_SCHEDULE entry {n} is not {{EPOCH, MAX_BLOBS_PER_BLOCK}}")
        epoch, max_blobs = as_int(entry["EPOCH"]), as_int(entry["MAX_BLOBS_PER_BLOCK"])
        if epoch is None or max_blobs is None or epoch in pinned_schedule:
            raise InputError(f"pinned BLOB_SCHEDULE entry {n} is malformed or repeats an epoch")
        pinned_schedule[epoch] = max_blobs
    forks = {k: v for k, v in scalars.items() if FORK_KEY.match(k) and isinstance(v, str)}
    if not forks:
        raise InputError("pinned config has no *_FORK_VERSION / *_FORK_EPOCH keys")
    return forks, pinned_schedule


def as_int(value):
    """A non-negative integer from a JSON number or decimal string, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    return None


def same_value(key, pinned, node):
    if key.endswith("_FORK_EPOCH"):
        return as_int(pinned) is not None and as_int(pinned) == as_int(node)
    return isinstance(node, str) and pinned.lower() == node.lower()


def show(value):
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]+|0[xX][0-9a-fA-F]+", value) else json.dumps(value)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise InputError(f"{path}: not a JSON answer ({e.__class__.__name__})") from None
    if isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        doc = doc["data"]
    if not isinstance(doc, dict):
        raise InputError(f"{path}: not a JSON object")
    return doc


def schedule_diffs(pinned, node_schedule):
    if node_schedule is None:
        return ["BLOB_SCHEDULE: missing on the node"]
    if not isinstance(node_schedule, list):
        return ["BLOB_SCHEDULE: not a list on the node"]
    diffs, node, seen = [], {}, {}
    for n, entry in enumerate(node_schedule, 1):
        epoch = max_blobs = None
        if isinstance(entry, dict) and set(entry) == SCHEDULE_FIELDS:
            epoch, max_blobs = as_int(entry["EPOCH"]), as_int(entry["MAX_BLOBS_PER_BLOCK"])
        if epoch is None or max_blobs is None:
            diffs.append(f"BLOB_SCHEDULE: entry {n} on the node is not {{EPOCH, MAX_BLOBS_PER_BLOCK}}: "
                         f"{json.dumps(entry)}")
            continue
        seen[epoch] = seen.get(epoch, 0) + 1
        node.setdefault(epoch, max_blobs)
    diffs += [f"BLOB_SCHEDULE: epoch {e} appears {c} times on the node" for e, c in sorted(seen.items()) if c > 1]
    for epoch in sorted(set(pinned) | set(node)):
        if epoch not in node:
            diffs.append(f"BLOB_SCHEDULE: epoch {epoch} (max {pinned[epoch]}) missing on the node")
        elif epoch not in pinned:
            diffs.append(f"BLOB_SCHEDULE: epoch {epoch} (max {node[epoch]}) not in the pinned config")
        elif pinned[epoch] != node[epoch]:
            diffs.append(f"BLOB_SCHEDULE: epoch {epoch}: pinned max {pinned[epoch]}, node max {node[epoch]}")
    return diffs


def spec_diff(pinned_path, spec_path):
    try:
        with open(pinned_path, encoding="utf-8") as f:
            forks, schedule = parse_pinned(f.read())
    except OSError as e:
        raise InputError(f"{pinned_path}: {e.strerror}") from None
    node = load_json(spec_path)
    diffs = []
    for key, value in forks.items():
        if key not in node:
            diffs.append(f"{key}: pinned {value}, missing on the node")
        elif not same_value(key, value, node[key]):
            diffs.append(f"{key}: pinned {value}, node {show(node[key])}")
    for key in sorted(k for k in node if FORK_KEY.match(k) and k not in forks):
        epoch_key = key[: -len("VERSION")] + "EPOCH" if key.endswith("_VERSION") else key
        if as_int(node.get(epoch_key)) == FAR_FUTURE_EPOCH:
            continue
        diffs.append(f"{key}: node {show(node[key])}, not in the pinned config")
    diffs += schedule_diffs(schedule, node.get("BLOB_SCHEDULE"))
    versions = sum(k.endswith("_VERSION") for k in forks)
    summary = f"{versions} fork versions, {len(forks) - versions} fork epochs, {len(schedule)} blob schedule entries"
    if not diffs:
        print(f"spec diff: empty ({summary})")
        return 0
    print(f"spec diff: {len(diffs)} difference(s) ({summary} pinned)")
    for d in diffs:
        print(f"- {d}")
    if not any(k in node for k in forks):
        print("note: the answer has no fork keys at all; a checkpointz proxy serves only part of "
              "the spec, so it cannot be checked: use a full beacon node's API")
    return 1

MAX_SLOT_LAG = 2
MIN_FINALIZED_RANGE = 128
PEER_ID = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,128}")


def verdict(passed):
    return "PASS" if passed else "FAIL"


def flag(data, key):
    """`key false` / `key true` for a JSON boolean, else how it differs; and whether it is false."""
    if key not in data:
        return f"{key} missing", False
    value = data[key]
    if isinstance(value, bool):
        return f"{key} {str(value).lower()}", value is False
    return f"{key} {json.dumps(value)}", False


def seconds_per_slot(spec):
    sps = as_int(spec.get("SECONDS_PER_SLOT"))
    if sps is None:
        ms = as_int(spec.get("SLOT_DURATION_MS"))
        sps = ms // 1000 if ms is not None and ms % 1000 == 0 else None
    if not sps:
        raise InputError("the spec has no positive SECONDS_PER_SLOT or SLOT_DURATION_MS")
    return sps


def syncing(syncing_path, genesis_path, spec_path, now):
    data = load_json(syncing_path)
    genesis_time = as_int(load_json(genesis_path).get("genesis_time"))
    if genesis_time is None:
        raise InputError("the genesis answer has no genesis_time")
    sps = seconds_per_slot(load_json(spec_path))
    now = as_int(now)
    if now is None or now < genesis_time:
        raise InputError("NOW is not a unix time past genesis")
    wall = (now - genesis_time) // sps
    head = as_int(data.get("head_slot"))
    parts, passed = [], head is not None
    if head is None:
        parts.append(f"head_slot {json.dumps(data.get('head_slot'))}, wall-clock slot {wall}")
    else:
        lag = wall - head
        passed = abs(lag) <= MAX_SLOT_LAG
        parts.append(f"head_slot {head}, wall-clock slot {wall} (lag {lag})")
    for key in ("is_syncing", "is_optimistic", "el_offline"):
        text, ok = flag(data, key)
        parts.append(text)
        passed = passed and ok
    print(f"{', '.join(parts)}: {verdict(passed)}")
    return 0 if passed else 1


def finalized(header_path, info_path):
    header = load_json(header_path)
    slot = as_int(((header.get("header") or {}).get("message") or {}).get("slot"))
    if slot is None:
        raise InputError("the finalized header answer has no header.message.slot")
    info = load_json(info_path)
    if "anchor" not in info:
        print(f"finalized slot {slot}, oldest block slot unknown (no anchor): FAIL")
        return 1
    anchor = info["anchor"]
    oldest = as_int(anchor.get("oldest_block_slot")) if isinstance(anchor, dict) else None
    source = "anchor.oldest_block_slot"
    if oldest is None:
        print(f"finalized slot {slot}, oldest block slot unknown (anchor: {json.dumps(anchor)}): FAIL")
        return 1
    span = slot - oldest
    passed = span >= MIN_FINALIZED_RANGE
    print(f"finalized slot {slot}, oldest block slot {oldest} ({source}): {span} slots: {verdict(passed)}")
    return 0 if passed else 1


def public_ipv4(addresses):
    for addr in addresses:
        m = re.match(r"^/ip4/([0-9.]+)/", addr) if isinstance(addr, str) else None
        if m:
            try:
                ip = ipaddress.IPv4Address(m.group(1))
            except ValueError:
                continue
            if ip.is_global:
                return str(ip)
    return None


def identity(identity_path, public_ip, p2p_port):
    port = as_int(p2p_port)
    if port is None or not 0 < port < 65536 or str(port) != p2p_port:
        raise InputError("the p2p port is not a TCP port number")
    data = load_json(identity_path)
    passed = True
    peer_id = data.get("peer_id")
    if isinstance(peer_id, str) and PEER_ID.fullmatch(peer_id):
        print(f"peer_id: {peer_id}")
    else:
        print("error: peer_id is not base58 or missing")
        peer_id, passed = None, False
    addresses = data.get("p2p_addresses")
    if not isinstance(addresses, list):
        addresses = []
    print(f"p2p_addresses: {', '.join(a for a in addresses if isinstance(a, str)) or 'none'}")
    cgc = as_int((data.get("metadata") or {}).get("custody_group_count"))
    if cgc is None:
        print("error: custody_group_count is missing")
        passed = False
    else:
        print(f"custody_group_count: {cgc}")
    if public_ip:
        try:
            ip = str(ipaddress.IPv4Address(public_ip))
        except ValueError:
            print("error: --public-ip is not an IPv4 address")
            return 1
    else:
        ip = public_ipv4(addresses)
        if ip is None:
            print("error: no public IPv4 address in p2p_addresses; pass --public-ip")
            return 1
    if peer_id:
        print(f"multiaddr: /ip4/{ip}/tcp/{port}/p2p/{peer_id}")
    return 0 if passed else 1


ROOT = re.compile(r"0x[0-9a-fA-F]{64}")


def anchor_header(path, who):
    """(slot, block root, state root, canonical) of a /eth/v1/beacon/headers answer."""
    try:
        data = load_json(path)
    except InputError as e:
        raise InputError(f"{who}: {e}") from None
    header = data.get("header") if isinstance(data.get("header"), dict) else {}
    message = header.get("message") if isinstance(header.get("message"), dict) else {}
    slot = as_int(message.get("slot"))
    if slot is None:
        raise InputError(f"{who}: the header answer has no header.message.slot")
    root, state_root = data.get("root"), message.get("state_root")
    if not (isinstance(root, str) and ROOT.fullmatch(root)):
        raise InputError(f"{who}: the header answer has no 32-byte root")
    if not (isinstance(state_root, str) and ROOT.fullmatch(state_root)):
        raise InputError(f"{who}: the header answer has no 32-byte header.message.state_root")
    return slot, root.lower(), state_root.lower(), data.get("canonical") is True


def header_slot(path):
    print(anchor_header(path, "provider 1")[0])
    return 0


def anchor_compare(path_1, path_2):
    slot_1, root_1, state_1, canonical_1 = anchor_header(path_1, "provider 1")
    slot_2, root_2, state_2, canonical_2 = anchor_header(path_2, "provider 2")
    if slot_1 != slot_2:
        print(f"anchor: slot {slot_1} on provider 1, {slot_2} on provider 2: FAIL")
        return 1
    problems = []
    if root_1 != root_2:
        problems.append(f"block root {root_1} on provider 1, {root_2} on provider 2")
    if state_1 != state_2:
        problems.append(f"state root {state_1} on provider 1, {state_2} on provider 2")
    if not canonical_1:
        problems.append("not canonical on provider 1")
    if not canonical_2:
        problems.append("not canonical on provider 2")
    if problems:
        print(f"anchor: slot {slot_1}: {'; '.join(problems)}: FAIL")
        return 1
    print(f"anchor: slot {slot_1}, block root {root_1}, state root {state_1}, the same on both providers: PASS")
    return 0


SECURITY_OPT = ["no-new-privileges:true"]
TMPFS_FLAGS = {"noexec": "exec", "nosuid": "suid", "nodev": "dev"}


def tmpfs_ok(tmpfs):
    """Exactly a /tmp tmpfs whose options end up noexec, nosuid and nodev (mount applies the
    options in order, so a later exec, suid or dev undoes its no-flag)."""
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"} or not isinstance(tmpfs["/tmp"], str):
        return False
    final = {}
    for opt in (o.strip() for o in tmpfs["/tmp"].split(",")):
        for flag, opposite in TMPFS_FLAGS.items():
            if opt in (flag, opposite):
                final[flag] = opt == flag
    return all(final.get(flag) for flag in TMPFS_FLAGS)


def own_namespace(mode, may_join):
    """A namespace mode that is neither the host's nor, if `may_join`, another container's."""
    if not isinstance(mode, str):
        return False
    return mode != "host" and not (may_join and mode.startswith("container:"))


def container(inspect_path, service, data_root, uid, gid, pinned_id):
    try:
        with open(inspect_path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        raise InputError("the docker inspect output is not JSON") from None
    c = doc[0] if isinstance(doc, list) and doc else doc
    if not isinstance(c, dict):
        raise InputError("the docker inspect output is not a container")
    host = c.get("HostConfig") or {}
    config = c.get("Config") or {}
    results = []

    def line(text, passed):
        results.append(passed)
        print(f"{text}: {verdict(passed)}")

    image = c.get("Image")
    line(f"image {image}, pinned image {pinned_id}", isinstance(image, str) and image == pinned_id and image.startswith("sha256:"))
    user = config.get("User") or ""
    ids_ok = all(as_int(i) not in (None, 0) for i in (uid, gid))
    line(f"Config.User {user or '(none)'} (want {uid}:{gid})", ids_ok and user == f"{uid}:{gid}")
    line(f"ReadonlyRootfs {json.dumps(host.get('ReadonlyRootfs'))}", host.get("ReadonlyRootfs") is True)
    cap_drop, cap_add = host.get("CapDrop") or [], host.get("CapAdd") or []
    line(f"CapDrop {json.dumps(cap_drop)}, CapAdd {json.dumps(cap_add)}", "ALL" in cap_drop and not cap_add)
    sec = host.get("SecurityOpt") or []
    line(f"SecurityOpt {json.dumps(sec)}", sec == SECURITY_OPT)
    line(f"Privileged {json.dumps(host.get('Privileged'))}", host.get("Privileged") is False)
    line(f"NetworkMode {json.dumps(host.get('NetworkMode'))}", host.get("NetworkMode") == "host")
    group_add = host.get("GroupAdd")
    line(f"GroupAdd {json.dumps(group_add)}", group_add in (None, []))
    devices = host.get("Devices")
    shown = [d.get("PathOnHost") if isinstance(d, dict) else d for d in devices] if isinstance(devices, list) else devices
    line(f"Devices {json.dumps(shown)}", devices in (None, []))
    for key, may_join in (("PidMode", True), ("IpcMode", True), ("UTSMode", False)):
        line(f"{key} {json.dumps(host.get(key))}", own_namespace(host.get(key), may_join))
    if "CgroupnsMode" in host:
        line(f"CgroupnsMode {json.dumps(host['CgroupnsMode'])}", host["CgroupnsMode"] == "private")
    else:
        line("CgroupnsMode (none)", False)
    masked, readonly = host.get("MaskedPaths"), host.get("ReadonlyPaths")
    counts = [len(p) if isinstance(p, list) else 0 for p in (masked, readonly)]
    line(f"MaskedPaths {counts[0]}, ReadonlyPaths {counts[1]}", all(counts))
    want = {
        "/data": (f"{data_root}/{service}/data", True),
        "/secrets/jwt.hex": (f"{data_root}/{service}/jwt.hex", False),
    }
    mounts, mounts_ok = [], True
    seen = set()
    for m in c.get("Mounts") or []:
        dest, src, rw, kind = m.get("Destination"), m.get("Source"), m.get("RW"), m.get("Type")
        mounts.append(f"{dest} <- {src} ({kind}, {'rw' if rw else 'ro'})")
        if kind == "tmpfs" and dest == "/tmp":
            continue
        if kind != "bind" or dest not in want or want[dest] != (src, rw) or dest in seen:
            mounts_ok = False
        seen.add(dest)
    line(f"mounts {'; '.join(mounts) or 'none'}", mounts_ok and seen == set(want))
    tmpfs = host.get("Tmpfs") or {}
    line(f"tmpfs {json.dumps(tmpfs, sort_keys=True)}", tmpfs_ok(tmpfs))
    return 0 if all(results) else 1


COMMANDS = {
    "spec-diff": (spec_diff, 2),
    "syncing": (syncing, 4),
    "finalized": (finalized, 2),
    "identity": (identity, 3),
    "anchor-compare": (anchor_compare, 2),
    "header-slot": (header_slot, 1),
    "container": (container, 6),
}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS or len(argv) - 2 != COMMANDS[argv[1]][1]:
        print(f"usage: beacon.py {{{'|'.join(COMMANDS)}}} ARGS... (see the module docstring)", file=sys.stderr)
        return 2
    func, _ = COMMANDS[argv[1]]
    try:
        return func(*argv[2:])
    except InputError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
