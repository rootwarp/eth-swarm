"""Lint the probe systemd units: python3 -I lint_units.py DIR

DIR must hold ethswarm-p2p.service, ethswarm-discv5.service and ethswarm-chain.service, and
each must equal its committed version: every line systemd reads (not blank, not a comment)
equals, in order and byte for byte, its entry in EXPECTED; only Description= may differ. That
exact pin is the rule; the checks below run as well, as defence in depth and for clearer
messages. Each unit must, in its [Service] section unless noted:
  - hold only allow-listed keys (ALLOWED below: exactly the keys the committed units use, per
    section; any other key or section is refused, so a directive that changes how the reviewed
    lines run, such as PermissionsStartOnly= or SuccessExitStatus=, cannot slip in);
  - run as its own user and group: User=ethswarm-<svc> and Group= the same (never root, no
    DynamicUser= or SupplementaryGroups=, which the allow-list refuses);
  - get the node key only as the credential `nodekey` (p2p and discv5): exactly one
    LoadCredential=nodekey:<absolute path>, no SetCredential*/ImportCredential/other credential,
    and the source path and `--node-key` nowhere else in the unit; cl-chain gets no credential;
  - gate the start on the anchor check: an ExecStartPre= running `/…/anchor-fetch --providers
    <value> --check`, its only other argument `--scratch <absolute dir>` (so no `--help`,
    `--out`, `--config`, `--allow-insecure-http`, or `--quiet`, which would keep the providers
    out of the journal), with no prefix that ignores its failure (`-`);
  - run no Exec*= line (ExecStart, ExecStartPre, ExecStartPost, ExecStop, ExecStopPost,
    ExecReload, ExecCondition) with a prefix that drops the sandbox or the user (`+`, `!`, `!!`,
    alone or with `@`, `-`, `:`) or runs a shell (`|`); and, fail-closed, none with a quote, a
    backslash or a bare `;` word, which systemd resolves before it reads the prefixes;
  - give the check its time: TimeoutStartSec= at least CHECK_BUDGET + MARGIN seconds, finite;
  - not loop on a refusal: RestartSec= at least 60 s, RestartPreventExitStatus= covering
    1 2 64 with exit codes only (a signal name there would turn an OOM kill, SIGKILL, into a
    stop), and in [Unit] StartLimitIntervalSec= at least 1 h and StartLimitBurst= 1 to 5;
  - hold its memory: MemoryMax= a finite positive size (digits and an optional K, M, G or T
    suffix), no MemoryHigh= (without swap, past it the kernel only throttles, so the probe
    stalls instead of being killed), MemorySwapMax=0 (no swap to grow into) and
    OOMPolicy=stop or kill (never continue, and never the host's DefaultOOMPolicy=), so an OOM
    kill fails the unit and Restart= applies;
  - carry the full hardening set of the committed units (HARDENING below, plus an empty
    CapabilityBoundingSet= and no AmbientCapabilities=, RestrictAddressFamilies= exactly the
    unit's "families" in UNITS (AF_UNIX AF_INET AF_INET6, and for cl-p2p AF_NETLINK too: libp2p-tcp's
    wildcard listen watches the interfaces through a netlink route socket), StateDirectory= the
    user's name, and ReadWritePaths= exactly its /var/lib/<StateDirectory>).
Fail-closed reading: a unit file may hold only tab, newline and printable ASCII bytes, no
backslash, and no line that is not blank, a comment, a [section] header or a key=value inside
a section; anything else refuses the whole file, so there is no continuation, escape or exotic
line end to model. No line may be LINE_MAX (2048) bytes or longer: a systemd that reads unit
files through fgets() into a LINE_MAX buffer reads the bytes from 2048 on as a line of their
own, so a long comment could hide a setting (current systemd refuses a line of 1 MiB or more
instead). No file may exceed FILE_MAX (64 KiB). No `*.d` drop-in directory and no `*.service` other than
the three may sit in DIR (an install by glob would pick it up unlinted). Of systemd's syntax
the lint then models only `#`/`;` comments, an empty assignment resetting a list setting (and
a single-valued one to its default), and the last assignment of a single-valued setting
winning.

Exit: 0 every rule holds (prints "ok: 3 units"), 1 a rule fails (one line per finding,
"<unit>: <finding>"), 2 usage or an unreadable DIR.
"""

import os
import re
import shlex
import sys

# The address families each unit may use, exactly. cl-p2p alone needs AF_NETLINK: for a wildcard
# listen (/ip4/0.0.0.0/tcp/...) libp2p-tcp watches the host's interfaces (if-watch) through a
# netlink route socket, and without it the listen fails at start. cl-discv5 binds one UDP socket
# and cl-chain uses Unix and TCP sockets only, so neither gets netlink.
INET = ["AF_UNIX", "AF_INET", "AF_INET6"]
UNITS = {
    "ethswarm-p2p.service": {"user": "ethswarm-p2p", "node_key": True,
                             "families": INET + ["AF_NETLINK"]},
    "ethswarm-discv5.service": {"user": "ethswarm-discv5", "node_key": True, "families": INET},
    "ethswarm-chain.service": {"user": "ethswarm-chain", "node_key": False, "families": INET},
}
CREDENTIAL = "nodekey"
# The shortest line refused. systemd 257 reads unit files with read_line(LONG_LINE_MAX = 1 MiB)
# and refuses the whole file on a line of that length or more; a systemd reading them through
# fgets() into a LINE_MAX (2048) buffer instead splits a longer line, and its tail from byte
# 2048 on is read as a line of its own, which could hold a setting this lint took for comment.
# At 2047 bytes or less every systemd reads a line whole (the longest committed is under 100).
LINE_MAX = 2048
# A unit file's size cap: the committed units are under 4 KiB.
FILE_MAX = 64 * 1024
TRUE = {"yes", "y", "true", "t", "on", "1"}
# Settings whose assignments accumulate, and which an empty assignment resets.
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
             "ExecReload", "ExecCondition")
LISTS = {
    "LoadCredential", "LoadCredentialEncrypted", "SetCredential", "SetCredentialEncrypted",
    "ImportCredential", "Environment", "EnvironmentFile", "CapabilityBoundingSet",
    "AmbientCapabilities", "RestrictAddressFamilies", "ReadWritePaths", "StateDirectory",
    "SystemCallFilter", "SystemCallArchitectures", "RestartPreventExitStatus",
} | set(EXEC_KEYS)
# The single-valued hardening settings and their only accepted values (the last assignment
# wins; an empty one resets to the default, which is never accepted).
HARDENING = {
    "NoNewPrivileges": TRUE, "ProtectSystem": {"strict"}, "ProtectHome": TRUE,
    "PrivateTmp": TRUE, "PrivateDevices": TRUE, "RestrictNamespaces": TRUE,
    "RestrictRealtime": TRUE, "RestrictSUIDSGID": TRUE, "LockPersonality": TRUE,
    "MemoryDenyWriteExecute": TRUE, "ProtectKernelTunables": TRUE,
    "ProtectKernelModules": TRUE, "ProtectKernelLogs": TRUE, "ProtectControlGroups": TRUE,
    "ProtectClock": TRUE, "ProtectHostname": TRUE, "ProtectProc": {"invisible"},
    "ProcSubset": {"pid"}, "UMask": {"0077"},
    # No swap: the memory ceiling is the unit's RAM, not RAM plus whatever swap it can fill.
    "MemorySwapMax": {"0"},
    # An OOM kill stops the unit with result oom-kill, a failure Restart=on-failure restarts
    # (within the start limit); pinned here so the host's DefaultOOMPolicy= cannot make it
    # `continue`.
    "OOMPolicy": {"stop", "kill"},
}
# The list hardening settings and their exact effective words.
HARDENING_LISTS = {
    "SystemCallFilter": ["@system-service", "~@privileged"],
    "SystemCallArchitectures": ["native"],
}
# The anchor check's worst case with anchor-fetch's defaults (config.rs): four JSON requests
# at 30 s, and the block and the state at 30 s for the headers plus 1800 s for the body.
CHECK_BUDGET = 4 * 30 + 2 * (30 + 1800)
MARGIN = 300
PREVENT = {"1", "2", "64"}
# The memory ceiling's sizes, base 1024 as systemd's parse_size(), as bytes. Stricter than
# systemd: whole numbers only (no fraction, sign or exponent) and K, M, G or T at most. At most
# 20 digits (2^64 has 20), so int() never meets Python's digit limit for str-to-int.
SIZE_UNITS = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
SIZE = re.compile(r"([0-9]{1,20})([KMGT]?)")
# systemd's sizes are uint64, and UINT64_MAX is its infinity: a finite size is below it.
SIZE_LIMIT = (1 << 64) - 1
TIME_UNITS = {
    "us": 1e-6, "usec": 1e-6, "ms": 1e-3, "msec": 1e-3, "s": 1, "sec": 1, "second": 1,
    "seconds": 1, "m": 60, "min": 60, "minute": 60, "minutes": 60, "h": 3600, "hr": 3600,
    "hour": 3600, "hours": 3600, "d": 86400, "day": 86400, "days": 86400,
}
# The keys each section may hold: exactly those the three committed units use, nothing else.
# Any other key (PermissionsStartOnly=, SuccessExitStatus=, ExecCondition=,
# SupplementaryGroups=, ...) can change what the reviewed lines mean, so it is refused. Adding a
# directive to a unit means adding it here, after review.
ALLOWED = {
    "Unit": {"Description", "Wants", "After", "StartLimitIntervalSec", "StartLimitBurst"},
    "Service": {
        "Type", "User", "Group", "UMask", "EnvironmentFile", "ExecStartPre", "TimeoutStartSec",
        "ExecStart", "LoadCredential", "StateDirectory", "StateDirectoryMode",
        "RuntimeDirectory", "RuntimeDirectoryMode", "ReadWritePaths", "NoNewPrivileges",
        "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
        "CapabilityBoundingSet", "AmbientCapabilities", "RestrictAddressFamilies",
        "RestrictNamespaces", "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality",
        "MemoryDenyWriteExecute", "ProtectKernelTunables", "ProtectKernelModules",
        "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "ProtectHostname",
        "ProtectProc", "ProcSubset", "SystemCallArchitectures", "SystemCallFilter", "Restart",
        "RestartSec", "RestartPreventExitStatus", "MemoryMax", "MemorySwapMax", "OOMPolicy",
    },
    "Install": {"WantedBy"},
}
CREDENTIAL_KEYS = ("LoadCredential", "LoadCredentialEncrypted", "SetCredential",
                   "SetCredentialEncrypted", "ImportCredential")


# The three units, pinned line for line: (section, key, value) for every line systemd reads, in
# order, with a header as (section, None, None). Generated from ops/probe/*.service and kept
# here as data: a change to a unit is a reviewed change to the unit AND to this table, in the
# same commit. Only Description= may differ; blank lines and comments are ignored.
EXPECTED = {
    "ethswarm-p2p.service": (
        ('Unit', None, None),
        ('Unit', 'Description', 'ETH Swarm probe: cl-p2p (libp2p req/resp; gossip IGNORE-all)'),
        ('Unit', 'Wants', 'network-online.target'),
        ('Unit', 'After', 'network-online.target'),
        ('Unit', 'StartLimitIntervalSec', '6h'),
        ('Unit', 'StartLimitBurst', '3'),
        ('Service', None, None),
        ('Service', 'Type', 'simple'),
        ('Service', 'User', 'ethswarm-p2p'),
        ('Service', 'Group', 'ethswarm-p2p'),
        ('Service', 'UMask', '0077'),
        ('Service', 'EnvironmentFile', '/etc/ethswarm/anchor-check.env'),
        ('Service', 'ExecStartPre', '/usr/local/bin/anchor-fetch --providers ${ANCHOR_PROVIDERS} --check'),
        ('Service', 'TimeoutStartSec', '70min'),
        ('Service', 'ExecStart', '/usr/local/bin/cl-p2p'),
        ('Service', 'LoadCredential', 'nodekey:/etc/ethswarm/credentials/nodekey'),
        ('Service', 'StateDirectory', 'ethswarm-p2p'),
        ('Service', 'StateDirectoryMode', '0700'),
        ('Service', 'RuntimeDirectory', 'ethswarm/cl-p2p'),
        ('Service', 'RuntimeDirectoryMode', '0750'),
        ('Service', 'ReadWritePaths', '/var/lib/ethswarm-p2p'),
        ('Service', 'NoNewPrivileges', 'yes'),
        ('Service', 'ProtectSystem', 'strict'),
        ('Service', 'ProtectHome', 'yes'),
        ('Service', 'PrivateTmp', 'yes'),
        ('Service', 'PrivateDevices', 'yes'),
        ('Service', 'CapabilityBoundingSet', ''),
        ('Service', 'AmbientCapabilities', ''),
        ('Service', 'RestrictAddressFamilies', 'AF_UNIX AF_INET AF_INET6 AF_NETLINK'),
        ('Service', 'RestrictNamespaces', 'yes'),
        ('Service', 'RestrictRealtime', 'yes'),
        ('Service', 'RestrictSUIDSGID', 'yes'),
        ('Service', 'LockPersonality', 'yes'),
        ('Service', 'MemoryDenyWriteExecute', 'yes'),
        ('Service', 'ProtectKernelTunables', 'yes'),
        ('Service', 'ProtectKernelModules', 'yes'),
        ('Service', 'ProtectKernelLogs', 'yes'),
        ('Service', 'ProtectControlGroups', 'yes'),
        ('Service', 'ProtectClock', 'yes'),
        ('Service', 'ProtectHostname', 'yes'),
        ('Service', 'ProtectProc', 'invisible'),
        ('Service', 'ProcSubset', 'pid'),
        ('Service', 'SystemCallArchitectures', 'native'),
        ('Service', 'SystemCallFilter', '@system-service'),
        ('Service', 'SystemCallFilter', '~@privileged'),
        ('Service', 'MemoryMax', '7G'),
        ('Service', 'MemorySwapMax', '0'),
        ('Service', 'OOMPolicy', 'stop'),
        ('Service', 'Restart', 'on-failure'),
        ('Service', 'RestartSec', '5min'),
        ('Service', 'RestartPreventExitStatus', '1 2 64'),
        ('Install', None, None),
        ('Install', 'WantedBy', 'multi-user.target'),
    ),
    "ethswarm-discv5.service": (
        ('Unit', None, None),
        ('Unit', 'Description', 'ETH Swarm probe: cl-discv5 (discv5 peer discovery)'),
        ('Unit', 'Wants', 'network-online.target'),
        ('Unit', 'After', 'network-online.target'),
        ('Unit', 'StartLimitIntervalSec', '6h'),
        ('Unit', 'StartLimitBurst', '3'),
        ('Service', None, None),
        ('Service', 'Type', 'simple'),
        ('Service', 'User', 'ethswarm-discv5'),
        ('Service', 'Group', 'ethswarm-discv5'),
        ('Service', 'UMask', '0077'),
        ('Service', 'EnvironmentFile', '/etc/ethswarm/anchor-check.env'),
        ('Service', 'ExecStartPre', '/usr/local/bin/anchor-fetch --providers ${ANCHOR_PROVIDERS} --check'),
        ('Service', 'TimeoutStartSec', '70min'),
        ('Service', 'ExecStart', '/usr/local/bin/cl-discv5'),
        ('Service', 'LoadCredential', 'nodekey:/etc/ethswarm/credentials/nodekey'),
        ('Service', 'StateDirectory', 'ethswarm-discv5'),
        ('Service', 'StateDirectoryMode', '0700'),
        ('Service', 'RuntimeDirectory', 'ethswarm/cl-discv5'),
        ('Service', 'RuntimeDirectoryMode', '0750'),
        ('Service', 'ReadWritePaths', '/var/lib/ethswarm-discv5'),
        ('Service', 'NoNewPrivileges', 'yes'),
        ('Service', 'ProtectSystem', 'strict'),
        ('Service', 'ProtectHome', 'yes'),
        ('Service', 'PrivateTmp', 'yes'),
        ('Service', 'PrivateDevices', 'yes'),
        ('Service', 'CapabilityBoundingSet', ''),
        ('Service', 'AmbientCapabilities', ''),
        ('Service', 'RestrictAddressFamilies', 'AF_UNIX AF_INET AF_INET6'),
        ('Service', 'RestrictNamespaces', 'yes'),
        ('Service', 'RestrictRealtime', 'yes'),
        ('Service', 'RestrictSUIDSGID', 'yes'),
        ('Service', 'LockPersonality', 'yes'),
        ('Service', 'MemoryDenyWriteExecute', 'yes'),
        ('Service', 'ProtectKernelTunables', 'yes'),
        ('Service', 'ProtectKernelModules', 'yes'),
        ('Service', 'ProtectKernelLogs', 'yes'),
        ('Service', 'ProtectControlGroups', 'yes'),
        ('Service', 'ProtectClock', 'yes'),
        ('Service', 'ProtectHostname', 'yes'),
        ('Service', 'ProtectProc', 'invisible'),
        ('Service', 'ProcSubset', 'pid'),
        ('Service', 'SystemCallArchitectures', 'native'),
        ('Service', 'SystemCallFilter', '@system-service'),
        ('Service', 'SystemCallFilter', '~@privileged'),
        ('Service', 'MemoryMax', '4G'),
        ('Service', 'MemorySwapMax', '0'),
        ('Service', 'OOMPolicy', 'stop'),
        ('Service', 'Restart', 'on-failure'),
        ('Service', 'RestartSec', '5min'),
        ('Service', 'RestartPreventExitStatus', '1 2 64'),
        ('Install', None, None),
        ('Install', 'WantedBy', 'multi-user.target'),
    ),
    "ethswarm-chain.service": (
        ('Unit', None, None),
        ('Unit', 'Description', 'ETH Swarm probe: cl-chain (state transition and fork choice; holds no node key)'),
        ('Unit', 'Wants', 'network-online.target'),
        ('Unit', 'After', 'network-online.target'),
        ('Unit', 'StartLimitIntervalSec', '6h'),
        ('Unit', 'StartLimitBurst', '3'),
        ('Service', None, None),
        ('Service', 'Type', 'simple'),
        ('Service', 'User', 'ethswarm-chain'),
        ('Service', 'Group', 'ethswarm-chain'),
        ('Service', 'UMask', '0077'),
        ('Service', 'EnvironmentFile', '/etc/ethswarm/anchor-check.env'),
        ('Service', 'ExecStartPre', '/usr/local/bin/anchor-fetch --providers ${ANCHOR_PROVIDERS} --check'),
        ('Service', 'TimeoutStartSec', '70min'),
        ('Service', 'ExecStart', '/usr/local/bin/cl-chain'),
        ('Service', 'StateDirectory', 'ethswarm-chain'),
        ('Service', 'StateDirectoryMode', '0700'),
        ('Service', 'RuntimeDirectory', 'ethswarm/cl-chain'),
        ('Service', 'RuntimeDirectoryMode', '0750'),
        ('Service', 'ReadWritePaths', '/var/lib/ethswarm-chain'),
        ('Service', 'NoNewPrivileges', 'yes'),
        ('Service', 'ProtectSystem', 'strict'),
        ('Service', 'ProtectHome', 'yes'),
        ('Service', 'PrivateTmp', 'yes'),
        ('Service', 'PrivateDevices', 'yes'),
        ('Service', 'CapabilityBoundingSet', ''),
        ('Service', 'AmbientCapabilities', ''),
        ('Service', 'RestrictAddressFamilies', 'AF_UNIX AF_INET AF_INET6'),
        ('Service', 'RestrictNamespaces', 'yes'),
        ('Service', 'RestrictRealtime', 'yes'),
        ('Service', 'RestrictSUIDSGID', 'yes'),
        ('Service', 'LockPersonality', 'yes'),
        ('Service', 'MemoryDenyWriteExecute', 'yes'),
        ('Service', 'ProtectKernelTunables', 'yes'),
        ('Service', 'ProtectKernelModules', 'yes'),
        ('Service', 'ProtectKernelLogs', 'yes'),
        ('Service', 'ProtectControlGroups', 'yes'),
        ('Service', 'ProtectClock', 'yes'),
        ('Service', 'ProtectHostname', 'yes'),
        ('Service', 'ProtectProc', 'invisible'),
        ('Service', 'ProcSubset', 'pid'),
        ('Service', 'SystemCallArchitectures', 'native'),
        ('Service', 'SystemCallFilter', '@system-service'),
        ('Service', 'SystemCallFilter', '~@privileged'),
        ('Service', 'MemoryMax', '4G'),
        ('Service', 'MemorySwapMax', '0'),
        ('Service', 'OOMPolicy', 'stop'),
        ('Service', 'Restart', 'on-failure'),
        ('Service', 'RestartSec', '5min'),
        ('Service', 'RestartPreventExitStatus', '1 2 64'),
        ('Install', None, None),
        ('Install', 'WantedBy', 'multi-user.target'),
    ),
}


# The one key whose value may differ from EXPECTED (a host may rename the unit's description).
FREE_KEYS = {("Unit", "Description")}


def expected_text(entry):
    section, key, value = entry
    return "[%s]" % section if key is None else "%s=%s" % (key, value)


def lint_exact(name, text):
    """The unit's lines, in order and byte for byte, against EXPECTED[name]. No case folding,
    no joining, no whitespace tolerance: each line systemd reads (not blank, not a comment)
    must be the expected one. Only Description= may carry another value."""
    expected = EXPECTED[name]
    found = []
    actual = []
    for number, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        actual.append((number, line))
    section = None
    for i, (number, line) in enumerate(actual):
        if i >= len(expected):
            found.append("line %d: unexpected %r after the last expected line" % (number, line))
            continue
        want = expected[i]
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        key = line.split("=", 1)[0]
        if (section, key) in FREE_KEYS and want[:2] == (section, key):
            continue
        if line != expected_text(want):
            found.append("line %d: expected %r, got %r" % (number, expected_text(want), line))
            # One shifted line misaligns the rest; report the first difference only.
            break
    else:
        for want in expected[len(actual):]:
            found.append("missing %r at the end (after line %d)"
                         % (expected_text(want), actual[-1][0] if actual else 0))
    return found


def parse(text):
    """{section: {key: [values]}}, systemd's way: lists accumulate, empty resets. `text` has
    passed `check_bytes`, so it holds no backslash (no continuation, no escape) and no byte
    systemd would read differently; lines are split on newline only."""
    sections = {}
    current = None
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
            continue
        if current is None or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        values = current.setdefault(key, [])
        if key in LISTS and value == "":
            values.clear()
            values.append("")
        else:
            values.append(value)
    return sections


def check_bytes(blob):
    """Fail-closed reading: instead of modelling systemd's line grammar, refuse every file it
    could read differently from this lint. Allowed bytes are tab, newline and printable ASCII
    (so no NUL, which systemd reads as a line end, no CR, VT, FF, U+2028 or other byte that
    Python's line splitting treats as a line end, and no non-ASCII), and no backslash (so no
    continuation and no escape). The file is at most FILE_MAX bytes and no line (newline not
    counted) LINE_MAX bytes or more, which systemd refuses. Each other line must be blank, a
    comment, a [section] header or a key=value inside a section."""
    found = []
    if len(blob) > FILE_MAX:
        found.append("%d bytes, over the %d-byte cap for a unit file; refused"
                     % (len(blob), FILE_MAX))
    allowed = {0x09, 0x0A} | set(range(0x20, 0x7F))
    in_section = False
    for number, line in enumerate(blob.split(b"\n"), start=1):
        if len(line) >= LINE_MAX:
            found.append("line %d: %d bytes, over the %d-byte line cap (an older systemd reads "
                         "the rest as a line of its own); refused"
                         % (number, len(line), LINE_MAX - 1))
            continue
        bad = sorted({b for b in line if b not in allowed})
        if bad:
            found.append("line %d: byte%s %s outside tab, newline and printable ASCII; refused"
                         % (number, "s" if len(bad) > 1 else "",
                            " ".join("0x%02x" % b for b in bad)))
            continue
        if b"\\" in line:
            found.append("line %d: a backslash (continuation or escape); refused" % number)
            continue
        text = line.decode("ascii").strip()
        if not text or text.startswith(("#", ";")):
            continue
        if text.startswith("[") and text.endswith("]"):
            in_section = True
        elif "=" not in text or not in_section:
            found.append("line %d: neither a comment, a [section] nor a key=value in a section"
                         % number)
    return found


def last(service, key):
    values = service.get(key)
    return values[-1] if values else None


def effective(service, key):
    """A list setting's entries after its last reset, as words."""
    values = service.get(key, [])
    if "" in values:
        values = values[len(values) - 1 - values[::-1].index(""):]
    return [word for value in values for word in value.split()]


def lint_allowed_keys(sections):
    found = []
    for section, keys in sections.items():
        allowed = ALLOWED.get(section)
        if allowed is None:
            found.append("[%s] is not an allowed section" % section)
            continue
        for key in keys:
            if key not in allowed:
                found.append("%s= is not in the [%s] allow-list; a new directive is added to "
                             "the lint after review" % (key, section))
    return found


def lint_user(service, user):
    found = []
    got = last(service, "User")
    if got is None:
        found.append("missing User=%s" % user)
    elif got != user:
        found.append("User=%s, want User=%s (each probe service has its own user)" % (got, user))
    group = last(service, "Group")
    if group != user:
        found.append("Group=%s, want Group=%s (the user's own group)" % (group, user))
    if (last(service, "DynamicUser") or "no").lower() in TRUE:
        found.append("DynamicUser= is set; the service runs as the static user %s" % user)
    return found


def lint_credentials(service, node_key):
    found = []
    if not node_key:
        for key in CREDENTIAL_KEYS:
            if any(service.get(key, [])):
                found.append("%s= is set; cl-chain gets no node key" % key)
        return found
    for key in CREDENTIAL_KEYS[1:]:
        if any(service.get(key, [])):
            found.append("%s= is set; the node key comes only from LoadCredential=%s"
                         % (key, CREDENTIAL))
    loads = [v for v in service.get("LoadCredential", []) if v]
    named = [v for v in loads if v.split(":", 1)[0] == CREDENTIAL]
    if len(named) != 1 or len(loads) != 1:
        found.append("want exactly one LoadCredential=%s:<path> and no other credential, got %d"
                     % (CREDENTIAL, len(loads)))
        return found
    source = named[0].split(":", 1)[1] if ":" in named[0] else ""
    if not source.startswith("/"):
        found.append("LoadCredential=%s needs an absolute source path" % CREDENTIAL)
        return found
    for key, values in service.items():
        if key == "LoadCredential":
            continue
        for value in values:
            if source in value or "--node-key" in value:
                found.append("%s= names the node key; it comes only from $CREDENTIALS_DIRECTORY"
                             % key)
    return found


def exec_prefix(entry):
    """An Exec*= value split into its prefix characters (systemd's whole set, `-@:|+!`) and
    the command line."""
    prefix = ""
    while entry and entry[0] in "-@:|+!":
        prefix += entry[0]
        entry = entry[1:]
    return prefix, entry


def words(command):
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def lint_exec_prefixes(service):
    """Every Exec*= line, fail-closed. systemd unquotes and C-unescapes each command's first
    word before it reads the prefix, and splits a line into commands at a bare `;`, so a value
    with a quote, a backslash or a `;` word could hide a prefix this lint cannot see; such a
    value is refused outright, as is the `|` (shell) prefix. Of the rest, a prefix with `+` or
    `!` would run the command as root outside the sandbox."""
    found = []
    for key in EXEC_KEYS:
        for entry in service.get(key, []):
            if set(entry) & set("\"'\\"):
                found.append("%s= has a quote or a backslash: systemd unquotes and unescapes it "
                             "before reading the prefix, so it is refused" % key)
            if ";" in entry.split():
                found.append("%s= chains commands with ';': each could carry its own prefix, so "
                             "it is refused" % key)
            prefix, _ = exec_prefix(entry)
            if "|" in prefix:
                found.append("%s= has the prefix %r: '|' runs it through a shell" % (key, prefix))
            if set(prefix) & set("+!"):
                found.append("%s= has the prefix %r: it would run without the sandbox or the "
                             "unit's user" % (key, prefix))
    return found


def lint_check_args(args):
    """Findings for anchor-fetch's arguments: an allow-list, so nothing can stand in for the
    check (no --help) or make it write (no --out)."""
    found = []
    for arg in args:
        # systemd splits an unbraced $VAR into words at exec time; only ${NAME} stays one.
        if "$" in arg and re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "", arg).count("$"):
            found.append("ExecStartPre= anchor-fetch argument %r: a variable must be braced, "
                         "${NAME}, so it stays one word" % arg)
    if "--check" not in args:
        found.append("ExecStartPre= anchor-fetch lacks --check")
    providers = 0
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--providers", "--scratch"):
            value = args[i + 1] if i + 1 < len(args) else ""
            if not value or value.startswith("-"):
                found.append("ExecStartPre= anchor-fetch %s needs a value, got %r" % (arg, value))
            elif arg == "--scratch" and not value.startswith("/"):
                found.append("ExecStartPre= anchor-fetch --scratch needs an absolute dir")
            providers += arg == "--providers"
            i += 2
            continue
        if arg != "--check":
            found.append("ExecStartPre= anchor-fetch has %r; only --providers A,B --check "
                         "[--scratch DIR] are allowed (no --quiet: the journal must name the "
                         "providers)" % arg)
        i += 1
    if providers != 1:
        found.append("ExecStartPre= anchor-fetch needs exactly one --providers A,B")
    return found


def lint_anchor_check(service):
    found = []
    entries = [v for v in service.get("ExecStartPre", []) if v]
    if not entries:
        return ["missing ExecStartPre= anchor-fetch --providers A,B --check"]
    checks = []
    for entry in entries:
        prefix, command = exec_prefix(entry)
        argv = words(command)
        if argv and os.path.basename(argv[0]) == "anchor-fetch":
            checks.append((prefix, argv))
    if not checks:
        return ["no ExecStartPre= runs anchor-fetch; the start must wait for the anchor check"]
    for prefix, argv in checks:
        if "-" in prefix:
            found.append("ExecStartPre= anchor-fetch has the prefix %r: its failure must fail "
                         "the start" % prefix)
        if not argv[0].startswith("/"):
            found.append("ExecStartPre= anchor-fetch needs an absolute path")
        found += lint_check_args(argv[1:])
    return found


def seconds(span):
    """A systemd time span in seconds; None for infinity or anything unparsable."""
    span = span.strip()
    if not span or span == "infinity":
        return None
    total = 0.0
    for number, unit in re.findall(r"(\d+(?:\.\d+)?)\s*([a-z]*)", span):
        factor = TIME_UNITS.get(unit or "s")
        if factor is None:
            return None
        total += float(number) * factor
    if re.sub(r"(\d+(?:\.\d+)?)\s*([a-z]*)", "", span).strip():
        return None
    return total


def lint_start_and_restart(unit_section, service):
    found = []
    timeout = last(service, "TimeoutStartSec")
    want = CHECK_BUDGET + MARGIN
    if timeout is None:
        found.append("missing TimeoutStartSec= (the default 90 s cuts the anchor check short)")
    elif (seconds(timeout) or 0) < want:
        found.append("TimeoutStartSec=%s, want a finite span of at least %d s (the check's "
                     "budget %d s plus %d s)" % (timeout, want, CHECK_BUDGET, MARGIN))
    restart_sec = last(service, "RestartSec")
    if restart_sec is None or (seconds(restart_sec) or 0) < 60:
        found.append("RestartSec=%s, want at least 60 s" % restart_sec)
    prevent = set(effective(service, "RestartPreventExitStatus"))
    signals = sorted(word for word in prevent if not word.isdigit())
    if signals:
        found.append("RestartPreventExitStatus=%s: exit codes only; a signal name would stop the "
                     "restart after an OOM kill (SIGKILL) or a stop" % " ".join(signals))
    if not PREVENT <= prevent:
        found.append("RestartPreventExitStatus=%s, want it to cover %s"
                     % (" ".join(sorted(prevent)) or "(missing)", " ".join(sorted(PREVENT))))
    for key in ("StartLimitIntervalSec", "StartLimitBurst"):
        if key in service:
            found.append("%s= belongs in [Unit], not [Service]" % key)
    interval = last(unit_section, "StartLimitIntervalSec")
    if interval is None or (seconds(interval) or 0) < 3600:
        found.append("[Unit] StartLimitIntervalSec=%s, want at least 1h" % interval)
    burst = last(unit_section, "StartLimitBurst")
    if burst is None or not burst.isdigit() or not 1 <= int(burst) <= 5:
        found.append("[Unit] StartLimitBurst=%s, want 1 to 5" % burst)
    return found


def size(value):
    """A finite systemd size in bytes, 1 to SIZE_LIMIT - 1; None for anything else: infinity, a
    percentage, a fraction, a sign, an exponent, another suffix, zero or a value out of range.
    Integer arithmetic only, so no value can overflow."""
    match = SIZE.fullmatch(value)
    if not match:
        return None
    bytes_ = int(match.group(1)) * SIZE_UNITS[match.group(2)]
    return bytes_ if 0 < bytes_ < SIZE_LIMIT else None


def lint_memory(service):
    """The memory ceiling: MemoryMax= a finite positive size, and no MemoryHigh=. Without swap,
    past MemoryHigh= the kernel can only throttle the unit, never OOM-kill it, so a probe there
    stalls (for minutes on systemd 247) and skews the measurement more than a restart would.
    MemorySwapMax= and OOMPolicy= are in HARDENING."""
    found = []
    if "MemoryHigh" in service:
        found.append("MemoryHigh= is set; without swap, past it the kernel only throttles and "
                     "never kills, so the probe stalls: MemoryMax= alone is the ceiling")
    got = last(service, "MemoryMax")
    if got is None:
        found.append("missing MemoryMax= (a finite size: the unit's memory ceiling)")
    elif size(got) is None:
        found.append("MemoryMax=%s, want a finite size: 1 to 2^64 - 2 bytes, digits and an "
                     "optional K, M, G or T suffix" % got)
    return found


def lint_hardening(service, user, want_families):
    found = []
    for key, want in HARDENING.items():
        got = last(service, key)
        if got is None:
            found.append("missing %s=" % key)
        elif got.lower() not in want:
            found.append("%s=%s, want %s" % (key, got, "/".join(sorted(want))))
    for key, want in HARDENING_LISTS.items():
        got = effective(service, key)
        if got != want:
            found.append("%s=%s, want exactly %s" % (key, " ".join(got) or "(none)",
                                                     " ".join(want)))
    if "CapabilityBoundingSet" not in service:
        found.append("missing CapabilityBoundingSet= (empty: no capabilities)")
    elif "" not in service["CapabilityBoundingSet"] or effective(service, "CapabilityBoundingSet"):
        got = " ".join(effective(service, "CapabilityBoundingSet")) or "no empty assignment"
        found.append("CapabilityBoundingSet= must be empty, got %s" % got)
    if effective(service, "AmbientCapabilities"):
        found.append("AmbientCapabilities= must be empty")
    families = effective(service, "RestrictAddressFamilies")
    if not families:
        found.append("missing RestrictAddressFamilies=")
    elif families != want_families:
        found.append("RestrictAddressFamilies=%s, want exactly the allow-list %s"
                     % (" ".join(families), " ".join(want_families)))
    state = effective(service, "StateDirectory")
    if state != [user]:
        found.append("StateDirectory=%s, want StateDirectory=%s"
                     % (" ".join(state) or "(missing)", user))
    paths = effective(service, "ReadWritePaths")
    want = "/var/lib/%s" % user
    if paths != [want]:
        found.append("ReadWritePaths=%s, want exactly the state dir %s"
                     % (" ".join(paths) or "(missing)", want))
    return found


def lint(path, rules):
    with open(path, "rb") as f:
        blob = f.read()
    refused = check_bytes(blob)
    if refused:
        return refused
    text = blob.decode("ascii")
    exact = lint_exact(os.path.basename(path), text)
    sections = parse(text)
    service = sections.get("Service")
    if service is None:
        return ["no [Service] section"]
    return (exact
            + lint_allowed_keys(sections)
            + lint_user(service, rules["user"])
            + lint_credentials(service, rules["node_key"])
            + lint_exec_prefixes(service)
            + lint_anchor_check(service)
            + lint_start_and_restart(sections.get("Unit", {}), service)
            + lint_memory(service)
            + lint_hardening(service, rules["user"], rules["families"]))


def main(argv):
    if len(argv) != 2 or not os.path.isdir(argv[1]):
        print("usage: lint_units.py DIR (a directory holding the probe units)", file=sys.stderr)
        return 2
    findings = []
    # Drop-ins (<unit>.d/*.conf, or any *.d next to the units) would change the units behind
    # this lint's back; the host's own drop-in directories are the host check's. Any other
    # *.service here is not linted, and an install by glob would put it on the host.
    for entry in sorted(os.listdir(argv[1])):
        if entry.endswith(".d"):
            findings.append("%s: a drop-in directory next to the units; refused" % entry)
        elif entry.endswith(".service") and entry not in UNITS:
            findings.append("%s: not one of the %d probe units, so not linted; refused"
                            % (entry, len(UNITS)))
    for name, rules in sorted(UNITS.items()):
        path = os.path.join(argv[1], name)
        if not os.path.isfile(path):
            findings.append("%s: missing" % name)
            continue
        findings += ["%s: %s" % (name, finding) for finding in lint(path, rules)]
    for finding in findings:
        print(finding)
    if findings:
        return 1
    print("ok: %d units" % len(UNITS))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
