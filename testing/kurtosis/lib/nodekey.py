"""A probe node key for the Kurtosis devnet units (testing/kurtosis/run-units.sh).

cl-chain's config names the node ID of the probe's key (node_id), and cl-p2p refuses to start
when cl-chain's custody columns are not its key's. So the node ID must be known before the units
start. It is keccak256 of the key's uncompressed secp256k1 public key (64 bytes, without the
0x04 prefix), as discv5 and cl-p2p compute it. Standard library only, run with `python3 -I`.

    new PATH
        Writes a new 32-byte secp256k1 secret to PATH (mode 0600; PATH must not exist) and
        prints its node ID as 0x and 64 hex digits. The secret is never printed.

    id PATH
        Prints the node ID of the 32-byte secret in PATH.

    patterns PATH
        Prints the texts a log must never hold for the secret in PATH, one per line: its hex
        (lower and upper case) and its base64, standard and URL-safe, each with and without
        padding. Each text appears once.

Exit: 0, 1 a PATH that does not hold a valid secret (or exists already, for new), 2 usage.
"""

import base64
import os
import secrets
import sys

# secp256k1 (SEC 2): the field prime, the group order and the generator.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_add(a, b):
    """The sum of two points; None is the point at infinity."""
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (slope * slope - a[0] - b[0]) % P
    return (x, (slope * (a[0] - x) - a[1]) % P)


def public_key(secret):
    """The public key (x, y) of the secret scalar."""
    result, addend = None, G
    while secret:
        if secret & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        secret >>= 1
    return result


# Keccak-f[1600]: the round constants and the rotation offsets, by lane (x + 5 y).
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROTATIONS = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]
MASK = 2**64 - 1


def rotl(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & MASK if shift else value


def keccak_f(lanes):
    for constant in ROUND_CONSTANTS:
        c = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
        lanes = [lanes[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(lanes[x + 5 * y], ROTATIONS[x + 5 * y])
        lanes = [b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        lanes[0] ^= constant
    return lanes


def keccak256(data):
    """Keccak-256 as Ethereum uses it: the original padding (0x01 ... 0x80), not SHA3-256's."""
    rate = 136
    padded = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % rate)
    padded[-1] |= 0x80
    lanes = [0] * 25
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        lanes = keccak_f(lanes)
    return b"".join(lane.to_bytes(8, "little") for lane in lanes[:4])


def node_id(secret):
    x, y = public_key(int.from_bytes(secret, "big"))
    return "0x" + keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big")).hex()


def read_secret(path):
    with open(path, "rb") as f:
        secret = f.read()
    if len(secret) != 32 or not 0 < int.from_bytes(secret, "big") < N:
        raise ValueError(f"{path}: not a 32-byte secp256k1 secret")
    return secret


def patterns(secret):
    texts = [secret.hex(), secret.hex().upper()]
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        padded = encode(secret).decode()
        texts += [padded, padded.rstrip("=")]
    return list(dict.fromkeys(texts))


def main(argv):
    if len(argv) != 2 or argv[0] not in ("new", "id", "patterns"):
        print("usage: nodekey.py new|id|patterns PATH", file=sys.stderr)
        return 2
    command, path = argv
    try:
        if command == "new":
            while True:
                secret = secrets.token_bytes(32)
                if 0 < int.from_bytes(secret, "big") < N:
                    break
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secret)
            print(node_id(secret))
        elif command == "id":
            print(node_id(read_secret(path)))
        else:
            for text in patterns(read_secret(path)):
                print(text)
    except (OSError, ValueError) as err:
        print(f"nodekey.py: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
