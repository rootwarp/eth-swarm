"""The file-system half of setup.sh, which runs as root over a tree that the service users own
(and so can rename things inside), and the file reads of preflight.sh and collect-run-log.sh.

No path is resolved twice. The walk opens "/" and then every component of DATA_ROOT relative to
its parent's descriptor (openat with O_DIRECTORY|O_NOFOLLOW), checks each through its own
descriptor, and creates, chowns and chmods only through descriptors, so a component swapped for
a symlink after a check is never followed. Standard library only, run with `python3 -I`.
Exit 0 done, 1 a secret or verification problem, 2 a refused path or bad usage.

    check ROOT EUID RETH_UID LH_UID
        Every check `install` makes, changing nothing. A service uid of -1 means "no such
        user yet". Rules:
        - ROOT is absolute, without empty, . or .. components;
        - every existing directory from / down to ROOT's parent is owned by root or EUID and not
          writable by group or others, unless it is root-owned and sticky (/tmp);
        - ROOT, if it exists, is owned by root or EUID and not writable by group or others;
        - ROOT/.staging, if it exists, is a directory owned by EUID, mode 0700 and empty;
        - ROOT/<svc> and ROOT/<svc>/data, if they exist, are directories owned by EUID or the
          service uid; ROOT/<svc>/jwt.hex, if it exists, is a regular file with one link,
          owned the same way. Any symlink among them is refused.
    install ROOT EUID RETH_UID RETH_GID LH_UID LH_GID ROTATE CHOWN
        The same checks, then: create the missing directories (ROOT 0755 if created here,
        .staging 0700, the service dirs 0700), and write one JWT secret as two 0600 copies,
        each created O_EXCL in .staging, chowned there and renamed into ROOT/<svc>/jwt.hex.
        An existing secret is kept (a missing copy restored from the other) unless ROTATE is 1;
        copies that differ, or are not 64 lower-case hex characters, exit 1. CHOWN 0 (test
        mode) chowns nothing. Ends by verifying every mode and owner through descriptors.
    check-dir DIR EUID OPERATOR_UID
        The .env directory: DIR is absolute, without empty, . or .. components, and every
        directory from / down to DIR itself is a directory (never a symlink) owned by root,
        EUID or OPERATOR_UID (the sudo user, SUDO_UID; -1 for none) and not writable by group
        or others, unless it is root-owned and sticky (/tmp).
    write-file DIR NAME EUID OPERATOR_UID
        The check-dir walk again, keeping DIR's descriptor, then replace DIR/NAME with stdin,
        mode 0600, via a file created O_EXCL|O_NOFOLLOW through that descriptor and renamed
        over NAME through it (a symlink at NAME is replaced, never followed).
    inspect PATH
        PATH (absolute, without empty, . or .. components) opened by a walk from / that never
        follows a symlink (every directory O_DIRECTORY|O_NOFOLLOW), the file itself
        O_NOFOLLOW|O_NONBLOCK and fstat'ed before anything else: it must be a regular file with
        one link. Prints "<octal mode> <owner uid>"; whether those are right is the caller's
        verdict. Nothing is read. A symlink, a FIFO, a directory, a hard link or a missing file
        is refused (exit 2) with the reason.
    same-secret PATH_A PATH_B
        Both opened as `inspect` opens them; exit 0 if both hold the same 64 lower-case hex
        characters, 1 if not. The secret is never printed.

Files are opened O_NONBLOCK and fstat'ed before any read, so a FIFO planted at a checked path is
refused instead of blocking the run.
"""

import os
import re
import stat
import sys

# O_NONBLOCK: opening a FIFO for reading would otherwise wait for a writer.
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
SECRET = re.compile(rb"[0-9a-f]{64}")
SERVICES = ("reth", "lighthouse")


class Refused(Exception):
    """A path that is not provably safe: exit 2."""


class Bad(Exception):
    """A secret or verification problem: exit 1."""


def components(root, what="DATA_ROOT"):
    if not root.startswith("/"):
        raise Refused(f"{what} must be an absolute path")
    parts = root.split("/")[1:]
    if root == "/" or any(p in ("", ".", "..") for p in parts):
        raise Refused(f"{what} must not be /, or have an empty, . or .. component")
    return parts


def open_dir(parent_fd, name, path):
    """The directory's descriptor, or None if it does not exist; a symlink or non-directory is
    refused."""
    try:
        return os.open(name, O_DIR, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise Refused(f"{path}: a symlink or not a directory ({e.strerror})") from None


def mode_of(st):
    return stat.S_IMODE(st.st_mode)


def check_closed(fd, path, owners, sticky_ok):
    st = os.fstat(fd)
    if st.st_uid not in owners:
        who = "root" if owners == {0} else "uid " + " or ".join(str(o) for o in sorted(owners))
        raise Refused(f"{path}: owned by uid {st.st_uid}, not {who}")
    if mode_of(st) & 0o022 and not (sticky_ok and st.st_uid == 0 and st.st_mode & stat.S_ISVTX):
        raise Refused(f"{path}: writable by group or others (mode {mode_of(st):o})")


def walk(root, euid, create, operator=None, what="DATA_ROOT", sticky_last=False):
    """The descriptor of ROOT (created, 0755, if `create`), or None if it does not exist and
    `create` is false. Every component is checked on the way: owned by root or EUID (or
    `operator`, when not None) and closed to group and others, unless root-owned and sticky.
    ROOT itself may be root-owned and sticky only with `sticky_last` (the .env directory)."""
    parts = components(root, what)
    owners = {0, euid} | ({operator} if operator is not None else set())
    fd = os.open("/", O_DIR)
    check_closed(fd, "/", owners, True)
    path = ""
    try:
        for i, name in enumerate(parts):
            path += "/" + name
            last = i == len(parts) - 1
            nfd = open_dir(fd, name, path)
            if nfd is None:
                if not create:
                    os.close(fd)
                    return None
                os.mkdir(name, 0o700, dir_fd=fd)
                nfd = open_dir(fd, name, path)
                if nfd is None or os.fstat(nfd).st_uid != euid:
                    raise Refused(f"{path}: changed while it was created")
                os.fchmod(nfd, 0o755)
            check_closed(nfd, path, owners, sticky_last or not last)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def check_owner(fd, path, owners):
    uid = os.fstat(fd).st_uid
    if uid not in owners:
        raise Refused(f"{path}: owned by uid {uid}")


def open_file(dir_fd, name, path, owners):
    """The file's descriptor, or None if absent; it must be a regular file with one link, owned
    by one of `owners` (any owner for None). It is opened O_NONBLOCK and fstat'ed before
    anything reads it, so a FIFO is refused at once."""
    try:
        fd = os.open(name, O_FILE, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise Refused(f"{path}: a symlink or unreadable ({e.strerror})") from None
    st = os.fstat(fd)
    problem = None
    if not stat.S_ISREG(st.st_mode):
        problem = "not a regular file"
    elif st.st_nlink != 1:
        problem = f"has {st.st_nlink} hard links"
    elif owners is not None and st.st_uid not in owners:
        problem = f"owned by uid {st.st_uid}"
    if problem:
        os.close(fd)
        raise Refused(f"{path}: {problem}")
    os.set_blocking(fd, True)  # a regular file: the O_NONBLOCK that kept a FIFO from blocking is done
    return fd


def check_staging(fd, path, euid):
    st = os.fstat(fd)
    if st.st_uid != euid or mode_of(st) != 0o700:
        raise Refused(f"{path}: must be owned by uid {euid}, mode 0700 (got uid {st.st_uid}, {mode_of(st):o})")
    if os.listdir(fd):
        raise Refused(f"{path}: not empty (remove what a failed run left there)")


def read_secret(fd):
    data = os.read(fd, 4097)
    os.close(fd)
    return data


def check_tree(root_fd, root, euid, uids):
    """Every check below ROOT; returns the existing secrets {svc: bytes or None}."""
    secrets = {}
    fd = open_dir(root_fd, ".staging", f"{root}/.staging")
    if fd is not None:
        try:
            check_staging(fd, f"{root}/.staging", euid)
        finally:
            os.close(fd)
    for svc in SERVICES:
        owners = {euid, uids[svc]}
        secrets[svc] = None
        sfd = open_dir(root_fd, svc, f"{root}/{svc}")
        if sfd is None:
            continue
        try:
            check_owner(sfd, f"{root}/{svc}", owners)
            dfd = open_dir(sfd, "data", f"{root}/{svc}/data")
            if dfd is not None:
                try:
                    check_owner(dfd, f"{root}/{svc}/data", owners)
                finally:
                    os.close(dfd)
            jfd = open_file(sfd, "jwt.hex", f"{root}/{svc}/jwt.hex", owners)
            if jfd is not None:
                secrets[svc] = read_secret(jfd)
        finally:
            os.close(sfd)
    return secrets


def check(root, euid, reth_uid, lh_uid):
    euid = int(euid)
    root_fd = walk(root, euid, False)
    if root_fd is not None:
        try:
            check_tree(root_fd, root, euid, {"reth": int(reth_uid), "lighthouse": int(lh_uid)})
        finally:
            os.close(root_fd)
    print(f"checks: {root} and every directory above it")
    return 0


def ensure_dir(parent_fd, name, path, owners, mode, ids):
    fd = open_dir(parent_fd, name, path)
    if fd is None:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        fd = open_dir(parent_fd, name, path)
        if fd is None:
            raise Refused(f"{path}: changed while it was created")
    try:
        check_owner(fd, path, owners)
        if ids is not None:
            os.fchown(fd, *ids)
        os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def pick_secret(secrets, rotate):
    have = {svc: s for svc, s in secrets.items() if s is not None}
    if rotate or not have:
        return os.urandom(32).hex().encode(), "rotated (restart both services)" if rotate else "generated a new secret (two copies)"
    values = list(have.values())
    if len(values) == 2 and values[0] != values[1]:
        raise Bad("the two JWT copies differ; rerun with --rotate-jwt")
    if not SECRET.fullmatch(values[0]):
        raise Bad("the JWT copies are not a 32-byte hex secret; rerun with --rotate-jwt")
    if len(values) == 2:
        return values[0], "kept the existing secret"
    return values[0], f"restored the missing copy from {next(iter(have))}/jwt.hex"


def install(root, euid, reth_uid, reth_gid, lh_uid, lh_gid, rotate, do_chown):
    euid = int(euid)
    ids = {"reth": (int(reth_uid), int(reth_gid)), "lighthouse": (int(lh_uid), int(lh_gid))}
    uids = {svc: ids[svc][0] for svc in SERVICES}
    chown = do_chown == "1"
    # Every check first, so a refused tree is left as it was.
    root_fd = walk(root, euid, False)
    if root_fd is not None:
        os.close(root_fd)
    root_fd = walk(root, euid, True)
    staged = []
    fds = {}
    try:
        secrets = check_tree(root_fd, root, euid, uids)
        stage = ensure_dir(root_fd, ".staging", f"{root}/.staging", {euid}, 0o700, None)
        fds["stage"] = stage
        check_staging(stage, f"{root}/.staging", euid)
        for svc in SERVICES:
            owners = {euid, uids[svc]}
            sfd = ensure_dir(root_fd, svc, f"{root}/{svc}", owners, 0o700, ids[svc] if chown else None)
            fds[svc] = sfd
            os.close(ensure_dir(sfd, "data", f"{root}/{svc}/data", owners, 0o700, ids[svc] if chown else None))
        print(f"directories: {root}/{{reth,lighthouse}}/data")
        secret, what = pick_secret(secrets, rotate == "1")
        for svc in SERVICES:
            name = f"jwt.{svc}.{os.urandom(6).hex()}"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage)
            staged.append(name)
            try:
                os.write(fd, secret)
                if chown:
                    os.fchown(fd, *ids[svc])
                os.fchmod(fd, 0o600)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                if stat.S_ISDIR(os.stat("jwt.hex", dir_fd=fds[svc], follow_symlinks=False).st_mode):
                    raise Refused(f"{root}/{svc}/jwt.hex: is a directory")
            except FileNotFoundError:
                pass
            os.rename(name, "jwt.hex", src_dir_fd=stage, dst_dir_fd=fds[svc])
            staged.remove(name)
        print(f"jwt: {what}")
        verify(root, root_fd, fds, euid, uids, secret)
    finally:
        for name in staged:
            try:
                os.unlink(name, dir_fd=fds["stage"])
            except OSError:
                pass
        for fd in fds.values():
            os.close(fd)
        os.close(root_fd)
    return 0


def verify(root, root_fd, fds, euid, uids, secret):
    bad = False

    def expect(path, st, mode, uid):
        nonlocal bad
        got = f"{mode_of(st):o} {st.st_uid}"
        ok = got == f"{mode:o} {uid}"
        bad = bad or not ok
        print(f"verify: {path}: {got}" + ("" if ok else f" (want {mode:o} {uid}): FAIL"))

    expect(f"{root}/.staging", os.fstat(fds["stage"]), 0o700, euid)
    for svc in SERVICES:
        expect(f"{root}/{svc}", os.fstat(fds[svc]), 0o700, uids[svc])
        dfd = open_dir(fds[svc], "data", f"{root}/{svc}/data")
        expect(f"{root}/{svc}/data", os.fstat(dfd), 0o700, uids[svc])
        os.close(dfd)
        jfd = open_file(fds[svc], "jwt.hex", f"{root}/{svc}/jwt.hex", {uids[svc]})
        expect(f"{root}/{svc}/jwt.hex", os.fstat(jfd), 0o600, uids[svc])
        if read_secret(jfd) != secret:
            print(f"verify: {root}/{svc}/jwt.hex does not hold the secret: FAIL")
            bad = True
    if bad:
        raise Bad("verification failed")
    print("verify: both JWT copies hold the same 32-byte secret")


def operator_uid(value):
    """OPERATOR_UID as an int, or None for -1 (no sudo user)."""
    if not re.fullmatch(r"-1|[0-9]+", value):
        raise Refused(f"OPERATOR_UID {value!r} is not a uid or -1")
    return None if value == "-1" else int(value)


def env_dir(directory, euid, operator):
    """The .env directory's descriptor, after the walk from /; a missing one is refused."""
    fd = walk(directory, int(euid), False, operator_uid(operator), "the .env directory", sticky_last=True)
    if fd is None:
        raise Refused(f"{directory}: no such directory")
    return fd


def check_dir(directory, euid, operator):
    os.close(env_dir(directory, euid, operator))
    print(f"checks: {directory} (the .env directory) and every directory above it")
    return 0


def write_file(directory, name, euid, operator):
    if name in ("", ".", "..") or "/" in name:
        raise Refused(f"{name!r}: not a file name")
    data = sys.stdin.buffer.read()
    dfd = env_dir(directory, euid, operator)
    tmp = f".{name}.{os.urandom(6).hex()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            os.write(fd, data)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise
    finally:
        os.close(dfd)
    return 0


def open_path(path):
    """PATH's descriptor, through the walk from / that follows no symlink; any owner."""
    parts = components(path, "the path")
    fd = os.open("/", O_DIR)
    try:
        walked = ""
        for name in parts[:-1]:
            walked += "/" + name
            nfd = open_dir(fd, name, walked)
            if nfd is None:
                raise Refused(f"{path}: no such file")
            os.close(fd)
            fd = nfd
        ffd = open_file(fd, parts[-1], path, None)
    finally:
        os.close(fd)
    if ffd is None:
        raise Refused(f"{path}: no such file")
    return ffd


def inspect(path):
    fd = open_path(path)
    st = os.fstat(fd)
    os.close(fd)
    print(f"{mode_of(st):o} {st.st_uid}")
    return 0


def same_secret(path_a, path_b):
    a, b = read_secret(open_path(path_a)), read_secret(open_path(path_b))
    return 0 if a == b and SECRET.fullmatch(a) else 1


COMMANDS = {
    "check": (check, 4),
    "install": (install, 8),
    "check-dir": (check_dir, 3),
    "write-file": (write_file, 4),
    "inspect": (inspect, 1),
    "same-secret": (same_secret, 2),
}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS or len(argv) - 2 != COMMANDS[argv[1]][1]:
        print(f"usage: fsguard.py {{{'|'.join(COMMANDS)}}} ARGS... (see the module docstring)", file=sys.stderr)
        return 2
    try:
        return COMMANDS[argv[1]][0](*argv[2:])
    except Refused as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except Bad as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"ERROR: {e.filename or ''}: {e.strerror} (refused; nothing was followed)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
