"""Kernel-level confinement of the extraction worker (#43), Linux only, via ctypes.

Two unprivileged mechanisms, both usable as a non-root user under Docker's
`cap_drop: ALL` + `no-new-privileges` (they only need `PR_SET_NO_NEW_PRIVS`, which any
process may set):

- **Landlock** (Linux 5.13+): after `restrict_self`, this process can only open files
  beneath the allowed paths, read-only (no write, create, delete, rename, truncate,
  device ioctl anywhere). With ABI 4+ it also can't bind or connect TCP sockets; with ABI 6+
  it can't signal processes or reach abstract unix sockets outside its own domain.
- **seccomp-bpf**: a tiny filter that makes `socket()`, `io_uring_setup()` and path
  `truncate()` fail with EPERM (and every syscall of a foreign ABI, such as x32 or i386).

Both apply to the calling thread and its future children only, and they're irreversible.
Already-open file descriptors (the stdin/stdout pipes) keep working. Everything is best
effort: `confine()` reports what was applied and never raises for an unsupported kernel."""

from __future__ import annotations

import glob
import os
import platform
import struct
import sys

# Syscall numbers. Landlock's are the same on every architecture.
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

# Filesystem access rights (include/uapi/linux/landlock.h).
FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REFER = 1 << 13     # ABI 2
FS_TRUNCATE = 1 << 14  # ABI 3
FS_IOCTL_DEV = 1 << 15  # ABI 5
NET_BIND_TCP = 1 << 0   # ABI 4
NET_CONNECT_TCP = 1 << 1
SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0  # ABI 6
SCOPE_SIGNAL = 1 << 1

# seccomp: syscall numbers to deny per audit arch.
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
DENIED_SYSCALLS = {
    # socket, io_uring_setup (IORING_OP_SOCKET), truncate (path-based; Landlock < ABI 3)
    "x86_64": (41, 425, 76),
    "aarch64": (198, 425, 45),
}
X32_SYSCALL_BIT = 0x40000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
EPERM = 1

LEVELS = ("full", "filesystem", "network", "basic")


def handled_fs(abi: int) -> int:
    """Every filesystem right the kernel's Landlock ABI knows, so all are denied by default."""
    rights = (1 << 13) - 1  # ABI 1: EXECUTE .. MAKE_SYM
    if abi >= 2:
        rights |= FS_REFER
    if abi >= 3:
        rights |= FS_TRUNCATE
    if abi >= 5:
        rights |= FS_IOCTL_DEV
    return rights


def _libc():
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return ctypes, libc


def landlock_abi() -> int:
    """The kernel's Landlock ABI version, or 0 when Landlock is unavailable (not Linux, an old
    kernel, Landlock not in the LSM list, or the syscall blocked by a seccomp profile)."""
    if not sys.platform.startswith("linux"):
        return 0
    try:
        ctypes, libc = _libc()
        abi = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0),
                           ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
        return int(abi) if abi > 0 else 0
    except Exception:  # noqa: BLE001
        return 0


def allowed_paths() -> list[str]:
    """What the worker may read after confinement: the Python installation, the venv and
    sys.path entries (code), shared libraries, and a few device/loader files. Never `/`,
    never anything the caller didn't list here (in particular not DATA_DIR)."""
    candidates = [sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix, *sys.path,
                  "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/share/zoneinfo",
                  *glob.glob("/usr/lib/python3*"), *glob.glob("/usr/local/lib/python3*"),
                  "/etc/ld.so.cache", "/dev/null", "/dev/urandom"]
    out: list[str] = []
    for p in candidates:
        if not p or not os.path.isabs(p):
            continue
        p = os.path.realpath(p)
        if p == "/" or p in out or not os.path.exists(p):
            continue
        out.append(p)
    return out


def exposes(path: str | os.PathLike, allowed: list[str] | None = None) -> str | None:
    """The allowed path that would make `path` readable by the confined worker, if any."""
    target = os.path.realpath(path)
    for a in allowed if allowed is not None else allowed_paths():
        if target == a or target.startswith(a.rstrip("/") + "/"):
            return a
    return None


def landlock_restrict(paths: list[str], abi: int, failures: list[str] | None = None) -> bool:
    """Read-only access beneath `paths`, nothing else; TCP bind/connect denied when abi >= 4.
    Paths whose rule couldn't be added are appended to `failures` (they stay unreadable).
    Returns True once the process is restricted."""
    failures = failures if failures is not None else []
    ctypes, libc = _libc()
    fs = handled_fs(abi)
    net = (NET_BIND_TCP | NET_CONNECT_TCP) if abi >= 4 else 0
    scoped = (SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL) if abi >= 6 else 0
    size = 8 if abi < 4 else 16 if abi < 6 else 24
    attr = ctypes.create_string_buffer(struct.pack("=QQQ", fs, net, scoped)[:size], size)
    ruleset = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, attr, ctypes.c_size_t(size), ctypes.c_uint32(0))
    if ruleset < 0:
        return False
    try:
        o_path = getattr(os, "O_PATH", 0o10000000)
        for p in paths:
            is_dir = os.path.isdir(p)
            access = (FS_READ_FILE | FS_READ_DIR) if is_dir else FS_READ_FILE
            try:
                fd = os.open(p, o_path | os.O_CLOEXEC)
            except OSError:
                failures.append(p)
                continue
            try:
                # struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; } packed
                rule = ctypes.create_string_buffer(struct.pack("=Qi", access, fd), 12)
                if libc.syscall(SYS_LANDLOCK_ADD_RULE, ctypes.c_int(ruleset),
                                ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH), rule, ctypes.c_uint32(0)) != 0:
                    # Not readable then; the rest still applies. Reported as rules_failed.
                    failures.append(p)
            finally:
                os.close(fd)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            return False
        return libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(ruleset), ctypes.c_uint32(0)) == 0
    finally:
        os.close(ruleset)


def seccomp_filter(machine: str) -> bytes | None:
    """The BPF program (sock_filter array) for this architecture, or None if unknown."""
    arch, denied = AUDIT_ARCH.get(machine), DENIED_SYSCALLS.get(machine)
    if arch is None or denied is None:
        return None

    def ins(code: int, jt: int, jf: int, k: int) -> bytes:
        return struct.pack("=HBBI", code, jt, jf, k)

    LD_W_ABS, JEQ, JGE, RET = 0x20, 0x15, 0x35, 0x06
    prog = [ins(LD_W_ABS, 0, 0, 4)]  # seccomp_data.arch
    n_checks = len(denied) + (1 if machine == "x86_64" else 0)
    # foreign arch -> deny (jump to the final ERRNO); else continue
    prog.append(ins(JEQ, 0, n_checks + 2, arch))
    prog.append(ins(LD_W_ABS, 0, 0, 0))  # seccomp_data.nr
    remaining = n_checks
    if machine == "x86_64":
        remaining -= 1
        prog.append(ins(JGE, remaining + 1, 0, X32_SYSCALL_BIT))
    for nr in denied:
        remaining -= 1
        prog.append(ins(JEQ, remaining + 1, 0, nr))
    prog.append(ins(RET, 0, 0, SECCOMP_RET_ALLOW))
    prog.append(ins(RET, 0, 0, SECCOMP_RET_ERRNO | EPERM))
    return b"".join(prog)


def seccomp_restrict() -> bool:
    program = seccomp_filter(platform.machine())
    if program is None:
        return False
    ctypes, libc = _libc()

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    buf = ctypes.create_string_buffer(program, len(program))
    prog = SockFprog(len(program) // 8, ctypes.cast(buf, ctypes.c_void_p))
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return False
    return libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) == 0


def level_of(landlock_fs: bool, net_blocked: bool) -> str:
    if landlock_fs and net_blocked:
        return "full"
    if landlock_fs:
        return "filesystem"
    if net_blocked:
        return "network"
    return "basic"


def confine() -> dict:
    """Apply Landlock and seccomp to this (single-threaded) process, as far as supported.
    Returns {"level", "landlock_abi", "landlock_fs", "landlock_net", "seccomp", "rules_failed"}.
    The worker has no logging (stderr is discarded), so rule failures are counted and the
    parent logs them."""
    import threading

    report = {"level": "basic", "landlock_abi": 0, "landlock_fs": False, "landlock_net": False,
              "seccomp": False, "rules_failed": 0}
    if not sys.platform.startswith("linux"):
        return report
    # Both mechanisms only bind the calling thread; a second thread would stay unconfined.
    if threading.active_count() != 1:
        raise RuntimeError("confine() must run before any other thread starts")
    abi = landlock_abi()
    report["landlock_abi"] = abi
    if abi > 0:
        failures: list[str] = []
        try:
            report["landlock_fs"] = landlock_restrict(allowed_paths(), abi, failures)
        except Exception:  # noqa: BLE001
            report["landlock_fs"] = False
        report["rules_failed"] = len(failures)
        report["landlock_net"] = report["landlock_fs"] and abi >= 4
    try:
        report["seccomp"] = seccomp_restrict()
    except Exception:  # noqa: BLE001
        report["seccomp"] = False
    report["level"] = level_of(report["landlock_fs"], report["landlock_net"] or report["seccomp"])
    return report
