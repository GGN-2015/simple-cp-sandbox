from __future__ import annotations

import ctypes
import errno
import os
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from os import PathLike
from typing import Final, Sequence

from ..api import Executable, SandboxConfig, SandboxResult
from ..errors import SandboxSecurityError, SandboxUnsupportedError


class LinuxSandboxBackend:
    name = "linux-landlock-seccomp"

    def start(
        self,
        executable: Executable,
        args: Sequence[str | PathLike[str]],
        config: SandboxConfig,
    ) -> "LinuxSandboxProcess":
        _validate_linux_environment(config)

        argv = tuple(str(part) for part in (executable, *args))
        popen = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=config.cwd,
            env=dict(config.env) if config.env is not None else None,
            close_fds=True,
            preexec_fn=lambda: _linux_child_preexec(config),
        )
        return LinuxSandboxProcess(popen=popen, args=argv, backend=self.name)


@dataclass(slots=True)
class LinuxSandboxProcess:
    popen: subprocess.Popen[bytes]
    args: tuple[str, ...]
    backend: str
    started_at: float = 0.0
    killed: bool = False
    _result: SandboxResult | None = None

    def __post_init__(self) -> None:
        self.started_at = time.monotonic()

    @property
    def pid(self) -> int:
        return self.popen.pid

    def kill(self) -> None:
        self.killed = True
        self._kill_process_group()

    def communicate(self, timeout: float | None = None) -> SandboxResult:
        if self._result is not None:
            return self._result

        timed_out = False
        try:
            stdout, stderr = self.popen.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self.kill()
            stdout, stderr = self.popen.communicate()
        else:
            if self._kill_process_group():
                self.killed = True

        elapsed = time.monotonic() - self.started_at
        self._result = SandboxResult(
            args=self.args,
            returncode=self.popen.returncode,
            stdout=stdout,
            stderr=stderr,
            elapsed=elapsed,
            timed_out=timed_out,
            killed=self.killed,
            backend=self.backend,
        )
        return self._result

    def _kill_process_group(self) -> bool:
        try:
            os.killpg(self.popen.pid, signal.SIGKILL)
        except ProcessLookupError:
            return False
        except OSError:
            if self.popen.poll() is None:
                self.popen.kill()
                return True
            return False
        return True


def _validate_linux_environment(config: SandboxConfig) -> None:
    if os.geteuid() == 0 and config.refuse_root:
        raise SandboxSecurityError(
            "refusing to start a sandbox as root; run this package as an unprivileged user"
        )

    _validate_directory_policy_paths(config)

    if _uses_landlock_filesystem_policy(config):
        abi = _landlock_abi_version()
        if abi < MIN_LANDLOCK_ABI:
            raise SandboxUnsupportedError(
                f"Linux Landlock ABI {abi} is too old; ABI {MIN_LANDLOCK_ABI}+ is required "
                "to enforce filesystem access safely"
            )


def _validate_directory_policy_paths(config: SandboxConfig) -> None:
    for label, paths in (
        ("read deny", config.read_deny_paths),
        ("write allow", config.write_allow_paths),
    ):
        for path in paths:
            if not os.path.isdir(path):
                raise SandboxSecurityError(f"{label} path must be an existing directory: {path!s}")


def _linux_child_preexec(config: SandboxConfig) -> None:
    os.setsid()

    if config.block_privilege_escalation or _uses_landlock_filesystem_policy(config) or config.block_network:
        _set_no_new_privs()

    if _uses_landlock_filesystem_policy(config):
        _apply_landlock_filesystem_policy(config)

    if config.block_network or config.block_privilege_escalation or _enforces_write_policy(config):
        _apply_seccomp_filter(config)


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.prctl.restype = ctypes.c_int


def _syscall(number: int, *args: object) -> int:
    ctypes.set_errno(0)
    result = _libc.syscall(ctypes.c_long(number), *args)
    if result < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(result)


def _set_no_new_privs() -> None:
    PR_SET_NO_NEW_PRIVS = 38

    ctypes.set_errno(0)
    result = _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]


SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
MIN_LANDLOCK_ABI: Final = 3

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15


def _landlock_abi_version() -> int:
    try:
        return _syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            ctypes.c_void_p(0),
            ctypes.c_size_t(0),
            ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
        )
    except OSError as exc:
        raise SandboxUnsupportedError(
            "Linux Landlock is not available; kernel 5.13+ with Landlock enabled is required"
        ) from exc


def _landlock_read_rights() -> int:
    return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR


def _landlock_write_rights_for_abi(abi: int) -> int:
    rights = (
        LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
    )
    if abi >= 2:
        rights |= LANDLOCK_ACCESS_FS_REFER
    rights |= LANDLOCK_ACCESS_FS_TRUNCATE
    if abi >= 5:
        rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV
    return rights


def _landlock_file_rights_for_abi(abi: int) -> int:
    rights = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE
    rights |= LANDLOCK_ACCESS_FS_TRUNCATE
    if abi >= 5:
        rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV
    return rights


def _uses_landlock_filesystem_policy(config: SandboxConfig) -> bool:
    return bool(config.read_deny_paths) or _enforces_write_policy(config)


def _enforces_write_policy(config: SandboxConfig) -> bool:
    return config.block_filesystem_writes or bool(config.write_allow_paths)


def _apply_landlock_filesystem_policy(config: SandboxConfig) -> None:
    abi = _landlock_abi_version()
    handled_access = _landlock_handled_access(config, abi)
    attr = _LandlockRulesetAttr(handled_access_fs=handled_access)
    ruleset_fd = _syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr),
        ctypes.c_size_t(ctypes.sizeof(attr)),
        ctypes.c_uint32(0),
    )
    try:
        if config.read_deny_paths:
            read_allow_paths = _read_allow_paths(config.read_deny_paths)
            for path in read_allow_paths:
                _add_landlock_path_rule(ruleset_fd, path, _landlock_read_rights(), abi)

        if _enforces_write_policy(config):
            for path in config.write_allow_paths:
                _add_landlock_path_rule(ruleset_fd, path, _landlock_write_rights_for_abi(abi), abi)

        _syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(ruleset_fd), ctypes.c_uint32(0))
    finally:
        os.close(ruleset_fd)


def _landlock_handled_access(config: SandboxConfig, abi: int) -> int:
    handled_access = 0
    if config.read_deny_paths:
        handled_access |= _landlock_read_rights()
    if _enforces_write_policy(config):
        handled_access |= _landlock_write_rights_for_abi(abi)
    return handled_access


def _read_allow_paths(read_deny_paths: Sequence[str | PathLike[str]]) -> tuple[str, ...]:
    denied_roots = _existing_realpaths(read_deny_paths)
    if not denied_roots:
        return ("/",)

    allowed: list[str] = []
    seen: set[str] = set()
    pending = ["/"]

    while pending:
        candidate = pending.pop()
        real_candidate = os.path.realpath(candidate)
        if real_candidate in seen:
            continue
        seen.add(real_candidate)

        if real_candidate in denied_roots:
            continue
        if any(_is_path_beneath(real_candidate, denied) for denied in denied_roots):
            continue
        if any(_is_path_beneath(real_candidate, existing) for existing in allowed):
            continue

        contains_denied_path = any(_is_path_beneath(denied, real_candidate) for denied in denied_roots)
        if contains_denied_path:
            pending.extend(_child_paths(real_candidate))
        else:
            allowed.append(real_candidate)

    return tuple(allowed)


def _child_paths(path: str) -> tuple[str, ...]:
    try:
        with os.scandir(path) as entries:
            return tuple(entry.path for entry in entries)
    except OSError:
        return ()


def _existing_realpaths(paths: Sequence[str | PathLike[str]]) -> tuple[str, ...]:
    realpaths: set[str] = set()
    for path in paths:
        realpaths.add(os.path.realpath(os.fsdecode(path)))
    return tuple(sorted(realpaths, key=lambda item: item.count(os.sep)))


def _is_path_beneath(path: str, ancestor: str) -> bool:
    try:
        return os.path.commonpath((path, ancestor)) == ancestor
    except ValueError:
        return False


def _add_landlock_path_rule(ruleset_fd: int, path: str | PathLike[str], access: int, abi: int) -> None:
    fd = os.open(os.fsdecode(path), os.O_PATH | os.O_CLOEXEC)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISDIR(mode):
            access &= _landlock_file_rights_for_abi(abi)
        if access == 0:
            return

        path_beneath = _LandlockPathBeneathAttr(allowed_access=access, parent_fd=fd)
        _syscall(
            SYS_LANDLOCK_ADD_RULE,
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(path_beneath),
            ctypes.c_uint32(0),
        )
    finally:
        os.close(fd)


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_ALU = 0x04
BPF_AND = 0x50
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
AUDIT_ARCH_X86_64 = 0xC000003E
PR_SET_SECCOMP = 22


def _stmt(code: int, k: int) -> _SockFilter:
    return _SockFilter(code=code, jt=0, jf=0, k=k)


def _jump(code: int, k: int, jt: int, jf: int) -> _SockFilter:
    return _SockFilter(code=code, jt=jt, jf=jf, k=k)


def _deny_syscall(number: int, action: int) -> list[_SockFilter]:
    return [
        _jump(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1),
        _stmt(BPF_RET | BPF_K, action),
    ]


def _apply_seccomp_filter(config: SandboxConfig) -> None:
    deny_action = SECCOMP_RET_ERRNO | errno.EPERM
    filters: list[_SockFilter] = [
        _stmt(BPF_LD | BPF_W | BPF_ABS, 4),
        _jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        _stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        _stmt(BPF_LD | BPF_W | BPF_ABS, 0),
    ]

    if config.block_privilege_escalation:
        filters.extend(_deny_clone_with_namespace_flags(deny_action))

    blocked: set[int] = set()
    if config.block_network:
        blocked.update(_NETWORK_SYSCALLS)
        blocked.update(_IO_URING_SYSCALLS)
    if _enforces_write_policy(config):
        blocked.update(_FILESYSTEM_METADATA_SYSCALLS)
        blocked.update(_IO_URING_SYSCALLS)
    if config.block_privilege_escalation:
        blocked.update(_PRIVILEGE_SYSCALLS)
        blocked.update(_IO_URING_SYSCALLS)

    for syscall_number in sorted(blocked):
        filters.extend(_deny_syscall(syscall_number, deny_action))

    filters.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    filter_array = (_SockFilter * len(filters))(*filters)
    program = _SockFprog(len=len(filters), filter=filter_array)

    ctypes.set_errno(0)
    result = _libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0)
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _deny_clone_with_namespace_flags(action: int) -> list[_SockFilter]:
    # seccomp_data.args[0] is the clone(2) flags argument on x86_64.
    namespace_flags = (
        CLONE_NEWNS
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWNET
        | CLONE_NEWCGROUP
        | CLONE_NEWTIME
    )
    return [
        _jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_CLONE, 0, 4),
        _stmt(BPF_LD | BPF_W | BPF_ABS, 16),
        _stmt(BPF_ALU | BPF_AND | BPF_K, namespace_flags),
        _jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        _stmt(BPF_RET | BPF_K, action),
        _stmt(BPF_LD | BPF_W | BPF_ABS, 0),
    ]


SYS_CLONE = 56

CLONE_NEWTIME = 0x00000080
CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

_NETWORK_SYSCALLS = {
    41,  # socket
    42,  # connect
    43,  # accept
    44,  # sendto
    45,  # recvfrom
    46,  # sendmsg
    47,  # recvmsg
    48,  # shutdown
    49,  # bind
    50,  # listen
    51,  # getsockname
    52,  # getpeername
    53,  # socketpair
    54,  # setsockopt
    55,  # getsockopt
    288,  # accept4
    299,  # recvmmsg
    307,  # sendmmsg
}

_FILESYSTEM_METADATA_SYSCALLS = {
    90,  # chmod
    91,  # fchmod
    92,  # chown
    93,  # fchown
    94,  # lchown
    95,  # umask
    188,  # setxattr
    189,  # lsetxattr
    190,  # fsetxattr
    197,  # removexattr
    198,  # lremovexattr
    199,  # fremovexattr
    260,  # fchownat
    268,  # fchmodat
    280,  # utimensat
    452,  # fchmodat2
}

_IO_URING_SYSCALLS = {
    425,  # io_uring_setup
    426,  # io_uring_enter
    427,  # io_uring_register
}

_PRIVILEGE_SYSCALLS = {
    101,  # ptrace
    103,  # syslog
    105,  # setuid
    106,  # setgid
    109,  # setpgid
    112,  # setsid
    113,  # setreuid
    114,  # setregid
    116,  # setgroups
    117,  # setresuid
    119,  # setresgid
    122,  # setfsuid
    123,  # setfsgid
    126,  # capset
    155,  # pivot_root
    156,  # _sysctl
    161,  # chroot
    163,  # acct
    164,  # settimeofday
    165,  # mount
    166,  # umount2
    167,  # swapon
    168,  # swapoff
    169,  # reboot
    170,  # sethostname
    171,  # setdomainname
    172,  # iopl
    173,  # ioperm
    175,  # init_module
    176,  # delete_module
    246,  # kexec_load
    248,  # add_key
    249,  # request_key
    250,  # keyctl
    272,  # unshare
    298,  # perf_event_open
    304,  # open_by_handle_at
    308,  # setns
    313,  # finit_module
    320,  # kexec_file_load
    321,  # bpf
    323,  # userfaultfd
    435,  # clone3
}
