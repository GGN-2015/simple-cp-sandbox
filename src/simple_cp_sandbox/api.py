from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, replace
from os import PathLike
from typing import Mapping, Protocol, Sequence

from .errors import SandboxUnsupportedError


Executable = str | PathLike[str]


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Runtime configuration for a sandboxed process.

    The default profile is fail-closed: if the current platform backend cannot
    enforce the requested security properties, process creation raises
    SandboxUnsupportedError instead of starting an unsafe child.
    """

    timeout: float | None = None
    cwd: str | PathLike[str] | None = None
    env: Mapping[str, str] | None = None
    refuse_root: bool = True
    read_deny_paths: Sequence[str | PathLike[str]] = ()
    write_allow_paths: Sequence[str | PathLike[str]] = ()
    block_filesystem_writes: bool = True
    block_network: bool = True
    block_privilege_escalation: bool = True


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """Completed sandbox execution result.

    stdout/stderr are captured as bytes.  elapsed is wall-clock seconds measured
    by the parent process.
    """

    args: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed: float
    timed_out: bool
    killed: bool
    backend: str


class SandboxProcess(Protocol):
    @property
    def pid(self) -> int:
        """Operating-system process identifier for the sandbox leader."""

    def kill(self) -> None:
        """Forcibly terminate the sandboxed process group/job."""

    def communicate(self, timeout: float | None = None) -> SandboxResult:
        """Wait for process completion and collect stdout/stderr."""


class _Backend(Protocol):
    name: str

    def start(
        self,
        executable: Executable,
        args: Sequence[str | PathLike[str]],
        config: SandboxConfig,
    ) -> SandboxProcess:
        ...


def run_executable(
    executable: Executable,
    args: Sequence[str | PathLike[str]] = (),
    *,
    timeout: float | None = None,
    config: SandboxConfig | None = None,
) -> SandboxResult:
    """Run an executable inside the platform sandbox and return its output."""

    effective_config = config or SandboxConfig()
    if timeout is not None:
        effective_config = replace(effective_config, timeout=timeout)

    process = start_executable(executable, args, config=effective_config)
    return process.communicate(timeout=effective_config.timeout)


def start_executable(
    executable: Executable,
    args: Sequence[str | PathLike[str]] = (),
    *,
    config: SandboxConfig | None = None,
) -> SandboxProcess:
    """Start an executable inside the platform sandbox."""

    backend = _select_backend()
    return backend.start(executable, args, config or SandboxConfig())


def _select_backend() -> _Backend:
    machine = platform.machine().lower()
    is_amd64 = machine in {"amd64", "x86_64"}

    if sys.platform.startswith("linux") and is_amd64:
        from .backends.linux import LinuxSandboxBackend

        return LinuxSandboxBackend()

    raise SandboxUnsupportedError(
        f"unsupported platform {sys.platform!r} on architecture {platform.machine()!r}; "
        "only Linux amd64 is supported"
    )
