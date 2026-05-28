from __future__ import annotations

import argparse
import sys

from .api import SandboxConfig, run_executable
from .errors import SandboxError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="simple-cp-sandbox")
    parser.add_argument("--timeout", type=float, default=None, help="wall-clock timeout in seconds")
    parser.add_argument("--cwd", default=None, help="working directory for the child process")
    parser.add_argument(
        "--deny-read",
        action="append",
        default=[],
        metavar="PATH",
        help="deny read access to PATH and its descendants; can be passed more than once",
    )
    parser.add_argument(
        "--allow-write",
        action="append",
        default=[],
        metavar="PATH",
        help="allow file creation and writes under PATH; can be passed more than once",
    )
    parser.add_argument("executable", help="executable to run inside the sandbox")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments passed to the executable")

    namespace = parser.parse_args(argv)
    config = SandboxConfig(
        timeout=namespace.timeout,
        cwd=namespace.cwd,
        read_deny_paths=tuple(namespace.deny_read),
        write_allow_paths=tuple(namespace.allow_write),
    )

    try:
        result = run_executable(namespace.executable, namespace.args, config=config)
    except SandboxError as exc:
        print(f"simple-cp-sandbox: {exc}", file=sys.stderr)
        return 125

    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    if result.timed_out:
        return 124
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
