# simple-cp-sandbox

A small Python package for running an executable in a fail-closed sandbox.

The target profile is useful for competitive-programming style runners:

- the child may read normal files except configured deny-listed directories;
- writes to the filesystem are denied except configured allow-listed directories;
- stdout and stderr are captured;
- network syscalls are denied;
- privilege escalation is blocked with `no_new_privs`/seccomp;
- the whole child process group can be killed on timeout.

## Platform support

| Platform | Status |
| --- | --- |
| Linux amd64 | Implemented with Landlock, seccomp-BPF, `no_new_privs`, and a process group. Requires Linux Landlock ABI 3+ so truncation can be blocked. |

Only Linux amd64 is supported.

## Install

```sh
python -m pip install -e .
```

## Python API

```python
from simple_cp_sandbox import run_executable

result = run_executable("./program", ["arg1", "arg2"], timeout=2.0)

print(result.returncode)
print(result.stdout.decode())
print(result.stderr.decode())
print(result.elapsed)
print(result.timed_out)
```

For manual lifecycle control:

```python
from simple_cp_sandbox import start_executable

process = start_executable("./program")
result = process.communicate(timeout=2.0)
```

To deny reads from selected directories and allow writes only inside selected directories:

```python
from simple_cp_sandbox import SandboxConfig, run_executable

config = SandboxConfig(
    read_deny_paths=("/home/runner/private",),
    write_allow_paths=("/home/runner/workdir",),
)

result = run_executable("./program", config=config)
```

The paths in `read_deny_paths` and `write_allow_paths` must be existing directories.

## CLI

```sh
simple-cp-sandbox --timeout 2.0 ./program arg1 arg2
```

You can also run it as a module:

```sh
python -m simple_cp_sandbox --timeout 2.0 ./program arg1 arg2
```

Filesystem policy can be configured from the CLI:

```sh
simple-cp-sandbox \
  --deny-read /home/runner/private \
  --allow-write /home/runner/workdir \
  --timeout 2.0 \
  ./program arg1 arg2
```

The CLI writes the captured child stdout/stderr back to the runner's stdout/stderr. It exits with `124` on timeout and `125` if the sandbox cannot be created.

## Security notes

This package is intentionally conservative:

- Filesystem read/write policy uses Landlock. Read deny paths are excluded from the read rules, and write-like rights are granted only under `write_allow_paths`.
- seccomp denies networking, namespace creation, mount/module/keyring/BPF/io_uring style syscalls, and filesystem metadata syscalls such as chmod/chown/xattr changes.
- The parent starts the child in a new process group and kills that group with `SIGKILL` on timeout or explicit `kill()`.
- Do not run the sandbox parent as root. By default the Linux backend refuses to start when `geteuid() == 0`.

This is still a small sandbox runner, not a full VM or container runtime. Use stronger isolation for hostile, high-value, or multi-tenant workloads.

## AI implementation notice

This project was implemented entirely by Codex. Users should review the code and understand the risks of AI-generated software, especially for security-sensitive sandboxing code.
