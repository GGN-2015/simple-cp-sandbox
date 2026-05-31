# Implementation Principles

This document explains how `simple-cp-sandbox` starts, restricts, and supervises
a sandboxed executable. It also describes how the Linux backend combines
Landlock, seccomp-BPF, `no_new_privs`, and process groups into a conservative
competitive-programming style runner.

## Design Goal

This project is intentionally small. It is not a container runtime, a virtual
machine, or a complete multi-tenant isolation system. Its goal is to run one
executable with:

- captured stdout and stderr;
- network-related syscalls denied;
- filesystem writes denied by default, except under explicitly allowed
  directories;
- optional read-deny directories;
- common privilege-escalation paths blocked;
- timeout handling that kills the whole child process group.

The default behavior is fail-closed: if the current platform cannot enforce the
requested security properties, the package refuses to start the target process
instead of falling back to unsafe execution.

## Public API Layer

The public API lives in `src/simple_cp_sandbox/api.py`.

`SandboxConfig` is the declarative policy object. It contains execution settings
such as `timeout`, `cwd`, and `env`, plus these security controls:

- `refuse_root`: refuse to start the sandbox parent as root by default;
- `read_deny_paths`: directories that the child must not read;
- `write_allow_paths`: directories where the child may perform write-like
  filesystem operations;
- `block_filesystem_writes`: deny filesystem writes outside explicitly allowed
  directories;
- `block_network`: deny network-related syscalls;
- `block_privilege_escalation`: enable `no_new_privs` and deny
  privilege-related syscalls.

`run_executable()` is the one-shot API. It builds the effective config, starts
the process through `start_executable()`, and then calls `communicate()` with
the configured timeout.

`start_executable()` selects the platform backend and returns a
`SandboxProcess`. This is the manual lifecycle API for callers that need to
inspect the PID, explicitly kill the sandbox, or collect output later.

`SandboxResult` is the completed execution record. It contains the original
arguments, return code, captured output, parent-measured wall-clock elapsed
time, timeout status, kill status, and backend name.

## Backend Selection

Backend selection is deliberately narrow. `_select_backend()` currently accepts
only Linux on amd64/x86_64:

- `sys.platform` must start with `linux`;
- `platform.machine()` must be `amd64` or `x86_64`.

If these checks fail, `SandboxUnsupportedError` is raised. This prevents the
package from silently running without isolation on unsupported platforms.

The current backend is `LinuxSandboxBackend`, whose backend name is
`linux-landlock-seccomp`.

## Linux Startup Flow

The Linux backend lives in `src/simple_cp_sandbox/backends/linux.py`.

`LinuxSandboxBackend.start()` validates the environment before launching the
child:

- when `refuse_root=True`, `geteuid() == 0` is rejected;
- every path in `read_deny_paths` and `write_allow_paths` must be an existing
  directory;
- if Landlock is required, the kernel Landlock ABI must be at least 3.

The backend then starts the target with `subprocess.Popen()`:

- stdin is connected to `subprocess.DEVNULL`;
- stdout and stderr are captured with pipes;
- `cwd` and `env` are forwarded from the config;
- `close_fds=True` closes unrelated file descriptors;
- `preexec_fn` runs `_linux_child_preexec(config)` in the child before `exec`.

`_linux_child_preexec()` applies restrictions in this order:

1. Call `setsid()` to create a new session and process group.
2. Enable `no_new_privs` when privilege blocking, Landlock, or seccomp is used.
3. Apply the Landlock filesystem policy when filesystem policy is required.
4. Install the seccomp-BPF filter when network, privilege, or write policy is
   required.

These controls are applied before `exec`, so the target program starts already
restricted.

## Process Group And Lifecycle Control

The child calls `setsid()`, so its PID is also the ID of the new process group.
`LinuxSandboxProcess.kill()` sends `SIGKILL` to that whole process group with
`killpg()`.

`communicate()` has three important behaviors:

- if a result has already been collected, later calls return the cached
  `SandboxResult`;
- on `subprocess.TimeoutExpired`, it kills the process group and then drains
  stdout/stderr;
- even after normal leader exit, it still attempts to kill the process group so
  descendant processes do not survive after the leader exits.

If `killpg()` reports that the process group no longer exists, cleanup is treated
as complete. If process-group killing fails while the leader is still running,
the backend falls back to `popen.kill()`.

## Landlock Filesystem Policy

Filesystem isolation uses Landlock. The backend calls Landlock syscalls directly
through `ctypes`:

- `landlock_create_ruleset`;
- `landlock_add_rule`;
- `landlock_restrict_self`.

Landlock is enabled whenever either condition is true:

- `read_deny_paths` is configured;
- writes are controlled through `block_filesystem_writes` or
  `write_allow_paths`.

### Handled Rights

The ruleset handles read-related rights only when read-deny paths are
configured:

- execute;
- read file;
- read directory.

When write policy is enabled, the ruleset handles write-like rights:

- write file;
- remove file or directory;
- create regular files, directories, symlinks, FIFOs, sockets, and device nodes;
- `refer` on ABI 2+;
- `truncate`;
- device `ioctl` on ABI 5+.

The project requires Landlock ABI 3+ because older ABI versions cannot handle
`truncate`. Without blocking truncate, the write policy would have a significant
gap.

### Write Allow List

When write policy is enabled, the Landlock ruleset handles write-like rights.
The backend grants those rights only under `write_allow_paths`.

The default config is `block_filesystem_writes=True` with
`write_allow_paths=()`. That means Landlock handles write-like operations, but
no directory receives write rights. From the child process's perspective, the
default filesystem is effectively read-only except for operations outside
Landlock's handled rights.

### Read Deny List

Landlock is allow-list based, not deny-list based. To implement
`read_deny_paths`, the backend computes a read allow list that covers the
filesystem while excluding the denied directories and their descendants.

The algorithm works as follows:

1. Resolve all denied directories with `realpath()`.
2. Start from `/` as the pending candidate.
3. Skip a candidate if it is itself denied or beneath a denied directory.
4. If a candidate contains a denied directory, scan its direct children and keep
   descending.
5. Otherwise, add that candidate as a Landlock read-allow rule.

This produces a relatively compact set of allowed paths around the denied
subtrees. The implementation also tracks visited real paths to avoid repeated
work through symlinks or duplicate directory entries.

## seccomp-BPF Syscall Policy

The seccomp filter is built manually from classic BPF instructions and installed
with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`.

The filter first checks `seccomp_data.arch`. If the child is not running as
`AUDIT_ARCH_X86_64`, the process is killed. The filter then loads the syscall
number and returns `EPERM` for denied syscalls. Syscalls that are not explicitly
denied are allowed.

The denied syscall sets are selected from the config:

- network blocking denies socket creation, connect, bind/listen/accept,
  send/receive calls, socket options, and related batched message syscalls;
- filesystem write policy denies metadata-changing syscalls such as chmod,
  chown, xattr modification, selected timestamp changes, and also blocks
  io_uring;
- privilege blocking denies ptrace, mount, namespace entry or creation,
  user/group ID changes, keyring operations, module loading, BPF, reboot,
  hostname changes, chroot, pivot_root, and similar operations.

`clone` receives special handling. The filter checks the `clone()` flags
argument and denies only calls that request `CLONE_NEW*` namespace flags. This
allows ordinary process or thread creation while blocking namespace creation.

`clone3` is denied as part of the privilege-related syscall set.

## Privilege-Escalation Blocking

When `block_privilege_escalation=True`, the child receives two layers of
protection:

- `PR_SET_NO_NEW_PRIVS` prevents later `execve()` calls from gaining new
  privilege through setuid, setgid, or file capabilities;
- the seccomp filter denies common paths for credential changes, kernel-state
  changes, namespace operations, process attachment, and low-level kernel
  feature activation.

`no_new_privs` is also required before an unprivileged process can install a
seccomp filter, and it fits Landlock's `restrict_self` model.

## CLI Flow

The CLI lives in `src/simple_cp_sandbox/cli.py`.

It parses:

- `--timeout`;
- `--cwd`;
- repeated `--deny-read PATH`;
- repeated `--allow-write PATH`;
- the executable and remaining arguments.

The CLI converts these arguments into `SandboxConfig`, calls
`run_executable()`, and writes the captured child stdout/stderr back to the
runner's stdout/stderr.

Exit codes are:

- the target program's return code on normal completion;
- `124` on timeout;
- `125` when the sandbox cannot be created or started because of a sandbox
  error.

## Error Model

All package-specific errors inherit from `SandboxError`.

- `SandboxUnsupportedError` means the current OS, architecture, kernel feature
  set, or Landlock ABI cannot enforce the requested sandbox policy.
- `SandboxSecurityError` means startup would violate the safety policy, such as
  running as root with `refuse_root=True` or referencing a policy path that is
  not an existing directory.

The important property is that these errors occur before the target program is
allowed to run without the requested protections.

## Security Boundaries And Limitations

This project should be treated as a small runner, not a complete hostile-code
containment product.

Current boundaries include:

- only Linux amd64/x86_64 is supported;
- syscall numbers and architecture checks are x86_64-specific;
- Landlock is path based and its behavior depends on kernel support;
- the seccomp policy is deny-list based, so unlisted syscalls remain allowed;
- there are no CPU, memory, process-count, file-size, or cgroup limits;
- stdout and stderr are captured in memory by `subprocess.communicate()`;
- the parent process is trusted and should run as an unprivileged user;
- it is not a replacement for a VM, container runtime, or dedicated multi-tenant
  sandbox for high-value hostile workloads.

The package chooses conservative startup failure, but callers should still
review the policy against their own threat model, especially for
security-sensitive use cases.
