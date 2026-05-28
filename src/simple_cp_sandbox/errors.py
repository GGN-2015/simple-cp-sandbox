class SandboxError(RuntimeError):
    """Base class for sandbox failures."""


class SandboxUnsupportedError(SandboxError):
    """Raised when the current OS cannot enforce the requested sandbox."""


class SandboxSecurityError(SandboxError):
    """Raised when starting would violate the sandbox security policy."""
