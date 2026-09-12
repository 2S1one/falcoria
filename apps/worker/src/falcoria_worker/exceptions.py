"""Worker-specific exceptions."""


class WorkerError(Exception):
    """Base for the worker's own domain exceptions."""


class CommandExecutionError(WorkerError):
    """Raised when a scan subprocess exits with a non-zero status."""


class CommandTimeoutError(WorkerError):
    """Raised when a scan subprocess exceeds its timeout, even after SIGKILL escalation."""


class ScanUploadError(WorkerError):
    """Raised when uploading a scan report to scanledger fails."""
