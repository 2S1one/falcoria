"""Shared enums for the scanledger REST contract and the port-scan domain."""

from enum import Enum


class ImportMode(str, Enum):
    """How an nmap import merges with what scanledger already stores."""

    INSERT = "insert"
    REPLACE = "replace"
    UPDATE = "update"
    APPEND = "append"


class ScannerFormat(str, Enum):
    """The scanner tool whose CLI arguments are built, or whose report format is parsed."""

    NMAP = "nmap"


class PortProtocol(str, Enum):
    """Transport protocol of a scanned port."""

    TCP = "tcp"
    UDP = "udp"


class PortState(str, Enum):
    """nmap port state."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class ServiceMethod(str, Enum):
    """How nmap determined the service on a port."""

    PROBED = "probed"
    TABLE = "table"


class PortChangeType(str, Enum):
    """The field whose change a port-history row records."""

    STATE = "state"
    SERVICE = "service"
    PRODUCT = "product"
    VERSION = "version"
