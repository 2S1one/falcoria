"""Filter model and SQL compilation for POST /ips/search.

The request is a flat host-level filter (its set fields AND-ed) plus port-scoped
predicate groups. Each PortClause compiles to one correlated EXISTS over the IP's
open ports, so every condition in a clause must hold on the *same* port row.
"""

from ipaddress import ip_network
from uuid import UUID

from fastapi.openapi.models import Example
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import ColumnElement, and_, cast, or_
from sqlalchemy.dialects.postgresql import INET
from sqlmodel import col, select

from falcoria_contracts.enums import PortProtocol
from falcoria_scanledger.ips.models import (
    IPDB,
    ObservedHostnameDB,
    ObservedHostnameIPLink,
    PortDB,
)
from falcoria_scanledger.ips.schemas import IPOut


class PortClause(BaseModel):
    """Conditions that must all hold on one open-port row of an IP."""

    number: int | None = Field(default=None, description="Exact port number.")
    number_in: list[int] | None = Field(default=None, description="Port number is one of these.")
    number_not_in: list[int] | None = Field(
        default=None, description="Port number is none of these."
    )
    protocol: PortProtocol | None = None
    service_ilike: str | None = Field(
        default=None, description="Service name contains this substring, case-insensitive."
    )
    service_in: list[str] | None = Field(default=None, description="Service name is one of these.")
    service_is_null: bool | None = Field(
        default=None,
        description="True matches ports with no identified service; False the inverse.",
    )
    product_ilike: str | None = Field(
        default=None, description="Product contains this substring, case-insensitive."
    )
    product_not_ilike: str | None = Field(
        default=None,
        description="Product does not contain this substring; a port with no product still matches.",
    )
    product_in: list[str] | None = Field(default=None, description="Product is one of these.")
    product_not_in: list[str] | None = Field(
        default=None,
        description="Product is none of these; a port with no product still matches.",
    )
    version_ilike: str | None = Field(
        default=None, description="Version string contains this substring (text match, not semver)."
    )
    tunnel: str | None = Field(default=None, description='Exact tunnel value, e.g. "ssl".')


class PortGroups(BaseModel):
    """Port-scoped predicate groups; each clause becomes one EXISTS over the IP's ports."""

    all_of: list[PortClause] = Field(
        default_factory=list, description="The IP must have a port matching every clause."
    )
    any_of: list[PortClause] = Field(
        default_factory=list,
        description="The IP must have a port matching at least one clause.",
    )
    none_of: list[PortClause] = Field(
        default_factory=list, description="The IP must have no port matching any clause."
    )


class IPFilter(BaseModel):
    """Host-level filter; every set field is AND-ed."""

    cidr: str | None = Field(
        default=None, description="CIDR the address must fall within, e.g. 10.1.0.0/16."
    )
    os_ilike: str | None = Field(
        default=None, description="Reported OS contains this substring, case-insensitive."
    )
    hostname_ilike_any: list[str] | None = Field(
        default=None,
        description="Match if any observed hostname contains any of these substrings.",
    )
    has_hostname: bool | None = Field(
        default=None, description="True: the IP has at least one hostname. False: it has none."
    )
    first_seen_gte: int | None = Field(
        default=None, description="First seen at or after this Unix epoch second."
    )
    first_seen_lt: int | None = Field(
        default=None, description="First seen before this Unix epoch second."
    )
    last_seen_gte: int | None = Field(
        default=None, description="Last seen at or after this Unix epoch second."
    )
    last_seen_lt: int | None = Field(
        default=None, description="Last seen before this Unix epoch second."
    )
    ports: PortGroups | None = None

    @field_validator("cidr")
    @classmethod
    def _normalise_cidr(cls, v: str | None) -> str | None:
        return None if v is None else str(ip_network(v, strict=False))


class IPSearchRequest(BaseModel):
    """Body of POST /ips/search: a filter, a page window, and the port projection."""

    filter: IPFilter = Field(default_factory=IPFilter)
    matched_ports_only: bool = Field(
        default=False,
        description="Return only the ports matching the all_of / any_of clauses, "
        "not every open port on the IP.",
    )
    skip: int = Field(default=0, ge=0, description="Number of matched IPs to skip.")
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum matched IPs to return.")


class IPSearchResult(BaseModel):
    """One page of matched IPs plus the total match count, ignoring skip/limit."""

    items: list[IPOut]
    total: int = Field(description="Total IPs matching the filter, before skip/limit.")


SEARCH_EXAMPLES: dict[str, Example] = {
    "cidr_and_port": Example(
        summary="RDP exposed in a subnet",
        description="Hosts in 203.0.113.0/24 with 3389/tcp open.",
        value={"filter": {"cidr": "203.0.113.0/24", "ports": {"all_of": [{"number": 3389}]}}},
    ),
    "http_on_odd_port": Example(
        summary="HTTP on a non-standard port",
        description=(
            "One port that is both an HTTP service and outside the usual web ports; "
            "matched_ports_only returns just those ports."
        ),
        value={
            "filter": {
                "ports": {
                    "all_of": [{"service_ilike": "http", "number_not_in": [80, 443, 8080, 8443]}]
                }
            },
            "matched_ports_only": True,
        },
    ),
    "exclude_common_web": Example(
        summary="Web servers that aren't nginx or Apache",
        description=(
            "HTTP services whose product is neither nginx nor Apache; unidentified "
            "products are kept."
        ),
        value={
            "filter": {
                "ports": {
                    "all_of": [
                        {"service_ilike": "http", "product_not_in": ["nginx", "Apache httpd"]}
                    ]
                }
            }
        },
    ),
    "or_of_shapes": Example(
        summary="nginx on 443 OR any HTTP on an odd port",
        description="Two different single-port shapes OR'd at the host level.",
        value={
            "filter": {
                "ports": {
                    "any_of": [
                        {"number": 443, "product_ilike": "nginx"},
                        {"service_ilike": "http", "number_not_in": [80, 443, 8080, 8443]},
                    ]
                }
            }
        },
    ),
    "new_hosts": Example(
        summary="New hosts since a timestamp",
        description="Hosts first seen at or after the given Unix epoch second.",
        value={"filter": {"first_seen_gte": 1757400000}},
    ),
}


def _contains(value: str) -> str:
    """Return `value` as an ILIKE substring pattern with LIKE wildcards escaped."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _clause_conditions(clause: PortClause) -> list[ColumnElement[bool]]:
    """Translate one PortClause into per-column conditions on PortDB.

    The negative operators (`number_not_in`, `product_not_in`, `product_not_ilike`)
    keep rows whose column is NULL — an exclude never drops an unidentified value.
    """
    conds: list[ColumnElement[bool]] = []
    if clause.number is not None:
        conds.append(col(PortDB.number) == clause.number)
    if clause.number_in:
        conds.append(col(PortDB.number).in_(clause.number_in))
    if clause.number_not_in:
        conds.append(col(PortDB.number).not_in(clause.number_not_in))
    if clause.protocol is not None:
        conds.append(col(PortDB.protocol) == clause.protocol.value)
    if clause.service_ilike is not None:
        conds.append(col(PortDB.service).ilike(_contains(clause.service_ilike), escape="\\"))
    if clause.service_in:
        conds.append(col(PortDB.service).in_(clause.service_in))
    if clause.service_is_null is not None:
        conds.append(
            col(PortDB.service).is_(None)
            if clause.service_is_null
            else col(PortDB.service).is_not(None)
        )
    if clause.product_ilike is not None:
        conds.append(col(PortDB.product).ilike(_contains(clause.product_ilike), escape="\\"))
    if clause.product_not_ilike is not None:
        conds.append(
            or_(
                col(PortDB.product).is_(None),
                ~col(PortDB.product).ilike(_contains(clause.product_not_ilike), escape="\\"),
            )
        )
    if clause.product_in:
        conds.append(col(PortDB.product).in_(clause.product_in))
    if clause.product_not_in:
        conds.append(
            or_(col(PortDB.product).is_(None), col(PortDB.product).not_in(clause.product_not_in))
        )
    if clause.version_ilike is not None:
        conds.append(col(PortDB.version).ilike(_contains(clause.version_ilike), escape="\\"))
    if clause.tunnel is not None:
        conds.append(col(PortDB.tunnel) == clause.tunnel)
    return conds


def _port_exists(clause: PortClause) -> ColumnElement[bool]:
    """Correlated EXISTS: the IP has an open port satisfying every part of `clause`."""
    return (
        select(col(PortDB.id))
        .where(col(PortDB.ip_id) == col(IPDB.id), *_clause_conditions(clause))
        .exists()
    )


def _has_hostname() -> ColumnElement[bool]:
    return (
        select(col(ObservedHostnameIPLink.ip_id))
        .where(col(ObservedHostnameIPLink.ip_id) == col(IPDB.id))
        .exists()
    )


def _hostname_matches(patterns: list[str]) -> ColumnElement[bool]:
    return (
        select(col(ObservedHostnameIPLink.ip_id))
        .join(
            ObservedHostnameDB,
            col(ObservedHostnameDB.id) == col(ObservedHostnameIPLink.hostname_id),
        )
        .where(
            col(ObservedHostnameIPLink.ip_id) == col(IPDB.id),
            or_(
                *(
                    col(ObservedHostnameDB.hostname).ilike(_contains(p), escape="\\")
                    for p in patterns
                )
            ),
        )
        .exists()
    )


def build_search_conditions(project_id: UUID, f: IPFilter) -> list[ColumnElement[bool]]:
    """Build the WHERE conditions for an IP search, always scoped to `project_id`.

    Returned as a list so the page query and the count query share it. Every
    condition is on IPDB or a correlated EXISTS, so the statement stays at
    IP-row grain and LIMIT / OFFSET / COUNT stay exact.
    """
    conds: list[ColumnElement[bool]] = [col(IPDB.project_id) == project_id]

    if f.cidr is not None:
        conds.append(cast(col(IPDB.ip), INET).op("<<=")(cast(f.cidr, INET)))
    if f.os_ilike is not None:
        conds.append(col(IPDB.os).ilike(_contains(f.os_ilike), escape="\\"))
    if f.first_seen_gte is not None:
        conds.append(col(IPDB.first_seen) >= f.first_seen_gte)
    if f.first_seen_lt is not None:
        conds.append(col(IPDB.first_seen) < f.first_seen_lt)
    if f.last_seen_gte is not None:
        conds.append(col(IPDB.last_seen) >= f.last_seen_gte)
    if f.last_seen_lt is not None:
        conds.append(col(IPDB.last_seen) < f.last_seen_lt)

    if f.has_hostname is not None:
        conds.append(_has_hostname() if f.has_hostname else ~_has_hostname())
    if f.hostname_ilike_any:
        conds.append(_hostname_matches(f.hostname_ilike_any))

    if f.ports is not None:
        conds.extend(_port_exists(c) for c in f.ports.all_of)
        conds.extend(~_port_exists(c) for c in f.ports.none_of)
        if f.ports.any_of:
            conds.append(or_(*(_port_exists(c) for c in f.ports.any_of)))

    return conds


def matched_port_filter(f: IPFilter) -> ColumnElement[bool] | None:
    """Condition picking the ports a `matched_ports_only` response should carry.

    An OR of the all_of / any_of clauses. `none_of` is excluded — it proves a
    port is absent, it does not name a port to return. None when nothing
    positive was asked for.
    """
    if f.ports is None:
        return None
    groups = [
        and_(*conds)
        for clause in (*f.ports.all_of, *f.ports.any_of)
        if (conds := _clause_conditions(clause))
    ]
    return or_(*groups) if groups else None
