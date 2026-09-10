"""Facet request/result model for POST /ips/facets.

The filter selects a host population; each facet reports, per distinct value, how
many of those hosts have it. A matched host contributes its full open-port
inventory, so a host selected by one service also appears under every other
service it runs.
"""

from typing import Any

from fastapi.openapi.models import Example
from pydantic import BaseModel, Field
from sqlalchemy.orm import Mapped
from sqlmodel import col

from falcoria_scanledger.ips.models import IPDB, PortDB
from falcoria_scanledger.ips.search import IPFilter


class FacetsRequest(BaseModel):
    """Body of POST /ips/facets: a host filter and a per-facet cap."""

    filter: IPFilter = Field(default_factory=IPFilter)
    limit: int = Field(default=100, ge=1, le=1000, description="Max distinct values per facet.")


class FacetValue(BaseModel):
    """One value of a facet and the number of matched hosts that have it."""

    value: str | None = Field(description="The facet value; null is its own bucket.")
    count: int = Field(description="Distinct matched hosts with this value.")


class FacetsResult(BaseModel):
    """Per-dimension host counts for the hosts matching the filter.

    Each list is ordered by descending count. The `os` facet includes hosts with
    no open ports; the port-level facets do not.
    """

    port: list[FacetValue]
    protocol: list[FacetValue]
    service: list[FacetValue]
    product: list[FacetValue]
    version: list[FacetValue]
    tunnel: list[FacetValue]
    os: list[FacetValue]


_PORT_IP = col(PortDB.ip_id)

# facet name -> (column grouped on, the host-id column of that column's table).
FACET_COLUMNS: dict[str, tuple[Mapped[Any], Mapped[Any]]] = {
    "port": (col(PortDB.number), _PORT_IP),
    "protocol": (col(PortDB.protocol), _PORT_IP),
    "service": (col(PortDB.service), _PORT_IP),
    "product": (col(PortDB.product), _PORT_IP),
    "version": (col(PortDB.version), _PORT_IP),
    "tunnel": (col(PortDB.tunnel), _PORT_IP),
    "os": (col(IPDB.os), col(IPDB.id)),
}


FACET_EXAMPLES: dict[str, Example] = {
    "overview": Example(
        summary="Whole-project overview",
        description="No filter — value counts across every host in the project.",
        value={},
    ),
    "within_subnet": Example(
        summary="Breakdown inside a subnet",
        description="Facets restricted to hosts in 203.0.113.0/24.",
        value={"filter": {"cidr": "203.0.113.0/24"}},
    ),
    "http_hosts_inventory": Example(
        summary="What else HTTP hosts expose",
        description=(
            "Hosts with any HTTP port; the service and port facets then show every "
            "other service those hosts run."
        ),
        value={"filter": {"ports": {"all_of": [{"service_ilike": "http"}]}}},
    ),
}
