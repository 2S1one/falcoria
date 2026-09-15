"""How commonly each port/protocol pair is seen open, independent of any scan."""

from sqlalchemy import CheckConstraint, Column, String, UniqueConstraint
from sqlmodel import Field, SQLModel

from falcoria_contracts.enums import PortProtocol


class PortPrevalenceDB(SQLModel, table=True):
    """How commonly a port/protocol pair is seen open, independent of any scan.

    Static reference data, refreshed by re-running the sync step against the
    upstream source rather than by scan activity. Uniqueness is
    ``(number, protocol)`` — one row per port/protocol pair, shared across all
    projects. A missing pair means no data, not zero prevalence — callers must
    join rather than assume every port has a row.
    """

    __tablename__ = "port_prevalence"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (
        UniqueConstraint("number", "protocol"),
        CheckConstraint("score >= 0 AND score <= 1", name="ck_port_prevalence_score_range"),
    )

    id: int | None = Field(default=None, primary_key=True)
    number: int = Field(index=True)
    protocol: PortProtocol = Field(sa_column=Column(String, index=True, nullable=False))
    score: float = Field(index=True)
