"""Project records and the project-membership link table."""

import uuid

from sqlalchemy import Column, ForeignKey, Uuid
from sqlmodel import Field, SQLModel


class ProjectDB(SQLModel, table=True):
    """A project: the container that scopes IP inventory and scan history.

    `name` is unique and set once at creation; `comment` is the only mutable
    field.
    """

    # SQLAlchemy types __tablename__ as declared_attr; a plain str is correct here.
    __tablename__ = "projects"  # pyright: ignore[reportAssignmentType]

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True)
    comment: str | None = None


class ProjectMemberLink(SQLModel, table=True):
    """Join row granting one user access to one project.

    Both foreign keys cascade on delete, so removing a user or a project also
    clears its membership rows.
    """

    __tablename__ = "project_member_link"  # pyright: ignore[reportAssignmentType]

    project_id: uuid.UUID = Field(
        sa_column=Column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    )
    user_id: uuid.UUID = Field(
        sa_column=Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    )
