"""Admin-only identity endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service
from falcoria_scanledger.auth.schemas import TokenOut, UserCreate
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import Conflict

router = APIRouter(prefix="/admin", tags=[Tag.AUTH])


@router.post(
    "/users",
    status_code=status.HTTP_201_CREATED,
    responses={status.HTTP_409_CONFLICT: {"description": "Username already taken."}},
)
async def create_user(
    body: UserCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TokenOut:
    """Creates an API user and returns its bearer token.

    The token appears only in this response; the server stores only its hash.
    """
    try:
        _, plaintext = await service.create_user(session, body)
    except IntegrityError as exc:
        raise Conflict(f"User '{body.username}' already exists.") from exc
    return TokenOut(token=plaintext)
