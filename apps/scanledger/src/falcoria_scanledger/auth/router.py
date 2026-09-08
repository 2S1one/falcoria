"""Admin-only identity endpoints."""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service
from falcoria_scanledger.auth.schemas import TokenOut, TokenRequest, UserCreate, UserOut
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import Conflict, NotFound

router = APIRouter(prefix="/admin", tags=[Tag.AUTH])

_USER_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"description": "No such user."}
}


@router.get("/users")
async def list_users(session: Annotated[AsyncSession, Depends(get_session)]) -> list[UserOut]:
    """Lists every API user."""
    return [UserOut.model_validate(user) for user in await service.list_users(session)]


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


@router.delete(
    "/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, responses=_USER_NOT_FOUND
)
async def delete_user(
    user_id: uuid.UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Deletes an API user."""
    if not await service.delete_user(session, user_id):
        raise NotFound(f"User {user_id} not found.")


@router.put("/users/{user_id}/token", responses=_USER_NOT_FOUND)
async def rotate_token(
    user_id: uuid.UUID,
    body: TokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> TokenOut:
    """Issues a fresh bearer token for a user, revoking the previous one."""
    plaintext = await service.rotate_token(session, user_id, body.token_lifetime)
    if plaintext is None:
        raise NotFound(f"User {user_id} not found.")
    return TokenOut(token=plaintext)
