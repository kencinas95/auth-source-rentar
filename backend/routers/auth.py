from typing import Annotated

from fastapi import APIRouter, HTTPException
from fastapi import Form

from backend.config.http import Authorization
from backend.errors import UserUnauthorizedError, InvalidSessionError
from backend.services import sessions

router = APIRouter(prefix="/auth", tags=["Authentication subsystem"])


@router.post("/validate")
def validate(credentials: Authorization):
    """
    Validates the access token; also refresh it if necessary.

    :param credentials: user credentials
    """
    try:
        sessions.validate(credentials.credentials)
        return {"sid": credentials.credentials}
    except UserUnauthorizedError | InvalidSessionError:
        raise HTTPException(status_code=401)


@router.delete("/user")
def remove_user(email: Annotated[str, Form()]):
    """
    Deletes an existing user from the system.

    :param email: user email
    :return:
    """
    pass
