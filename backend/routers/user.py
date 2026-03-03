import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Query, Form
from pydantic import BaseModel
from pydantic import EmailStr

from backend.config.http import Authorization
from backend.errors import DuplicateUserError, UserNotFoundError
from backend.errors import InvalidActivationTokenError
from backend.errors import UnhandledDatasourceError
from backend.errors import UserUnauthorizedError
from backend.models import ContactInfo
from backend.models import NationalPersonIdentifier
from backend.models import UserRole
from backend.services import sessions
from backend.services import users

# router for user authentication<
router = APIRouter(prefix="/user", tags=["Users authentication subsystem"])

log = logging.getLogger("backend.routers.user")


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/login")
def login(request: UserLoginRequest):
    """
    Generates tokens for user login and returns the access token and the refresh token.

    :param request: user login request
    :return: access & refresh tokens

    :raises HTTPException: 401 Unauthorized for invalid credentials
    """
    try:
        sid, expires_at = sessions.authenticate(
            request.email, request.password)

        return {"sid": sid, "expires_at": expires_at.timestamp()}

    except UserNotFoundError:
        raise HTTPException(status_code=401)

    except UserUnauthorizedError:
        raise HTTPException(status_code=401)  # invalid credentials


@router.delete("/logout")
def logout(credentials: Authorization):
    """
    Deletes the access token for the user.

    :param credentials: user login credentials
    """
    log.debug(f"Logout requested for SID: {credentials.credentials}")
    try:
        return {"uid": sessions.revoke(credentials.credentials)}
    except UserUnauthorizedError:
        raise HTTPException(status_code=401, detail={"sid": credentials.credentials})


@router.get("/info")
def info(claims: Annotated[list[str], Query(min_length=1)], credentials: Authorization):
    """
    Returns the user info with the provided claims.

    :param credentials: user login credentials
    :param claims: user claims
    """
    log.debug(f"User info requested for SID: {credentials.credentials}")
    try:
        return users.info(credentials.credentials, claims)

    except ValueError:
        raise HTTPException(status_code=400)

    except UserUnauthorizedError:  # session not found or invalid
        raise HTTPException(status_code=401, detail={"sid": credentials.credentials})


class UserRegistration(BaseModel):
    email: EmailStr
    password: str
    surname: str
    lastname: str
    dob: datetime
    npi: NationalPersonIdentifier
    contact_info: list[ContactInfo] = []


@router.post("/register", status_code=201)
def register(registration: UserRegistration):
    """
    Registers a new user.

    :param registration: user registration dto
    """
    try:
        # every user created by this endpoint is forced to have a USER role
        user = users.create(registration.email, registration.password, registration.surname, registration.lastname,
                            registration.dob, UserRole.USER, registration.npi, registration.contact_info)

        users.create_activation_token(user.id)

        log.info(f"New user successfully created: {user.id} - {user.email}")

        return {"uid": str(user.id)}

    except DuplicateUserError as ex:
        raise HTTPException(status_code=409, detail=ex.key)  # conflict

    except UnhandledDatasourceError:
        raise HTTPException(status_code=500)  # unhandled exception


@router.post("/activate")
def activate(token: Annotated[str, Form()]):
    """
    Activates a user using the provided activation token.

    :param token: activation token
    """
    try:
        return {"uid": users.activate(token)}
    except InvalidActivationTokenError:
        raise HTTPException(status_code=400)


@router.post("/password/forgot")
def forget_password(email: Annotated[str, Form()]):
    """
    Creates a password reset token for the user by the provided email.

    :param email: user email
    """
    pass


@router.post("/password/reset")
def reset_password(password_reset_token: Annotated[str, Form()], new_password: Annotated[str, Form()]):
    """
    Sets the new password by the given password reset token.

    :param password_reset_token: password reset token
    :param new_password: new password to be set
    """
    pass
