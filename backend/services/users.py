import logging
import uuid
from datetime import date
from typing import Any

import pymongo.errors
from mongodb_odm import ODMObjectId
from pymongo import ReturnDocument

from backend import utils
from backend.config import datasource
from backend.config.settings import AT_UNSENT_EXPIRATION_LIMIT
from backend.errors import DuplicateUserError, UserUnauthorizedError
from backend.errors import InvalidActivationTokenError
from backend.errors import UnhandledDatasourceError
from backend.models import ContactInfo, ActivationToken, ActivationTokenStatus, Session
from backend.models import NationalPersonIdentifier
from backend.models import User
from backend.models import UserRole
from backend.models import UserStatus

log = logging.getLogger("backend.services.users")


def create_activation_token(uid: ODMObjectId):
    """
    Creates and stores a new activation token for a new user.

    :param uid: user id
    """
    created_at = utils.utcnow()

    # activation tokens expires after 12 hours
    ActivationToken(uid=uid, token=str(uuid.uuid4()), created_at=created_at,
                    expires_at=created_at + AT_UNSENT_EXPIRATION_LIMIT).create()


def activate(token: str) -> str:
    """
    Activates a new user account by given activation token.

    :param token: activation token
    :return: activated user id
    """
    now = utils.utcnow()

    mdb_tokens = datasource.collection(ActivationToken.ODMConfig.collection_name)

    mdb_users = datasource.collection(User.ODMConfig.collection_name)

    # TODO: implement support for transactions in this project
    # with datasource.dbsession() as session:
    #    with session.start_transaction():
    at_query = {"token": token, "claimed_at": None, "status": ActivationTokenStatus.SENT.value,
                "expires_at": {"$gte": now}}

    at_update = {"$set": {"claimed_at": now, "status": ActivationTokenStatus.CLAIMED.value},
                 "$unset": {"expires_at": ""}}

    at = mdb_tokens.find_one_and_update(at_query, at_update, projection={"_id": 1, "uid": 1},
                                        return_document=ReturnDocument.AFTER)  # session=

    if not at:
        log.error(f"User account activation failed for token: {token}")
        raise InvalidActivationTokenError(token)

    usr_query = {"_id": at["uid"], "status": UserStatus.PENDING.value}

    usr_update = {"$set": {"status": UserStatus.ACTIVE.value, "updated_at": now}}

    result = mdb_users.update_one(usr_query, usr_update)  # session=

    if result.matched_count != 1:
        log.error(f"Unable to activate user: {result}")
        raise InvalidActivationTokenError(token)

    return str(at["uid"])


def create(email: str, password: str, surname: str, lastname: str, dob: date, role: UserRole,
           npi: NationalPersonIdentifier, contact_info: list[ContactInfo]):
    """
    Creates a unique new user by given parameters.

    :param email: user email address
    :param password: user password
    :param surname: user surname
    :param lastname: user lastname
    :param dob: user date of birth
    :param role: user role
    :param npi: user national person identifier
    :param contact_info: user contact information list
    :raises DuplicateUserError: if user already exists
    :return: new user object
    """
    try:
        # normalize email
        email = email.lower().strip()

        # normalize surname
        surname = surname.strip().title()

        # normalize lastname
        lastname = lastname.strip().title()

        # hash password
        password = User.hash_password(password)

        # setting up status
        if role == UserRole.ADMIN:
            status = UserStatus.ACTIVE
        else:
            status = UserStatus.PENDING

        return User(email=email, password=password, surname=surname, lastname=lastname, dob=dob, role=role.value,
                    npi=npi, contact_info=contact_info, status=status.value, created_at=utils.utcnow()).create()

    except pymongo.errors.DuplicateKeyError as ex:  # duplicated user case
        log.exception("Cannot create new user, user already exists.")
        raise DuplicateUserError(ex)

    except pymongo.errors.PyMongoError as ex:  # unable to write, instance down, etc.
        log.exception("Cannot create new user, something went wrong.")
        raise UnhandledDatasourceError(ex)


info_allowed_claims = {"email", "surname", "lastname", "dob", "npi",  # object
    "contact_info",  # list of objects
}


def info(sid: str, claims: list[str]) -> dict[str, Any]:
    mdb_sessions = datasource.collection(Session.ODMConfig.collection_name)

    claims = {claim: f"$user.{claim}" for claim in (set(claims) & info_allowed_claims)}
    if len(claims) == 0:
        log.error(f"Unable to retrieve user info, no valid requested claims: {claims}")
        raise ValueError("Invalid claims")

    pipeline = [{"$match": {"sid": sid, "revoked_at": None, "expires_at": {"$gt": utils.utcnow()}}},
        {"$lookup": {"from": User.ODMConfig.collection_name, "localField": "uid", "foreignField": "_id", "as": "user"}},
        {"$unwind": "$user"}, {"$match": {"user.status": UserStatus.ACTIVE.value}},
        {"$project": {"_id": 0, "user": claims}}, {"$limit": 1}]

    user = next(mdb_sessions.aggregate(pipeline), None)
    if not user:
        log.error(f"Unable to find user by given sid: {sid}")
        raise UserUnauthorizedError()

    return user
