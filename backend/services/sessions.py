import logging
import secrets
from datetime import datetime

from mongodb_odm import ODMObjectId
from pymongo import ReturnDocument

from backend import utils
from backend.config import datasource
from backend.config.settings import AUTH_SESSION_EXPIRATION_LIMIT
from backend.config.settings import AUTH_SESSION_IDLE_LIMIT
from backend.errors import UserUnauthorizedError, InvalidSessionError, UserNotFoundError, UserInactiveError
from backend.models import Session, UserSessionStatus, UserSessionType
from backend.models import User
from backend.models import UserStatus

log = logging.getLogger(__name__)


def clean(uid: ODMObjectId):
    """
    Cleans every active session for the given session id.

    :param uid: session id
    """
    mdb_sessions = datasource.collection(Session.ODMConfig.collection_name)

    query = {"uid": uid, "revoked_at": None, "status": UserSessionStatus.ACTIVE.value}

    update = {"$currentDate": {"revoked_at": True}, "$set": {"status": UserSessionStatus.REVOKED.value}}

    mdb_sessions.update_many(query, update)  # don't care about the result


def authenticate(email: str, password: str | None = None, check_credentials: bool = True) -> tuple[str, int]:
    """
    Authenticates a user and creates a new session for the given email and password.

    :param email: user's email
    :param password: user's password
    :param check_credentials: checks the given credentials
    :return: session id, expires_at
    """
    user = User.find_one({"email": email})

    if not user:  # validates user
        log.error(f"Unable to authenticate user, not found: {email}")
        raise UserNotFoundError(email)  # unauthorized

    if user.status != UserStatus.ACTIVE.value:
        log.error(f"Unable to authenticate user ({email}), is not active: {user.status}")
        raise UserInactiveError(str(user.id))

    if check_credentials:
        log.debug(f"Authenticating user with password: {email}")
        if not user.check_password(password):
            log.error(f"Authentication failed for user: {email}")
            raise UserUnauthorizedError()

    clean(user.id)  # clean active sessions, force to only have one session active

    # utc now
    now = utils.utcnow()

    # session token - 64 bytes to enforce uniqueness
    sid = secrets.token_urlsafe(64)

    # session creation
    session = Session(sid=sid, uid=user.id, created_at=now, last_seen_at=now, type=UserSessionType.CREDENTIALS.value,
                      expires_at=now + AUTH_SESSION_EXPIRATION_LIMIT).create()

    # sid, expires_at, idle_session_timelimit
    return session.sid, int(session.expires_at.timestamp())


def validate(sid: str):
    """
    Validates a session for the given session id.

    :param sid: session id
    :raises InvalidSessionError: when session id is not found / expired / idle expired / revoked
    :raises UserUnauthorizedError: when user is not found
    """
    utcnow = utils.utcnow()

    mdb_sessions = datasource.collection(Session.ODMConfig.collection_name)

    valid_last_seen_timeframe = utcnow - AUTH_SESSION_IDLE_LIMIT

    query = {"sid": sid, "status": UserSessionStatus.ACTIVE.value, "revoked_at": None, "expires_at": {"$gt": utcnow},
             "last_seen_at": {"$gte": valid_last_seen_timeframe}}

    update = {"$currentDate": {"last_seen_at": True}}

    session = mdb_sessions.find_one_and_update(query, update, projection={"uid": 1},
                                               return_document=ReturnDocument.AFTER)

    if not session:
        log.error(f"Unable to validate session, active session not found: {sid}")

        # try to mark the session as expired or idle expired (if found)
        mdb_sessions.update_one({"sid": sid, "status": UserSessionStatus.ACTIVE.value}, [{"$set": {"status": {
            "$cond": [{"$lte": ["$expires_at", utcnow]}, UserSessionStatus.EXPIRED.value,
                      UserSessionStatus.IDLE_EXPIRED.value]}}}])

        raise InvalidSessionError()  # expired / revoked / out of idle time

    # checks if the user still exists...
    user = User.find_one({"_id": session["uid"], "status": UserStatus.ACTIVE.value})
    if not user:
        log.error(f"Revoke session for user not found: {session['uid']}")

        # async rollback - marked for housekeeping scheduler
        mdb_sessions.update_many({"uid": session["uid"]}, {"$currentDate": {"revoked_at": True},
                                                           "$set": {"status": UserSessionStatus.ORPHAN.value}})
        raise UserUnauthorizedError()


def revoke(sid: str) -> str:
    """
    Revokes a session for the given session id.

    :param sid: session id
    :return: session's user id
    """
    mdb_sessions = datasource.collection(Session.ODMConfig.collection_name)

    query = {"sid": sid, "revoked_at": None, "status": UserSessionStatus.ACTIVE.value,
             "expires_at": {"$gt": utils.utcnow()}}

    update = {"$currentDate": {"revoked_at": True}, "$set": {"status": UserSessionStatus.REVOKED.value}}

    session = mdb_sessions.find_one_and_update(query, update, projection={"uid": 1},
                                               return_document=ReturnDocument.AFTER)
    if not session:
        log.error(f"Unable to revoke session, not found: {sid}")
        raise UserUnauthorizedError()

    return str(session["uid"])
