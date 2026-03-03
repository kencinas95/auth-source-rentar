from datetime import datetime
from enum import Enum
from typing import Any

import bcrypt
from mongodb_odm import Document, ODMObjectId
from mongodb_odm import IndexModel
from pydantic import BaseModel

from backend import utils


# --- enums ---

class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"


class UserStatus(Enum):
    ACTIVE = "active"
    PENDING = "pending"
    DELETED = "deleted"


class ContactInfoType(Enum):
    EMAIL = "email"
    PHONE = "phone"


class ActivationTokenStatus(Enum):
    UNSENT = "unsent"
    SENT = "sent"
    CLAIMED = "claimed"
    EXPIRED = "expired"
    FAILED = "failed"


class UserSessionStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    IDLE_EXPIRED = "idle_expired"
    REVOKED = "revoked"
    ORPHAN = "orphan"


class UserSessionType(Enum):
    CREDENTIALS = "credentials"
    OIDC = "oidc"
    OAUTH = "oauth"


# --- sub documents ---

class NationalPersonIdentifier(BaseModel):
    type: str  # National Document Identifier, Passport, etc.
    value: str


class ContactInfo(BaseModel):
    type: str
    value: str
    is_active: bool = False


# --- document models ---


class User(Document):
    email: str

    password: str  # bcrypt(password)

    surname: str

    lastname: str

    dob: datetime

    npi: NationalPersonIdentifier  # country's unique person identifier

    role: str

    status: str

    created_at: datetime

    updated_at: datetime | None = None

    contact_info: list[ContactInfo]

    class ODMConfig(Document.ODMConfig):
        collection_name = "users"

        indexes = [IndexModel(["email"], unique=True), IndexModel(["npi.type", "npi.value"], unique=True)]

    @property
    def fullname(self) -> str:
        return (self.surname + " " + self.lastname).strip().title()

    def check_password(self, password: str) -> bool:
        """
        Checks if the password is correct.

        :param password:
        :return:
        """
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hashes the password and returns the hashed password.

        :param password: password to be hashed
        :return: bcrypt hashed password
        """
        password_bytes = password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        return hashed_password.decode('utf-8')


class ActivationToken(Document):
    uid: ODMObjectId

    token: str

    created_at: datetime

    status: str = ActivationTokenStatus.UNSENT.value  # UNSENT, SENT, CLAIMED, EXPIRED, FAILED

    sending_attempts_count: int = 0

    sent_at: datetime | None = None

    expires_at: datetime | None = None

    claimed_at: datetime | None = None

    class ODMConfig(Document.ODMConfig):
        collection_name = "activation_tokens"

        indexes = [IndexModel(["uid"], unique=True), IndexModel(["token"], unique=True), IndexModel(["status"]),
                   IndexModel(["created_at"]), IndexModel(["sending_attempts_count"])]


class Session(Document):
    sid: str

    type: str

    uid: ODMObjectId  # User id

    created_at: datetime

    expires_at: datetime  # it could be replaced by index TTL

    status: str = UserSessionStatus.ACTIVE.value

    last_seen_at: datetime | None = None

    revoked_at: datetime | None = None

    class ODMConfig(Document.ODMConfig):
        collection_name = "sessions"

        indexes = [IndexModel(["sid"], unique=True), IndexModel(["uid"]),  # multiple sessions history
                   IndexModel([("status", 1), ("uid", 1)]),
                   IndexModel(["uid"], unique=True, partialFilterExpression={"status": UserSessionStatus.ACTIVE.value},
                              name="one_active_session_per_user"), IndexModel(["created_at"]),  # for housekeeping later
                   IndexModel(["expires_at"])]  # keep it for auditory / history

    @property
    def is_active(self) -> bool:
        return all(
            [self.status == UserSessionStatus.ACTIVE.value, self.revoked_at is None, self.expires_at > utils.utcnow()])


class OIDCTicket(Document):
    action: str
    payload: dict[str, Any]
    created_at: datetime
    expires_at: datetime

    class ODMConfig(Document.ODMConfig):
        collection_name = "oidc_tickets"
        indexes = [IndexModel(["action"]), IndexModel(["created_at"]), IndexModel(["expires_at"], expireAfterSeconds=0)]
