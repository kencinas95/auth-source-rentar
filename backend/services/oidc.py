import logging
from datetime import timedelta, timezone
from enum import Enum
from typing import Any

import bson.errors
from bson import ObjectId

from backend import utils
from backend.config import datasource
from backend.errors import UserNotFoundError, UserInactiveError
from backend.models import OIDCTicket
from backend.services import sessions

log = logging.getLogger("backend.services.oidc")


class OIDCAction(Enum):
    ABORT = "abort"
    PROCEED = "proceed"
    ONBOARD_REQUIRED = "onboard_required"


class OIDCAbortReason:
    MISSING_EMAIL = "email:missing"
    UNVERIFIED_EMAIL = "email:unverified"
    UNACTIVATED_USER = "user:unactivated"


def create_ticket(action: OIDCAction, **kwargs) -> str:
    """
    Creates an OIDC Ticket with the given parameters.

    :param action: oidc action
    :param kwargs: parameters for ticket
    :return: OIDC ticket id
    """
    created_at = utils.utcnow()

    ticket = OIDCTicket(action=action, payload=kwargs, created_at=created_at,
                        expires_at=created_at + timedelta(seconds=30)).create()

    return str(ticket.id)


def process(userinfo: dict[str, Any]) -> str:
    """
    Processes the userinfo dict and creates an OIDC Ticket.

    :param userinfo: userinfo dict
    :return: OIDC Ticket id
    """
    if not userinfo.get("email"):
        log.error("Untrusty OIDC user: email not found")
        return create_ticket(OIDCAction.ABORT, reason=OIDCAbortReason.MISSING_EMAIL)

    if not userinfo.get("email_verified"):
        log.error("Untrusty OIDC user: email is not verified")
        return create_ticket(OIDCAction.ABORT, reason=OIDCAbortReason.UNVERIFIED_EMAIL)

    try:
        sid, expires_at = sessions.authenticate(userinfo.get("email"), check_credentials=False)

        return create_ticket(OIDCAction.PROCEED, sid=sid, expires_at=expires_at)

    except UserNotFoundError:
        return create_ticket(OIDCAction.ONBOARD_REQUIRED, email=userinfo.get("email"))

    except UserInactiveError:
        return create_ticket(OIDCAction.ABORT, reason=OIDCAbortReason.UNACTIVATED_USER, email=userinfo.get("email"))


def exchange(ticket_id: str) -> tuple[int, dict[str, Any] | None]:
    """
    Retrieves the OIDC Ticket with the given ticket_id.

    :param ticket_id: ticket id
    :return: ticket payload
    """
    mdb_tickets = datasource.collection(OIDCTicket.ODMConfig.collection_name)

    try:
        log.debug(f"Retrieving OIDC ticket {ticket_id}")

        ticket_id = ObjectId(ticket_id)

        ticket = mdb_tickets.find_one_and_delete({"_id": ticket_id})

        if not ticket:
            log.error(f"OIDC Ticket not found: {ticket_id}")
            return 404, None

        if ticket["expires_at"].replace(tzinfo=timezone.utc) < utils.utcnow():
            log.error(f"OIDC Ticket expired: {ticket_id}")
            return 410, None

        log.debug(f"OIDC Ticket successfully retrieved: {ticket_id}")
        return 200, {"action": ticket["action"], "payload": ticket["payload"]}

    except bson.errors.InvalidId:
        log.error(f"Given ticket id is invalid: {ticket_id}")
        return 400, None
