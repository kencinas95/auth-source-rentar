import logging
from email.message import EmailMessage
from smtplib import SMTPException
from typing import Any
import urllib.parse

from backend import utils
from backend.config import datasource
from backend.config import templates
from backend.config.settings import MAIN_APPLICATION_URL
from backend.config.settings import EMAIL_SERVICE_ACCOUNT
from backend.config.settings import AT_SENT_EXPIRATION_LIMIT
from backend.models import ActivationToken
from backend.models import ActivationTokenStatus
from backend.models import User
from backend.models import UserStatus
from backend.services import mailing


log = logging.getLogger("backend.jobs.users")

class ATokenQueryResult(object):
    def __init__(self, raw: dict[str, Any]):
        self.id = raw["_id"]
        self.token = raw["token"]
        self.email = raw["user"]["email"]
        self.fullname = raw["user"]["surname"] + " " + raw["user"]["lastname"]


def job_send_activation_token_email():
    """
    Sends an activation email to a new user.
    """
    # raw mdb collection instance
    mdb_collection = datasource.collection(ActivationToken.ODMConfig.collection_name)

    # query
    pipeline = [{"$match": {"status": ActivationTokenStatus.UNSENT.value, "expires_at": {"$gt": utils.utcnow()}}}, {
        "$lookup": {"from": User.ODMConfig.collection_name, "localField": "uid", "foreignField": "_id", "as": "user"}},
                {"$unwind": "$user"}, {"$match": {"user.status": UserStatus.PENDING.value}},
                {"$project": {"_id": 1, "token": 1, "user.email": 1, "user.surname": 1, "user.lastname": 1}}]

    # TODO: add a semaphore (or lock) to avoid schedulers collision
    with mdb_collection.aggregate(pipeline) as cursor:
        for at in cursor:
            result = ATokenQueryResult(at)

            log.debug(f"Sending account activation token email to user: {result.email}")

            # convert to query params
            at_url_safe = urllib.parse.urlencode({"token": result.token})

            # generate hyperlink
            activation_link_url = MAIN_APPLICATION_URL + "/register/activate?" + at_url_safe

            # render content
            content = templates.render("account_activation_email.template.html", fullname=result.fullname,
                                       link=activation_link_url)

            message = EmailMessage()
            message["From"] = EMAIL_SERVICE_ACCOUNT
            message["To"] = result.email
            message["Subject"] = "Activation link"
            message.set_content("Please activate your account.")
            message.add_alternative(content, subtype="html")

            try:
                mailing.send_message(message)

                mdb_collection.update_one({"_id": result.id}, {
                    "$set": {"status": ActivationTokenStatus.SENT.value, "sent_at": utils.utcnow(),
                             "expires_at": utils.utcnow() + AT_SENT_EXPIRATION_LIMIT}})
            except SMTPException:
                log.error(f"Error sending account activation email to user: {result.email}")
                mdb_collection.update_one({"_id": result.id}, {"$inc": {"sending_attempts_count": 1}})

            log.info(f"Account activation link sent [{activation_link_url}] to user: {result.email}")
