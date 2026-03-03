import logging
import ssl
from email.message import EmailMessage
from smtplib import SMTP
from smtplib import SMTPException

from backend.config.settings import EMAIL_SERVICE_ACCOUNT
from backend.config.settings import EMAIL_SERVICE_ACCOUNT_PASSWORD
from backend.config.settings import EMAIL_SERVICE_SERVER_ADDRESS
from backend.config.settings import EMAIL_SERVICE_USE_AUTH
from backend.config.settings import EMAIL_SERVICE_USE_TLS

log = logging.getLogger("backend.services.mailing")


def send_message(message: EmailMessage):
    try:
        with SMTP(EMAIL_SERVICE_SERVER_ADDRESS[0], EMAIL_SERVICE_SERVER_ADDRESS[1]) as server:
            server.ehlo()

            if EMAIL_SERVICE_USE_TLS:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()

            if EMAIL_SERVICE_USE_AUTH:
                server.login(EMAIL_SERVICE_ACCOUNT, EMAIL_SERVICE_ACCOUNT_PASSWORD)

            server.send_message(message)
    except SMTPException:
        log.exception("Unable to send activation email: fallback")
