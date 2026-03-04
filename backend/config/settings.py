import os
import urllib.parse as up
from datetime import timedelta
from pathlib import Path

# --- application settings ---
APPLICATION_NAME = os.environ["APPLICATION_NAME"]
APPLICATION_ROOT = Path(__file__).parent.parent.parent

# --- server settings ---
SERVER_APPLICATION_HOST = os.environ["SERVER_APPLICATION_HOST"]
SERVER_APPLICATION_PORT = int(os.environ["SERVER_APPLICATION_PORT"])
SERVER_BASE_URL = os.environ["SERVER_INSTANCE_BASE_URL"]

# --- mongo settings ---
MDB_USERNAME = os.environ["MDB_USERNAME"]
MDB_PASSWORD = os.environ["MDB_PASSWORD"]
MDB_DATABASE_NAME = os.environ["MDB_DATABASE_NAME"]
MDB_HOSTNAME = os.environ["MDB_HOSTNAME"]
MDB_PORT = int(os.environ["MDB_PORT"])
MDB_CONNECTION_URL = os.environ.get("MDB_CONNECTION_URL")
#if not MDB_CONNECTION_URL:
#    MDB_CONNECTION_URL = (f"mongodb://{MDB_USERNAME}:{up.quote(MDB_PASSWORD, safe='')}"
#                          f"@{MDB_HOSTNAME}:{MDB_PORT}/{MDB_DATABASE_NAME}"
#                          "?authSource=admin")

MDB_MAX_BATCH_SIZE = 3000

# --- activation token settings ---
AT_UNSENT_EXPIRATION_LIMIT = timedelta(hours=12)

AT_SENT_EXPIRATION_LIMIT = timedelta(days=7)

# --- auth session settings ---
AUTH_SESSION_IDLE_LIMIT = timedelta(minutes=30)

AUTH_SESSION_EXPIRATION_LIMIT = timedelta(hours=8)

AUTH_SESSION_STORAGE_AUDIT_TIME_LIMIT = timedelta(days=90)

# --- smtp settings ---
EMAIL_SERVICE_SERVER_ADDRESS = (os.environ["SMTP_SERVER_ADDRESS_HOST"], int(os.environ["SMTP_SERVER_ADDRESS_PORT"]))

EMAIL_SERVICE_USE_TLS = False  # only in dev / testing

EMAIL_SERVICE_USE_AUTH = False  # only in dev / testing

EMAIL_SERVICE_ACCOUNT = os.environ["SMTP_SERVER_ACCOUNT_USER"]

EMAIL_SERVICE_ACCOUNT_PASSWORD = os.environ["SMTP_SERVER_ACCOUNT_PASSWORD"]

# --- data ---
DATA_ROOT = APPLICATION_ROOT / "data"

# --- external links ---
MAIN_APPLICATION_URL = os.environ["REMOTE_APP_RENTAR_BASE_URL"]

# --- logging settings ---
LOGGING = {"version": 1, "disable_existing_loggers": False, "formatters": {"default": {
    "format": '%(asctime)s.%(msecs)03d %(levelname)s %(process)d --- [%(threadName)s] %(name)s : %(message)s',
    "datefmt": "%Y-%m-%d %H:%M:%S"}}, "handlers": {
    "console": {"class": "logging.StreamHandler", "formatter": "default", "level": "DEBUG",
                "stream": "ext://sys.stdout"}},
           "loggers": {"console": {"level": "DEBUG", "handlers": ["console"], "propagate": True}},
           'root': {'level': 'INFO', 'handlers': ['console'], 'propagate': False}}

# --- oidc settings ---
OIDC_REGISTRY = [
    {
        "name": "rentar",
        "return_to": os.environ["REMOTE_APP_RENTAR_BASE_URL"] + "/auth/callback",
        "providers": [
            {
                "name": "google",
                "client_id": os.environ["OIDC_REGISTRY_RENTAR_CLIENT_ID"],
                "client_secret": os.environ["OIDC_REGISTRY_RENTAR_CLIENT_SECRET"],
                "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
                "client_kwargs": {
                    "scope": "openid profile email"
                }
            },
            {
                "name": "linkedin",
                "client_id": "",
                "client_secret": "",
                "server_metadata_url": "https://www.linkedin.com/oauth/.well-known/openid-configuration",
                "client_kwargs": {
                    "scope": "openid profile email"
                }
            }
        ]
    }
]
