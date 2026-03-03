import urllib.parse as up
from datetime import timedelta
from pathlib import Path


# --- application settings ---
APPLICATION_ROOT = Path(__file__).parent.parent.parent
APPLICATION_NAME = "rentar-auth-service"
APPLICATION_HOST = "0.0.0.0"
APPLICATION_PORT = 8989

# --- server settings ---
SERVER_BASE_URL = f"http://localhost:{APPLICATION_PORT}"

# --- mongo settings ---
MDB_USERNAME = "ra_auth_app"
MDB_PASSWORD = "billgates21!"
MDB_DATABASE_NAME = "ra_auth"
MDB_HOSTNAME = "localhost"
MDB_PORT = 27017
MDB_CONNECTION_URL = (f"mongodb://{MDB_USERNAME}:{up.quote(MDB_PASSWORD, safe='')}"
                      f"@{MDB_HOSTNAME}:{MDB_PORT}/{MDB_DATABASE_NAME}"
                      "?authSource=admin")

MDB_MAX_BATCH_SIZE = 3000

# --- activation token settings ---
AT_UNSENT_EXPIRATION_LIMIT = timedelta(hours=12)

AT_SENT_EXPIRATION_LIMIT = timedelta(days=7)

# --- auth session settings ---
AUTH_SESSION_IDLE_LIMIT = timedelta(minutes=30)

AUTH_SESSION_EXPIRATION_LIMIT = timedelta(hours=8)

AUTH_SESSION_STORAGE_AUDIT_TIME_LIMIT = timedelta(days=90)

# --- smtp settings ---
EMAIL_SERVICE_SERVER_ADDRESS = ("localhost", 9025)

EMAIL_SERVICE_USE_TLS = False  # only in dev / testing

EMAIL_SERVICE_USE_AUTH = False  # only in dev / testing

EMAIL_SERVICE_ACCOUNT = "noreply@rentar.net"

EMAIL_SERVICE_ACCOUNT_PASSWORD = "ra_smtp_F321MMnOrYMa031$/=="

# --- data ---
DATA_ROOT = APPLICATION_ROOT / "data"

# --- external links ---
MAIN_APPLICATION_URL = "http://127.0.0.1:8080"

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
        "return_to": "http://127.0.0.1:8080/auth/callback",
        "providers": [
            {
                "name": "google",
                "client_id": "",
                "client_secret": "",
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