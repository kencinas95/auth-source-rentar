import logging
import urllib.parse

from authlib.integrations.base_client import BaseApp
from authlib.integrations.starlette_client import OAuth

from backend.config import settings

__initialized__ = False
__clients__: dict[tuple[str, str], BaseApp] = {}

log = logging.getLogger("backend.config.oauth2")


class OIDCConfigurationNotFound(BaseException):
    """
    Raised when a OIDC configuration registry is not found.
    """

    def __init__(self, app: str, provider: str | None = None):
        key = [app.lower()]
        err_message = f"OIDC configuration not found for app={app}"
        if provider:
            err_message += f" and provider={provider}"
            key.append(provider)

        super().__init__(err_message)
        self.key = tuple(key)


class OAuthClientNotFoundError(BaseException):
    """
    Raised when a OAuth client is not found.
    """

    def __init__(self, key: tuple[str, str]):
        super().__init__(f"OAuth client not found: {key}")
        self.key = key


class OAuthUntrustyUserError(BaseException):
    """
    Raised when a OAuth untrusty user is not found.
    """

    def __init__(self, email: str | None):
        super().__init__(f"OAuth untrusty user")
        self.email = email


def init() -> None:
    """
    Initializes the OAuth client registry.
    """
    global __clients__, __initialized__

    if __initialized__:
        log.info("OAuth2 clients registry already initialized")
        return

    oauth = OAuth()

    log.debug("Initializing OAuth client registry")

    for app in settings.OIDC_REGISTRY:
        for provider in app.get('providers', []):
            key = (app["name"].lower(), provider["name"].lower())
            provider_name = ":".join(key)
            log.debug(f"Registering OAuth client for app={app}, provider={provider}")
            __clients__[key] = oauth.register(name=provider_name, client_id=provider["client_id"],
                                              client_secret=provider["client_secret"],
                                              server_metadata_url=provider["server_metadata_url"],
                                              client_kwargs=provider["client_kwargs"])

    # from backend.routers.oidc import router as oidc_router
    # oidc_app = FastAPI()
    # oidc_app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(32))
    # oidc_app.include_router(oidc_router)
    # fastapi.mount("/api/v1/oidc", oidc_app)

    __initialized__ = True
    log.debug(f"OAuth client registry initialized")


def client(app: str, provider: str) -> BaseApp:
    """
    Retrieves the client for the given app and provider.

    :param app: app name
    :param provider: provider name
    :return: OIDC client
    """
    global __clients__

    key = (app.lower(), provider.lower())

    _client = __clients__.get(key)

    if not _client:
        log.error(f"OAuth client not found in registry for: ({app}, {provider})")
        raise OAuthClientNotFoundError(key)

    log.debug(f"OAuth client found for app={app}, provider={provider}")
    return _client


def redirect(app: str, provider: str) -> str:
    """
    Creates the redirect URL for the given app and provider.

    :param app: app name
    :param provider: provider name
    :return: redirect URL
    """
    app = urllib.parse.quote(app.lower(), safe='')  # just in case

    provider = urllib.parse.quote(provider.lower(), safe='')  # just in case

    return f"{settings.SERVER_BASE_URL}/api/v1/oidc/callback/{app}/{provider}"


def return_to(app_name: str) -> str:
    """
    Gets the app's return_to URL.

    :param app_name: app name
    :return: return_to URL
    """
    app = next((app for app in settings.OIDC_REGISTRY if app["name"] == app_name), None)
    if not app:
        log.error(f"OAuth app settings not found for: {app_name}")
        raise SystemExit(f"OAuth app not found: {app_name}")  # misconfiguration

    url = app.get("return_to")
    if not url:
        log.error(f"OAuth return_to not found in settings for app: {app_name}")
        raise SystemExit(f"OAuth return_to not found in settings for app: {app_name}")  # misconfiguration

    return url
