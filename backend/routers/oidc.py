import logging
import urllib.parse
from typing import Annotated

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi.params import Form
from starlette.responses import RedirectResponse

from backend.config import oauth2
from backend.config.oauth2 import OAuthClientNotFoundError
from backend.services import oidc

router = APIRouter(prefix="/oidc", tags=["OIDC authentication"])

log = logging.getLogger("backend.routers.oidc")


@router.get("/authorization/{app}/{provider}")
async def authorize(request: Request, app: str, provider: str):
    log.debug(f"OIDC authorization in action request for: ({app}, {provider})")

    try:
        client = oauth2.client(app, provider)

        redirect = oauth2.redirect(app, provider)

        log.info(f"OIDC authorization redirect to: {redirect}")

        return await client.authorize_redirect(request, redirect)

    except OAuthClientNotFoundError:
        raise HTTPException(status_code=404)


@router.get("/callback/{app}/{provider}")
async def callback(request: Request, app: str, provider: str):
    client = oauth2.client(app, provider)

    log.debug(f"Starting OIDC authorization exchange")

    token = await client.authorize_access_token(request)

    userinfo = token.get("userinfo") or await client.parse_id_token(request, token)

    oidc_ticket_id = oidc.process(userinfo)

    return_to = f"{oauth2.return_to(app)}?{urllib.parse.urlencode({'ticket': oidc_ticket_id})}"

    return RedirectResponse(url=return_to, status_code=303)


@router.post("/exchange")
async def exchange(ticket_id: Annotated[str, Form()]):
    log.debug(f"Starting OIDC exchange request for ticket: {ticket_id}")

    status, payload = oidc.exchange(ticket_id)

    if status != 200:
        raise HTTPException(status_code=status)

    return payload
