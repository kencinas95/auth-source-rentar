import secrets

import uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from backend.config import settings
from backend.config.app import lifecycle
from backend.routers.auth import router as auth_router
from backend.routers.user import router as user_router
from backend.routers.oidc import router as oidc_router


# main app
app = FastAPI(lifespan=lifecycle)
app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(128))

# add routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(user_router, prefix="/api/v1")
app.include_router(oidc_router, prefix="/api/v1")

if __name__ == '__main__':
    uvicorn.run(app, host=settings.APPLICATION_HOST, port=settings.APPLICATION_PORT)
