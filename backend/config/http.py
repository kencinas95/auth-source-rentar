from typing import Annotated

from fastapi.params import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# security
http_security_bearer = HTTPBearer()

# type hint
Authorization = Annotated[HTTPAuthorizationCredentials, Depends(http_security_bearer)]