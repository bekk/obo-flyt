import os
from typing import Annotated
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwcrypto import jwk, jwt
from jwt.exceptions import InvalidTokenError
import time
import requests


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_ttl_hash(seconds=3600):
    """Return the same value withing `seconds` time period"""
    return round(time.time() / seconds)


def get_public_jwks(url, ttl_hash=None):
    del ttl_hash
    jwk_keys = []
    res = requests.get(url)
    if res.status_code > 200:
        raise Exception(res.content)

    jwks = res.json()
    jwk_keys.clear()
    for jwk_key in jwks["keys"]:
        key = jwk.JWK(**jwk_key)
        jwk_keys.append(key)

    return jwk_keys


async def check_valid_token(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    url = os.getenv("TOKEN_X_JWKS_URL") or ""
    jwk_keys = get_public_jwks(url, ttl_hash=get_ttl_hash())
    signing_keys = [key for key in jwk_keys if key.use == "sig"]

    for key in signing_keys:
        try:
            jwt.JWT(jwt=token).validate(key)
        except InvalidTokenError:
            continue
        else:
            return token

    raise credentials_exception
