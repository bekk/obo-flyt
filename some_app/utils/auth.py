import os
from typing import Annotated
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwcrypto import jwk, jwt, jws
import time
import requests
import json


security = HTTPBearer()

client_id = os.getenv("TOKEN_X_CLIENT_ID") or ""


def get_ttl_hash(seconds=3600):
    """Return the same value withing `seconds` time period"""
    return round(time.time() / seconds)


@lru_cache
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


async def check_valid_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    tokendings_jwk_url = os.getenv("TOKEN_X_JWKS_URI") or ""
    tokendings_jwks = get_public_jwks(tokendings_jwk_url, ttl_hash=get_ttl_hash())
    signing_keys = [key for key in tokendings_jwks if key.use == "sig"]

    fakeauth_jwk_url = os.getenv("FAKEAUTH_JWKS_URI") or ""
    fakeauth_jwks = get_public_jwks(fakeauth_jwk_url, ttl_hash=get_ttl_hash())

    signing_keys.extend(fakeauth_jwks)

    token = None

    for key in signing_keys:
        try:
            token = jwt.JWT(jwt=credentials.credentials, key=key)
        except jws.InvalidJWSSignature:
            continue

    if token is None:
        raise credentials_exception

    claims = json.loads(token.claims)

    if claims["aud"] != client_id:
        raise credentials_exception

    return token
