import os
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException
from utils.auth import check_valid_token
from utils.login import login_with_fake_auth
from utils.tokenx import exchange_token
from jwcrypto import jwt
import requests
import json

app = FastAPI()


client_id = os.getenv("TOKEN_X_CLIENT_ID") or ""
NAMESPACE = os.getenv("POD_NAMESPACE") or ""
CLUSTER_NAME = os.getenv("CLUSTER_NAME") or ""


@app.get("/v2/test/token/{aud}/")
def request_token_v2(aud: str):
    CLIENT_ID = os.getenv("TOKEN_X_CLIENT_ID")
    if CLIENT_ID is None:
        raise HTTPException(status_code=500, detail="missing client id env")

    token = login_with_fake_auth(CLIENT_ID)
    if token is None:
        raise HTTPException(status_code=424, detail="could not get token for client")
    print("Token from fake auth (IDP): ", token)
    return exchange_token(token, aud)


@app.get("/test/token/{aud}/{token}")
def request_token(aud: str, token: str):
    CLIENT_ID = os.getenv("TOKEN_X_CLIENT_ID")
    if CLIENT_ID is None:
        raise HTTPException(status_code=500, detail="missing client id env")

    return exchange_token(token, aud)


@app.get("/")
def read_root(token: Annotated[jwt.JWT, Depends(check_valid_token)]):
    claims = json.loads(token.claims)
    you_are = claims["client_id"] if "client_id" in claims else claims["sub"]

    return {"Hello": you_are, "i am": client_id}


# endpoint to exchange token and ping another service
@app.get("/ping/{service}")
def ping(service: str, valid_token: Annotated[jwt.JWT, Depends(check_valid_token)]):
    return exchange_and_ping(service, valid_token.serialize())


# endpoint to login with fakeauth and ping another service
@app.get("/login-and-ping/{service}")
def login_and_ping(service: str):
    token = login_with_fake_auth(client_id)

    return exchange_and_ping(service, token)


def exchange_and_ping(service: str, token: str) -> dict:
    audience = f"{CLUSTER_NAME}:{NAMESPACE}:{service}"
    exchanged_token = exchange_token(token, audience)

    res = requests.get(
        f"http://{service}:6349",
        headers={"Authorization": f"Bearer {exchanged_token['access_token']}"},
    )

    if res.status_code != 200:
        return {"error": res.content}

    return res.json()
