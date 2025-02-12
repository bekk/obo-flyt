import os
from typing import Annotated
from fastapi import Depends, FastAPI
from utils.auth import check_valid_token
from utils.login import login_with_fake_auth
from utils.tokenx import exchange_token
from jwcrypto import jwt
import requests
import json

app = FastAPI()


client_id = os.getenv("TOKEN_X_CLIENT_ID") or ""


@app.get("/")
def read_root(token: Annotated[jwt.JWT, Depends(check_valid_token)]):
    claims = json.loads(token.claims)
    you_are = claims["client_id"] if "client_id" in claims else claims["sub"]

    return {"Hello": you_are, "i am": client_id}


# endpoint to exchange token and ping another service
@app.get("/ping/{service}")
def ping(service: str, valid_token: Annotated[jwt.JWT, Depends(check_valid_token)]):
    return exchange_and_ping(service, valid_token)


# endpoint to login with fakeauth and ping another service
@app.get("/login-and-ping/{service}")
def login_and_ping(service: str):
    token = login_with_fake_auth(client_id)

    return exchange_and_ping(service, token)


def exchange_and_ping(service: str, token: jwt.JWT) -> dict:
    audience = f"kind-skiperator:obo:{service}"
    exchanged_token = exchange_token(token, audience)

    res = requests.get(
        f"http://{service}:6349",
        headers={"Authorization": f"Bearer {exchanged_token['access_token']}"},
    )

    if res.status_code != 200:
        return {"error": res.content}

    return res.json()
