from fastapi import FastAPI, HTTPException
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
from base64 import b64decode
import requests
import uuid
import os

app = FastAPI()


def read_secret(secrets, name):
    return b64decode(secrets.data[name]).decode()


def create_client_assertion(client_id: str):
    # id registered in tokendings
    # jwk_key = key registered in tokendings
    key_string = os.getenv("TOKEN_X_PRIVATE_JWK")
    TOKEN_ENDPOINT = os.getenv("TOKEN_X_TOKEN_ENDPOINT")

    client_jwks = jwk.JWK.from_json(key_string)
    claims = {
        "sub": client_id,  # who am i
        "iss": client_id,  # who am i
        "aud": TOKEN_ENDPOINT,  # always tokendings when exchanging
        "jti": str(uuid.uuid4()),
        "nbf": int(datetime.utcnow().timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(seconds=119)).timestamp()),
    }
    token = jwt.JWT(header={"alg": "RS256", "typ": "JWT"}, claims=claims)
    token.make_signed_token(client_jwks)
    return token.serialize()


def get_sub_token(client_id: str):
    res = requests.get(f"http://fake-auth:6348/fake_auth/{client_id}")
    if res.status_code != 200:
        return None
    return res.text.replace('"', '')


@app.get("/v2/test/token/{aud}/")
def request_token_v2(aud: str):
    CLIENT_ID = os.getenv("TOKEN_X_CLIENT_ID")
    if CLIENT_ID == None:
        raise HTTPException(status_code=500, detail="missing client id env")

    token = get_sub_token(CLIENT_ID)
    if token == None:
        raise HTTPException(
            status_code=424, detail="could not get token for client")
    print("Token from fake auth (IDP): ", token)
    client_assertion_token = create_client_assertion(CLIENT_ID)

    TOKEN_ENDPOINT = os.getenv("TOKEN_X_TOKEN_ENDPOINT") or ""

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        # assertion with key registered in tokendings
        "client_assertion": client_assertion_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": token,  # original token from IDP
        "audience": aud,  # who do i want to talk to
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    res = requests.post(TOKEN_ENDPOINT, data=payload, headers=headers)
    if res.status_code > 200:
        return res.content
    return res.json()


@app.get("/test/token/{aud}/{token}")
def request_token(aud: str, token: str):
    CLIENT_ID = os.getenv("TOKEN_X_CLIENT_ID")
    if CLIENT_ID == None:
        raise HTTPException(status_code=500, detail="missing client id env")
    client_assertion_token = create_client_assertion(CLIENT_ID)

    TOKEN_ENDPOINT = os.getenv("TOKEN_X_TOKEN_ENDPOINT") or ""

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        # assertion with key registered in tokendings
        "client_assertion": client_assertion_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": token,  # original token from IDP
        "audience": aud,  # who do i want to talk to
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    res = requests.post(TOKEN_ENDPOINT, data=payload, headers=headers)
    if res.status_code > 200:
        return res.content
    return res.json()


@app.get("/")
def read_root():
    return {"Hello": "World!"}
