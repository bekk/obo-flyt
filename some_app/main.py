from fastapi import FastAPI, Request
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
from kubernetes import client, config
from base64 import b64decode
import json
import requests
import uuid

app = FastAPI()

config.load_incluster_config()

v1 = client.CoreV1Api()


def read_secret(secrets, name):
    return b64decode(secrets.data[name]).decode()


def create_client_assertion(secrets):
    # id registered in tokendings
    CLIENT_ID = read_secret(secrets, "TOKEN_X_CLIENT_ID")
    # jwk_key = key registered in tokendings
    JWK_KEY = json.loads(read_secret(secrets, "TOKEN_X_PRIVATE_JWK"))
    TOKEN_ENDPOINT = read_secret(secrets, "TOKEN_X_TOKEN_ENDPOINT")

    key_string = json.dumps(JWK_KEY)
    client_jwks = jwk.JWK.from_json(key_string)
    claims = {
        "sub": CLIENT_ID,  # who am i
        "iss": CLIENT_ID,  # who am i
        "aud": TOKEN_ENDPOINT,  # always tokendings when exchanging
        "jti": str(uuid.uuid4()),
        "nbf": int(datetime.utcnow().timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(seconds=119)).timestamp()),
    }
    token = jwt.JWT(header={"alg": "RS256", "typ": "JWT"}, claims=claims)
    token.make_signed_token(client_jwks)
    return token.serialize()


@app.get("/test/token/{aud}/{token}")
def request_token(aud: str, token: str):
    secrets = v1.read_namespaced_secret("some-app", "obo")
    client_assertion_token = create_client_assertion(secrets)

    TOKEN_ENDPOINT = read_secret(secrets, "TOKEN_X_TOKEN_ENDPOINT")

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion_token,  # assertion with key registered in tokendings
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": token,  # original token from IDP
        "audience": aud,  # who do i want to talk to
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    res = requests.post(TOKEN_ENDPOINT, data=payload, headers=headers)
    if res.status_code > 200:
        return res.content
    return res.json()


@app.get("/discovery/v2.0/keys")
def jwks():
    secrets = v1.read_namespaced_secret("some-app", "obo")

    client_jwk = jwk.JWK.from_json(
        json.loads(read_secret(secrets, "TOKEN_X_PRIVATE_JWK"))
    )

    return {"keys": [client_jwk.export_public()]}


@app.get("/")
def read_root():
    return {"Hello": "World!"}
