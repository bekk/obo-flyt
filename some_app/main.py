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
secrets = v1.read_namespaced_secret("some-app", "obo")

# id registered in tokendings
CLIENT_ID = b64decode(secrets.data["TOKEN_X_CLIENT_ID"])
# jwk_key = key registered in tokendings
JWK_KEY = json.loads(b64decode(secrets.data["TOKEN_X_PRIVATE_JWK"]))


def create_client_assertion():
    key_string = json.dumps(JWK_KEY)
    client_jwks = jwk.JWK.from_json(key_string)
    claims = {
        "sub": CLIENT_ID,  # who am i
        "iss": CLIENT_ID,  # who am i
        "aud": "http://tokendings:7456/token",  # always tokendings when exchanging
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
    client_assertion_token = create_client_assertion()

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion_token,  # assertion with key registered in tokendings
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": token,  # original token from IDP
        "audience": aud,  # who do i want to talk to
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    res = requests.post("http://tokendings:7456/token", data=payload, headers=headers)
    if res.status_code > 200:
        return res.content
    return res.json()


@app.get("/discovery/v2.0/keys")
def jwks():
    return {"keys": [JWK_KEY]}


@app.get("/")
def read_root():
    return {"Hello": "World!"}
