from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import requests
import uuid
import os


def create_client_assertion():
    # id registered in tokendings
    CLIENT_ID = os.getenv("TOKEN_X_CLIENT_ID")
    # jwk_key = key registered in tokendings
    key_string = os.getenv("TOKEN_X_PRIVATE_JWK")
    TOKEN_ENDPOINT = os.getenv("TOKEN_X_TOKEN_ENDPOINT")

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
    token = jwt.JWT(header={"alg": "RS256", "typ": "JWT", "kid": client_jwks.kid}, claims=claims)
    token.make_signed_token(client_jwks)
    return token.serialize()


def exchange_token(
    token: str,
    aud: str,
) -> dict:
    client_assertion_token = create_client_assertion()

    TOKEN_ENDPOINT = os.getenv("TOKEN_X_TOKEN_ENDPOINT") or ""

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion_token,  # assertion with key registered in tokendings
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": token,
        "audience": aud,  # who do i want to talk to
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    res = requests.post(TOKEN_ENDPOINT, data=payload, headers=headers)
    if res.status_code > 200:
        raise Exception(res.content)
    new_token = res.json()
    print("Exchanged token: ", new_token)

    return new_token
