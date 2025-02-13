import requests
import os
from jwcrypto import jwt

FAKE_AUTH_URL = os.getenv("FAKEAUTH_LOGIN_URL") or ""


def login_with_fake_auth(audience: str) -> jwt.JWT:
    req_url = f"{FAKE_AUTH_URL}/{audience}"
    response = requests.get(req_url)
    if response.status_code != 200:
        raise Exception(response.content)
    token = jwt.JWT.from_jose_token(response.json())
    return token
