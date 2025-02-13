import requests
import os

FAKE_AUTH_URL = os.getenv("FAKEAUTH_LOGIN_URL") or ""


def login_with_fake_auth(audience: str):
    req_url = f"{FAKE_AUTH_URL}/{audience}"
    response = requests.get(req_url)
    if response.status_code != 200:
        raise Exception(response.content)
    token = response.json()
    print("Token from fake auth (IDP): ", token)
    return token
