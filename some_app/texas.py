import os
import requests
from utils.login import login_with_fake_auth
from fastapi import APIRouter, HTTPException
from utils.tokenx import exchange_token

router = APIRouter()

def texas_token_exchange(texasUrl: str, target: str, user_token: str) -> requests.Response:
    req_url = f"{texasUrl}/api/v1/token/exchange"
    payload = {
        "target": target,
        "identity_provider": "tokenx",
        "user_token": user_token,
    }
    return requests.post(req_url, json=payload)

def texas_token_introspect(texasUrl: str, token: str) -> requests.Response:
    req_url = f"{texasUrl}/api/v1/introspect"
    payload = {
        "identity_provider": "tokenx",
        "token": token,
    }
    return requests.post(req_url, json=payload)


# gets token from fake-auth and perform token exchange for communicating with {target} using texas("sidecare/pod")
@router.get("/exchange/{target}")
def token_exchange(target: str):
    CLIENT_ID = os.getenv("TOKEN_X_CLIENT_ID")
    if CLIENT_ID is None:
        raise HTTPException(status_code=500, detail="missing client id env")
    try:
        token = login_with_fake_auth(CLIENT_ID)
    except:
        raise HTTPException(424, "error fetching token from idp")

    TEXAS_URL = os.getenv("TEXAS_URL")
    if TEXAS_URL is None:
        raise HTTPException(status_code=500, detail="missing texas url env")

    res = texas_token_exchange(TEXAS_URL, target, token)
    if res.status_code != 200:
        raise HTTPException(res.status_code, "error from texas")
    return res.json()

@router.get("/introspect/{token}")
def token_introspect(token: str):
    TEXAS_URL = os.getenv("TEXAS_URL")
    if TEXAS_URL is None:
        raise HTTPException(status_code=500, detail="missing texas url env")

    res = texas_token_introspect(TEXAS_URL, token)
    if res.status_code != 200:
        raise HTTPException(res.status_code, "error from texas")
    return res.json()





