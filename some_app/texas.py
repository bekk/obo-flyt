import os
import requests
from utils.login import login_with_fake_auth
from fastapi import APIRouter, HTTPException
from utils.tokenx import exchange_token

router = APIRouter()

def texas_token_exchange(target: str, user_token: str) -> requests.Response:
    req_url = "http://localhost:3000/api/v1/token/exchange"
    payload = {
        "target": target,
        "identity_provider": "tokenx",
        "user_token": user_token,
    }
    return requests.post(req_url, json=payload)

def texas_token_introspect(token: str) -> requests.Response:
    req_url = "http://localhost:3000/api/v1/introspect"
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

    res = texas_token_exchange(target, token)
    if res.status_code != 200:
        raise HTTPException(res.status_code, "error from texas")
    return res.json()

# checks token validity and payload using texas introspect
@router.get("/introspect/{token}")
def token_introspect(token: str):
    res = texas_token_introspect(token)
    if res.status_code != 200:
        raise HTTPException(res.status_code, "error from texas")
    return res.json()
