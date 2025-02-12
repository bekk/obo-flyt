from typing import Annotated
from fastapi import Depends, FastAPI
from utils.auth import check_valid_token
from utils.tokenx import exchange_token
from jwcrypto import jwt
import requests
import json

app = FastAPI()


@app.get("/")
def read_root(token: Annotated[jwt.JWT, Depends(check_valid_token)]):
    claims = json.loads(token.claims)
    you_are = claims["client_id"] if "client_id" in claims else claims["sub"]
    i_am = claims["aud"]

    return {"Hello": you_are, "i am": i_am}


# endpoint to exchange token and ping another service
@app.get("/ping/{serivce}")
def ping(service: str, valid_token: Annotated[jwt.JWT, Depends(check_valid_token)]):
    audience = f"kind-skiperator:obo:{service}"
    exchanged_token = exchange_token(valid_token, audience)

    res = requests.get(
        f"http://{service}:6439", headers={"Authorization": f"Bearer {exchanged_token}"}
    )

    if res.status_code != 200:
        return {"error": res.content}

    return res.json()
