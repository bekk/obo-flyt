import os
import requests
from fastapi import FastAPI, HTTPException, Request, Response
from starlette.responses import JSONResponse

app = FastAPI(title="Exchange sidecar")


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
@app.get("/exchange")
def token_exchange(request: Request):
    original_token_header = request.headers.get("Authorization")
    if not original_token_header:
        # No token => deny or error out
        return JSONResponse(
            status_code=401, content={"message": "Missing Authorization"}
        )

    original_token = original_token_header.split(" ")[1]

    host_header = request.headers.get("host", "unknown.default.svc.cluster.local")

    # Parse host_header if you need service/namespace logic:
    parts = host_header.split(".")
    if len(parts) >= 2:
        service_name = parts[0]
        namespace = parts[1]
    else:
        service_name = "unknown"
        namespace = "unknown"

    target_str = f"{host_header}:{namespace}:{service_name}"
    print(f"ExtAuthZ: target = {target_str}, original_token = {original_token}")

    res = texas_token_exchange(target_str, original_token)
    if res.status_code != 200:
        msg = {"error": "error exchanging token"}
        if len(res.content) > 0:
            msg = {"error": str(res.content)}
        raise HTTPException(res.status_code, msg)

    new_token = res.json()["access_token"]

    return Response(
        status_code=200,
        headers={
            # Overwrite the original Authorization
            "authorization": f"Bearer {new_token}"
        },
        content="",
    )


# checks token validity and payload using texas introspect
@app.get("/introspect")
def token_introspect(token: str):
    res = texas_token_introspect(token)
    if res.status_code != 200:
        msg = {"error": "error inspecting token"}
        if len(res.content) > 0:
            msg = {"error": str(res.content)}
        raise HTTPException(res.status_code, msg)
    return Response(status_code=200, content="")
