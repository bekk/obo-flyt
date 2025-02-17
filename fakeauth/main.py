from fastapi import FastAPI, Request
from jwks import generate_jwk, get_or_create_jwk
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
from base64 import b64decode
import requests
import json
import uuid

app = FastAPI()
key = get_or_create_jwk()


@app.post("/test_hostname")
def test_name(hostname: str):
    res = requests.get(f"http://{hostname}/health")
    return res.content


@app.get("/health")
def health():
    return "ok man!"


# read by tokendings at starup
@app.get("/.well-known/openid-configuration")
def read_root():
    config = {
        "token_endpoint": "http://fake-auth:6348/oauth2/v2.0/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "private_key_jwt",
            "client_secret_basic",
        ],
        "jwks_uri": "http://fake-auth:6348/discovery/v2.0/keys",
        "response_modes_supported": ["query", "fragment", "form_post"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": [
            "code",
            "id_token",
            "code id_token",
            "id_token token",
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "issuer": "http://fake-auth:6348",
        "request_uri_parameter_supported": "false",
        "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
        "authorization_endpoint": "https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/oauth2/v2.0/authorize",
        "device_authorization_endpoint": "https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/oauth2/v2.0/devicecode",
        "http_logout_supported": "true",
        "frontchannel_logout_supported": "true",
        "end_session_endpoint": "https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/oauth2/v2.0/logout",
        "claims_supported": [
            "sub",
            "iss",
            "cloud_instance_name",
            "cloud_instance_host_name",
            "cloud_graph_host_name",
            "msgraph_host",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "acr",
            "nonce",
            "preferred_username",
            "name",
            "tid",
            "ver",
            "at_hash",
            "c_hash",
            "email",
        ],
        "kerberos_endpoint": "https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/kerberos",
        "tenant_region_scope": "EU",
        "cloud_instance_name": "microsoftonline.com",
        "cloud_graph_host_name": "graph.windows.net",
        "msgraph_host": "graph.microsoft.com",
        "rbac_url": "https://pas.windows.net",
    }

    return config


@app.post("/override_key")
def override_key():
    global key
    key = generate_jwk()


@app.get("/discovery/v2.0/keys")
def jwks():
    return {"keys": [key.export_public(as_dict=True)]}


# used to "login" a user to be used as the subject token
@app.get("/fake_auth/{aud}")
def generate_sub_token(aud):
    claims = {
        "iss": "http://fake-auth:6348",
        "sub": "test@test.com",
        "aud": aud,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(days=1)).timestamp()),
    }
    token = jwt.JWT(header={"alg": "RS256", "type": "JWT", "kid": str(key.kid)}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()
