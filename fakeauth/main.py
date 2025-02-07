from fastapi import FastAPI, Request
from jwks import generate_jwk, get_or_create_jwk, create_signed_jwt
from auth import get_token
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
from kubernetes import client, config
from base64 import b64decode
import requests
import json

app = FastAPI()

config.load_incluster_config()

v1 = client.CoreV1Api()
some_app_secrets = v1.read_namespaced_secret("some-app", "obo")


def read_secret(secrets, name):
    return b64decode(secrets.data[name]).decode()


# id registered in tokendings
SOME_APP_CLIENT_ID = read_secret(some_app_secrets, "TOKEN_X_CLIENT_ID")
# jwk_key = key registered in tokendings
SOME_APP_JWK_KEY = json.loads(read_secret(some_app_secrets, "TOKEN_X_PRIVATE_JWK"))


@app.post("/test_hostname")
def test_name(hostname: str):
    res = requests.get(f"http://{hostname}/health")
    return res.content


@app.get("/health")
def health():
    return "ok"


# shared key with tokendings
AUTH_CLIENT_JWKS = {
    "keys": [
        {
            "p": "-UTsojJQES7Rxg-wyiRBMwI7qyBfjiBXkhOfhwLZPvaNFnL5O4PDZOl_5RpYSKYm3zhe1sI37P8kKLXpWKGTtahPU8pJp6wi3wKa14BjHfBoUD8vC8vPR6LPzCkaksuSLxnabmCqi5BIgM4Ktt8L365wxj3XvZk78jdqkfZ5TrU",
            "kty": "RSA",
            "q": "97x12F8J4rdh4Fxlnu_h8-RusL4JRFfXg3NC5Xg-sCUYA8qgObHAyQpeNj6WCN10G_OxdUaRvK-0RY0eeiAK2QgIgmQBhaRUcIk1_TE7NS30L8DbsLvJUkR38YrrSlGipMgIp2p1cPH2o0qqUREu3kBHpyibMtYJhP4GTtYo73k",
            "d": "owLjH1SbTKdgzK85s49oWGJXQ_0JZ0Gl_eYGodAXDJFRwRnCWcqmaQ4mtve8LuQKNhyfNzGL0q5B1EwzIQUTDA53OuU_nMLQREqajA7rl_EpAJaSt41AwE183Dq61BAgQvKCNBK2av_ih_eX5fZ0uwFarL4VNmP6ac-9SbOFKYWhYPksXkw9PO8PfjtVcR8mLC48LHfc-4WDZFb_7PZEGUE7LWIqfEq_LkMOx-zyB_aAENCgyjjJ00ArFpHwK6kJtuYW_vWCTUirn3V5EddFNuR9ueSo-OptOiR3U4v6zJDGdtvISP0wjLFOfyXfhy9gFOYaA9vX7O3AtXgpgG_gAQ",
            "e": "AQAB",
            "qi": "eDUmJ_GRtjbLzaF-bHQzIxxV7wJ8ta2Sc60yATDh1lfMOv1dKeVm5oXJIn-wz9yUVZqALyaXOXU4ajG3prAUuueoB7cVMx03AC91p3zMdTcCmhGfX3tT2VovpdrAjB7d6EtMYV5tHSsNBpkCMZQ4Gbp0oqaJFZEvCvKL_BuPKJk",
            "dp": "baDBjcgg7J2xxrDp6M0vG5b01RtEy0YwHV-h_ofjMczPWjswn9sgWUZUaFdA0pq4Z93r3_nFDOddaMYwnTlatD8UvF4wLJ0JLRmBLhwZ-3Xa-sf_EeoN_Ix_ZWQCeuMrJKnzJi4_c2f-ax-zGKBaIYMfuCBEvO8irTFwHkfPLC0",
            "dq": "VznI-GUGEwhkct21fg-SLBB7FMnkc2bGX-ceX7NFxzlYSkV2wrmeWmrHHyxMIVTvw8O68MLnH1tyCqcUWwWbLC1S6a4Shx6ECJeXJc3GvgOvHX03HPQRf2DSJn62N5WkwYYY3fFy5lCbeYUZkK-PI_vX_rgiZPTNp0DVsb5f7Wk",
            "n": "8TkBrXSAMTfBCnN1eQYUk6swUGUSVkKqim2HcbQe3vBEi7hATEiChL49z1f40w2l4qEMUpgQTUigkdacAc39I7VKaZkf0573KZa-pra0BDxOWGnqQUtseK73XM6Pn4Im9EU1fqQhSBUqOAMky40aLo4u4RFmCZRCTKMAJaVzOE0aSslmW0wN2SPQfMwqcglkAcoJhqn8kejJ7kA6j8DpR1Q0CTy9hhn63DRJSKD3Lx93g9YiBCBYXYQTBH4-ZUePPk6rHJvU6g40xbfRCWOjG6SSrEOKBL-qZGxIA_MUYJpNRH1YmHl5mzp9KahCplPBSWRaCSo4n8Q_68f-WhkujQ",
        }
    ]
}

# map the keys registered at tokendings so we can sign the fake login
keys = {
    "test_app": {
        "d": "Sx0CvZ4BfarypKZ3dBJcrGB_MRzpzbghyz2W9wp0ix1Z02DxLUNlGM6fQY8dE7eSjNayBc0F0f_mqg2dz6ZrRdoQsjp6OGlw4vK5akz3l5hnVZzDbbKwRajyrGJXSDV0A6pfXGG8h1CsNMAjMxOVQCp5eu-SinWdR_FvPBkBHNFCVSV4zvgqdNQENHtT6ZrZGbZ9v3ICrJ4tTAUcE4oBTuiX0uSTg_Jiw7Ce4c_8lFHmNT8sImsmVAftCYG3K4NN7ttTdp21KdhnTrHwMF_GoQFcy5kAsCjWZFu2bWyc4p2fZLfASogxpvoe0NzDaydG6Ak3EMYPCIhXWu9p_fLaoQ",
        "e": "AQAB",
        "n": "vHjZOPFqrxM0Kxjs-yB_o8L-Fb2EWmMMDyqWsPdrd4ub6pT3K8m5VaucicpLjnfaU-5Oq4hrpdhPrx9aXtvzOMW8lu6MXP3Jr17o1HnoTlT3e5rmadDgBZQ_cnCnHhFZuOK2yCw7fAwSDF9ivYaGpdDLIsaHpnT3Uk74hFvops8Ph-tzQ_faMjRplsD6ITsM2uX3gI0-uOLj9CVf4kNEP0U8Bgw7mhGrC9CAPoxGAcDgx3N_7jN_dCdB94nI3s5wOWcRjgT9vKl3CJNqpF0BBt9ij0z_uLLYwdrt0ho9OoUJJYiEZqHXKHU-XBVVvO65ZRTxyuPpdWkhVIYUZpY_mw",
        "p": "-5RmlrjNSb9DjxHSCpyQL8-Quot0F3P2Y9z5M-VvNR-0WBmee-eb7KjN__wr2GrGiTL84e-gjZ2XnmKejtmBSDr37sEn7_kpe4QnI3jSjuIyXAtA65whCN3JLPuy38IQ6YwgbLDex3tIl0h7dr7KRk5RhzFk209ViJi9pQsFXss",
        "q": "v8iXW2M8bYbryTcRD1L3qNPIgbHLji05y1BC113ew3pOrOd0nZLcjWOsJ-L2XUwIUskhu_YDwpMToeHA7WveBlgumeBx3nULeRcqYA_zVFl3OmT6o6Zj5bxukFbg9PoIEum8kePh0N47bNtnkW0WEgsRt8txRstfJ-h6pxMROHE",
        "dp": "Sf_bsSfIkpGkwJeATcjBjJ6kNorAagmdBsC_uGkbLegWdveKK23z6ke42DwHdY_qt_58bcS7WAxrxZXCh8gog-N8fAjqw2ZpskAr9v4aCRc1sudIgEUbXm1GOGoMsk52BQxHmVDpJon3zy_tyP7Tppxw1LBNt0h9o0EyPzKfsMM",
        "dq": "Acv5Twvg9w26i8oOSNx4IYbKbBykUZKu5e68kZP5kE9HCWuptgg4NMLoS_9eW4Vo1o232TD23A3Qs0WQLylBjUGqPhrSNklWcC39YaUEnJex_EQR7RKUAQUA7C1EMkddZ__0mlFOPky2tdBgagZhnI2p_tTTHNyu6YrOC16sXKE",
        "qi": "ynaCsJj3LtVaNsgEnGvb0yBQGfjWX712lLX1VSSUTVaxmqQPkf83NytmDvGuJksMg5Hq3WI0rlOje7XBkIm_K_QxUVy9t0XcRC7QLmu4hevuYmJd-DGAIiWebji9HH5K99RbEE7b37xfkAzTEeRQAD4xN9_LlJY-4oTdDSGXrnA",
        "kid": "12345",
        "kty": "RSA",
    },
    SOME_APP_CLIENT_ID: SOME_APP_JWK_KEY,
}


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
    key_string = json.dumps(keys[aud])
    client_jwks = jwk.JWK.from_json(key_string)
    token = jwt.JWT(header={"alg": "RS256", "type": "JWT"}, claims=claims)
    token.make_signed_token(client_jwks)
    return token.serialize()
