from fastapi import FastAPI, Request
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import requests
import json
import uuid

app = FastAPI()

# id registered in tokendings
CLIENT_ID="some_app"
# jwk_key = key registered in tokendings
JWK_KEY = {"d": "LhkOOF2xralEJlZemrlHuCNXh87kwV42tUb-oCpqjfL9xd0DaTyfH5WDp-JJn9_31BE4Z1A467eeJrFW8oShB3nJDpRpPJB6CIoG0iClMfYj03dBecWGefinTl9FhqSJG9n4u6N92Hmn_WZiaunxd-ICqIs5DxakCIzTOTVTEGkasNaqdHSKtWDMOvSAvE0wApOdbHw7c1wBEodmkSt4vWM503J6b4gW-qItwfgx44tNN5wraFQRxDw7kmvmgxS6iu5XDL0C4DTUnViOQc56QIXpo9pWWXOgofn2KIVVTa3yQs5c68Lwg-6ZnZDdZXKSqNoULCIeYTeAs-WkRLA8eQ", "e": "AQAB", "n": "tNW0ZqJ5dWJGCX49oc4ww_Di1ZGDAt9mkxWkjXNjbmvD2oAbjiXWxJfngQeVz72NpGXI-1_QIPvx6EGb85Th9cqyuN5PCaBYZpszX71sxFfz8yUayxiXFK5OwzaeXaRgsknp4eSb9fiLbaMHwCM_50ptIFKl8Q4bZq_8StEvABvX4UNlNja7QNPaRhAm7nfILFpNvL-l6CoBPJz6pCbrK2cWHk43fWFvU1l0jj0_zKKe6EHOFcsntxPO20XneKqpGiIDU2t1lwEOSl40dpl1QMnmpQxxI2bNc72-Da4AAPpFnaD0PKhLLQf7C8pZtJKZIzo1bxHRykKSx0NOAnpeRw", "p": "5hjzqZ5A2fF60AC99GAp814ZL2xM9URick5grG_whP9qbf9DBnXceZsgPCv7OuR0Q8UKpchGMmrGH0Fd7CkSNAVkV7RbmtvfT0BTrCXZjLxYAsjOTCG2MFv6_L17aDJJiY5LaTgQTz20oC_1s-lwBxx_ma-6j78KMOjF0dm_yKk", "q": "yTEUX4lberDGFGFd8J9UWLpugZm8wauYWw965HDgjSBB5ljK-RlRLKClZbVF4_c30mSh-ADpFlx6MB-oHWfdNCsy-JzJFOchNnGlxaRGFiZ-puZdO4r47lfrFY3GVgYgY6nC4SgJ7qLaPvHT4c1-zNih7_gYHDKWegsTb-FIlW8", "dp": "pfkvoZUWgF7wUKOIYYMQH40rq4p6RJzMSlmA4EFqg_TdJ3TuOvW_UDR2XxD2ijeKKewyzvyUrf9Y4-i5wASsLbwJ8j2VqjGZdcgX0uAGeb7N2UxRipbynRVsCO0A3FsRslhiywX2tcHzzWxq1hi3h1mmLQyWDOQnjLoLH2DrNuk", "dq": "H8nscSfv11PlCEVWJXXXSumyGjIjW-pz-TdZ8IxRPpsxLmcrMu6oH8gGOirJLzrZjBmwadIjAhB8kev-kR7fGaYVuKh1MSNP4R1V1wOcu1U7v704T_cmW-pyT4aGJwNyzKx_CTpdT2JV34owM0ZX2aAE_jiR_qqTkhb77DqJUGs", "qi": "wgE_Tr0d19s8EpjlZYmPkbpO-LpdS4WemucFfCbKUSYFeuf5sDJK1KOZ4NNJWjHhmBoCUDri_GKwDSJdmgerJ0_zyv4ZAMOUjU1ScGhioBdcMMFXCDEqMfVQVfNuP3IDlBMzVGPzBicjwVQ6rlFLaOzVexFgF8rmbGeQcwxeAMk", "kid": "12345", "kty": "RSA"}

def create_client_assertion():
    key_string = json.dumps(JWK_KEY)
    client_jwks = jwk.JWK.from_json(key_string)
    claims = {
        "sub": "some_app", # who am i
        "iss": "some_app", # who am i
        "aud": "http://tokendings:8080/token", # always tokendings when exchanging
        "jti":  str(uuid.uuid4()),
        "nbf": int(datetime.utcnow().timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(seconds=119)).timestamp()),
    }
    token = jwt.JWT(header={"alg": "RS256", "typ": "JWT"}, claims=claims)
    token.make_signed_token(client_jwks)
    return token.serialize()

@app.get("/test/token")
def request_token():
    client_assertion_token = create_client_assertion()

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion_token, # assertion with key registered in tokendings
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": "eyJhbGciOiJSUzI1NiIsInR5cGUiOiJKV1QifQ.eyJhdWQiOiJzb21lX2FwcCIsImV4cCI6MTczNjk0MDI5MiwiaWF0IjoxNzM2ODUzODkyLCJpc3MiOiJodHRwOi8vZmFrZV9hdXRoOjMwMDAiLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIn0.n9BF0213exN7Sa0od21D9oKGTwHgSISbvKVwn87Lxz6xvTs2ZWIPbBNeNAkK3UPO4VrKJXTcdffIzSLPqHSsKiAylBfomF2sCiAwGWRhNSWXYDCax4mUnL0U1TSxVaVjMSRqntbklejdSISYFqHbsW9D1NYOze7V41nhv3XHlkNggLO4wUspGxEQ0VowPK1D2-G4eyAG1X7QuxtpmlM2kGPnDOgTwci_m1YPbdTOBRxsHnzunkJWItVu56wPT5dfR-neiPcZ0VCpU6ClhF9COXU2ad0cVQU7fKvrMHlDJbNPY9oxmF2d-MqkftTtfI8XjHW7X-n1c80xVDMMpWzmWA", # original token from IDP
        "audience": "test_app" # who do i want to talk to
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    res = requests.post("http://tokendings:8080/token", data=payload, headers=headers)
    if res.status_code > 200:
        return res.content
    return res.json()


@app.get("/discovery/v2.0/keys")
def jwks():
    return {"keys": [JWK_KEY]}

@app.get("/")
def read_root():
    return {"Hello": "World!"}
