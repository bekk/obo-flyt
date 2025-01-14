from fastapi import FastAPI, Request
from jwks import generate_jwk, get_or_create_jwk, create_signed_jwt
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import requests
import json

app = FastAPI()

# shared key with tokendings
AUTH_CLIENT_JWKS={"keys":[{"p":"-UTsojJQES7Rxg-wyiRBMwI7qyBfjiBXkhOfhwLZPvaNFnL5O4PDZOl_5RpYSKYm3zhe1sI37P8kKLXpWKGTtahPU8pJp6wi3wKa14BjHfBoUD8vC8vPR6LPzCkaksuSLxnabmCqi5BIgM4Ktt8L365wxj3XvZk78jdqkfZ5TrU","kty":"RSA","q":"97x12F8J4rdh4Fxlnu_h8-RusL4JRFfXg3NC5Xg-sCUYA8qgObHAyQpeNj6WCN10G_OxdUaRvK-0RY0eeiAK2QgIgmQBhaRUcIk1_TE7NS30L8DbsLvJUkR38YrrSlGipMgIp2p1cPH2o0qqUREu3kBHpyibMtYJhP4GTtYo73k","d":"owLjH1SbTKdgzK85s49oWGJXQ_0JZ0Gl_eYGodAXDJFRwRnCWcqmaQ4mtve8LuQKNhyfNzGL0q5B1EwzIQUTDA53OuU_nMLQREqajA7rl_EpAJaSt41AwE183Dq61BAgQvKCNBK2av_ih_eX5fZ0uwFarL4VNmP6ac-9SbOFKYWhYPksXkw9PO8PfjtVcR8mLC48LHfc-4WDZFb_7PZEGUE7LWIqfEq_LkMOx-zyB_aAENCgyjjJ00ArFpHwK6kJtuYW_vWCTUirn3V5EddFNuR9ueSo-OptOiR3U4v6zJDGdtvISP0wjLFOfyXfhy9gFOYaA9vX7O3AtXgpgG_gAQ","e":"AQAB","qi":"eDUmJ_GRtjbLzaF-bHQzIxxV7wJ8ta2Sc60yATDh1lfMOv1dKeVm5oXJIn-wz9yUVZqALyaXOXU4ajG3prAUuueoB7cVMx03AC91p3zMdTcCmhGfX3tT2VovpdrAjB7d6EtMYV5tHSsNBpkCMZQ4Gbp0oqaJFZEvCvKL_BuPKJk","dp":"baDBjcgg7J2xxrDp6M0vG5b01RtEy0YwHV-h_ofjMczPWjswn9sgWUZUaFdA0pq4Z93r3_nFDOddaMYwnTlatD8UvF4wLJ0JLRmBLhwZ-3Xa-sf_EeoN_Ix_ZWQCeuMrJKnzJi4_c2f-ax-zGKBaIYMfuCBEvO8irTFwHkfPLC0","dq":"VznI-GUGEwhkct21fg-SLBB7FMnkc2bGX-ceX7NFxzlYSkV2wrmeWmrHHyxMIVTvw8O68MLnH1tyCqcUWwWbLC1S6a4Shx6ECJeXJc3GvgOvHX03HPQRf2DSJn62N5WkwYYY3fFy5lCbeYUZkK-PI_vX_rgiZPTNp0DVsb5f7Wk","n":"8TkBrXSAMTfBCnN1eQYUk6swUGUSVkKqim2HcbQe3vBEi7hATEiChL49z1f40w2l4qEMUpgQTUigkdacAc39I7VKaZkf0573KZa-pra0BDxOWGnqQUtseK73XM6Pn4Im9EU1fqQhSBUqOAMky40aLo4u4RFmCZRCTKMAJaVzOE0aSslmW0wN2SPQfMwqcglkAcoJhqn8kejJ7kA6j8DpR1Q0CTy9hhn63DRJSKD3Lx93g9YiBCBYXYQTBH4-ZUePPk6rHJvU6g40xbfRCWOjG6SSrEOKBL-qZGxIA_MUYJpNRH1YmHl5mzp9KahCplPBSWRaCSo4n8Q_68f-WhkujQ"}]}

# map the keys registered at tokendings so we can sign the fake login
keys = {
  "test_app": {"d": "Sx0CvZ4BfarypKZ3dBJcrGB_MRzpzbghyz2W9wp0ix1Z02DxLUNlGM6fQY8dE7eSjNayBc0F0f_mqg2dz6ZrRdoQsjp6OGlw4vK5akz3l5hnVZzDbbKwRajyrGJXSDV0A6pfXGG8h1CsNMAjMxOVQCp5eu-SinWdR_FvPBkBHNFCVSV4zvgqdNQENHtT6ZrZGbZ9v3ICrJ4tTAUcE4oBTuiX0uSTg_Jiw7Ce4c_8lFHmNT8sImsmVAftCYG3K4NN7ttTdp21KdhnTrHwMF_GoQFcy5kAsCjWZFu2bWyc4p2fZLfASogxpvoe0NzDaydG6Ak3EMYPCIhXWu9p_fLaoQ", "e": "AQAB", "n": "vHjZOPFqrxM0Kxjs-yB_o8L-Fb2EWmMMDyqWsPdrd4ub6pT3K8m5VaucicpLjnfaU-5Oq4hrpdhPrx9aXtvzOMW8lu6MXP3Jr17o1HnoTlT3e5rmadDgBZQ_cnCnHhFZuOK2yCw7fAwSDF9ivYaGpdDLIsaHpnT3Uk74hFvops8Ph-tzQ_faMjRplsD6ITsM2uX3gI0-uOLj9CVf4kNEP0U8Bgw7mhGrC9CAPoxGAcDgx3N_7jN_dCdB94nI3s5wOWcRjgT9vKl3CJNqpF0BBt9ij0z_uLLYwdrt0ho9OoUJJYiEZqHXKHU-XBVVvO65ZRTxyuPpdWkhVIYUZpY_mw", "p": "-5RmlrjNSb9DjxHSCpyQL8-Quot0F3P2Y9z5M-VvNR-0WBmee-eb7KjN__wr2GrGiTL84e-gjZ2XnmKejtmBSDr37sEn7_kpe4QnI3jSjuIyXAtA65whCN3JLPuy38IQ6YwgbLDex3tIl0h7dr7KRk5RhzFk209ViJi9pQsFXss", "q": "v8iXW2M8bYbryTcRD1L3qNPIgbHLji05y1BC113ew3pOrOd0nZLcjWOsJ-L2XUwIUskhu_YDwpMToeHA7WveBlgumeBx3nULeRcqYA_zVFl3OmT6o6Zj5bxukFbg9PoIEum8kePh0N47bNtnkW0WEgsRt8txRstfJ-h6pxMROHE", "dp": "Sf_bsSfIkpGkwJeATcjBjJ6kNorAagmdBsC_uGkbLegWdveKK23z6ke42DwHdY_qt_58bcS7WAxrxZXCh8gog-N8fAjqw2ZpskAr9v4aCRc1sudIgEUbXm1GOGoMsk52BQxHmVDpJon3zy_tyP7Tppxw1LBNt0h9o0EyPzKfsMM", "dq": "Acv5Twvg9w26i8oOSNx4IYbKbBykUZKu5e68kZP5kE9HCWuptgg4NMLoS_9eW4Vo1o232TD23A3Qs0WQLylBjUGqPhrSNklWcC39YaUEnJex_EQR7RKUAQUA7C1EMkddZ__0mlFOPky2tdBgagZhnI2p_tTTHNyu6YrOC16sXKE", "qi": "ynaCsJj3LtVaNsgEnGvb0yBQGfjWX712lLX1VSSUTVaxmqQPkf83NytmDvGuJksMg5Hq3WI0rlOje7XBkIm_K_QxUVy9t0XcRC7QLmu4hevuYmJd-DGAIiWebji9HH5K99RbEE7b37xfkAzTEeRQAD4xN9_LlJY-4oTdDSGXrnA", "kid": "12345", "kty": "RSA"},

  "some_app": {"d": "LhkOOF2xralEJlZemrlHuCNXh87kwV42tUb-oCpqjfL9xd0DaTyfH5WDp-JJn9_31BE4Z1A467eeJrFW8oShB3nJDpRpPJB6CIoG0iClMfYj03dBecWGefinTl9FhqSJG9n4u6N92Hmn_WZiaunxd-ICqIs5DxakCIzTOTVTEGkasNaqdHSKtWDMOvSAvE0wApOdbHw7c1wBEodmkSt4vWM503J6b4gW-qItwfgx44tNN5wraFQRxDw7kmvmgxS6iu5XDL0C4DTUnViOQc56QIXpo9pWWXOgofn2KIVVTa3yQs5c68Lwg-6ZnZDdZXKSqNoULCIeYTeAs-WkRLA8eQ", "e": "AQAB", "n": "tNW0ZqJ5dWJGCX49oc4ww_Di1ZGDAt9mkxWkjXNjbmvD2oAbjiXWxJfngQeVz72NpGXI-1_QIPvx6EGb85Th9cqyuN5PCaBYZpszX71sxFfz8yUayxiXFK5OwzaeXaRgsknp4eSb9fiLbaMHwCM_50ptIFKl8Q4bZq_8StEvABvX4UNlNja7QNPaRhAm7nfILFpNvL-l6CoBPJz6pCbrK2cWHk43fWFvU1l0jj0_zKKe6EHOFcsntxPO20XneKqpGiIDU2t1lwEOSl40dpl1QMnmpQxxI2bNc72-Da4AAPpFnaD0PKhLLQf7C8pZtJKZIzo1bxHRykKSx0NOAnpeRw", "p": "5hjzqZ5A2fF60AC99GAp814ZL2xM9URick5grG_whP9qbf9DBnXceZsgPCv7OuR0Q8UKpchGMmrGH0Fd7CkSNAVkV7RbmtvfT0BTrCXZjLxYAsjOTCG2MFv6_L17aDJJiY5LaTgQTz20oC_1s-lwBxx_ma-6j78KMOjF0dm_yKk", "q": "yTEUX4lberDGFGFd8J9UWLpugZm8wauYWw965HDgjSBB5ljK-RlRLKClZbVF4_c30mSh-ADpFlx6MB-oHWfdNCsy-JzJFOchNnGlxaRGFiZ-puZdO4r47lfrFY3GVgYgY6nC4SgJ7qLaPvHT4c1-zNih7_gYHDKWegsTb-FIlW8", "dp": "pfkvoZUWgF7wUKOIYYMQH40rq4p6RJzMSlmA4EFqg_TdJ3TuOvW_UDR2XxD2ijeKKewyzvyUrf9Y4-i5wASsLbwJ8j2VqjGZdcgX0uAGeb7N2UxRipbynRVsCO0A3FsRslhiywX2tcHzzWxq1hi3h1mmLQyWDOQnjLoLH2DrNuk", "dq": "H8nscSfv11PlCEVWJXXXSumyGjIjW-pz-TdZ8IxRPpsxLmcrMu6oH8gGOirJLzrZjBmwadIjAhB8kev-kR7fGaYVuKh1MSNP4R1V1wOcu1U7v704T_cmW-pyT4aGJwNyzKx_CTpdT2JV34owM0ZX2aAE_jiR_qqTkhb77DqJUGs", "qi": "wgE_Tr0d19s8EpjlZYmPkbpO-LpdS4WemucFfCbKUSYFeuf5sDJK1KOZ4NNJWjHhmBoCUDri_GKwDSJdmgerJ0_zyv4ZAMOUjU1ScGhioBdcMMFXCDEqMfVQVfNuP3IDlBMzVGPzBicjwVQ6rlFLaOzVexFgF8rmbGeQcwxeAMk", "kid": "12345", "kty": "RSA"}
}

key = get_or_create_jwk()

# read by tokendings at starup
@app.get("/.well-known/openid-configuration")
def read_root():
    signed = create_signed_jwt(key)
    config =  {
        "token_endpoint":"http://fake_auth:3000/oauth2/v2.0/token",
        "token_endpoint_auth_methods_supported":["client_secret_post","private_key_jwt","client_secret_basic"],
        "jwks_uri":"http://fake_auth:3000/discovery/v2.0/keys",
        "response_modes_supported":["query","fragment","form_post"],
        "subject_types_supported":["pairwise"],
        "id_token_signing_alg_values_supported":["RS256"],
        "response_types_supported":["code","id_token","code id_token","id_token token"],
        "scopes_supported":["openid","profile","email","offline_access"],
        "issuer":"http://fake_auth:3000",
        "request_uri_parameter_supported":"false",
        "userinfo_endpoint":"https://graph.microsoft.com/oidc/userinfo",
        "authorization_endpoint":"https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/oauth2/v2.0/authorize",
        "device_authorization_endpoint":"https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/oauth2/v2.0/devicecode",
        "http_logout_supported":"true",
        "frontchannel_logout_supported":"true",
        "end_session_endpoint":"https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/oauth2/v2.0/logout",
        "claims_supported":["sub","iss","cloud_instance_name","cloud_instance_host_name","cloud_graph_host_name","msgraph_host","aud","exp","iat","auth_time","acr","nonce","preferred_username","name","tid","ver","at_hash","c_hash","email"],
        "kerberos_endpoint":"https://login.microsoftonline.com/62366534-1ec3-4962-8869-9b5535279d0b/kerberos",
        "tenant_region_scope":"EU",
        "cloud_instance_name":"microsoftonline.com",
        "cloud_graph_host_name":"graph.windows.net",
        "msgraph_host":"graph.microsoft.com",
        "rbac_url":"https://pas.windows.net"
    }

    return config

@app.post("/oauth2/v2.0/token")
def token_endpoint(request: Request):
    print(request.body())

# must restart tokendings and use a new key when registering a new client to 
# ensure they get a different key
@app.get("/try-reg")
def try_reg():
    # sign using well known
    signed_token = create_signed_jwt(key)
    client_jwks = None
    try:
        key_string = json.dumps(AUTH_CLIENT_JWKS["keys"][0])
        client_jwks = jwk.JWK.from_json(key_string)
    except Exception as e:
        return

    claims = {
        "appId": "some_app",
        "accessPolicyInbound": ["test_app"],
        "accessPolicyOutbound": []
    }

    software_statement = jwt.JWT(header={"alg": "RS256"}, claims=claims)
    software_statement.make_signed_token(client_jwks)
    s = software_statement.serialize()

    payload = {
        "client_name": "some_app",
        "jwks": {"keys": [key]},
        "software_statement": s,
    }
    headers = {'Authorization': f'Bearer {signed_token}', "Content-Type": "application/json"}
    res = requests.post("http://tokendings:8080/registration/client", json=payload, headers=headers)
    if res.status_code > 200:
        return res.content
    return res.json()


# used to "login" a user to be used as the subject token
@app.get("/fake_auth/{aud}")
def generate_sub_token(aud):
    claims = {
        "iss": "http://fake_auth:3000",
        "sub": "test@test.com",
        "aud": aud,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(days=1)).timestamp())
    }
    key_string = json.dumps(keys[aud])
    client_jwks = jwk.JWK.from_json(key_string)
    token = jwt.JWT(header={"alg": "RS256", "type": "JWT"}, claims=claims)
    token.make_signed_token(client_jwks)
    return token.serialize()

@app.get("/discovery/v2.0/keys")
def jwks():
    return {"keys": [key]}

