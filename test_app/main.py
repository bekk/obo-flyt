from fastapi import FastAPI, Request
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import requests
import json

app = FastAPI()

CLIENT_ID="test_app"

JWK_KEY = {"d": "Sx0CvZ4BfarypKZ3dBJcrGB_MRzpzbghyz2W9wp0ix1Z02DxLUNlGM6fQY8dE7eSjNayBc0F0f_mqg2dz6ZrRdoQsjp6OGlw4vK5akz3l5hnVZzDbbKwRajyrGJXSDV0A6pfXGG8h1CsNMAjMxOVQCp5eu-SinWdR_FvPBkBHNFCVSV4zvgqdNQENHtT6ZrZGbZ9v3ICrJ4tTAUcE4oBTuiX0uSTg_Jiw7Ce4c_8lFHmNT8sImsmVAftCYG3K4NN7ttTdp21KdhnTrHwMF_GoQFcy5kAsCjWZFu2bWyc4p2fZLfASogxpvoe0NzDaydG6Ak3EMYPCIhXWu9p_fLaoQ", "e": "AQAB", "n": "vHjZOPFqrxM0Kxjs-yB_o8L-Fb2EWmMMDyqWsPdrd4ub6pT3K8m5VaucicpLjnfaU-5Oq4hrpdhPrx9aXtvzOMW8lu6MXP3Jr17o1HnoTlT3e5rmadDgBZQ_cnCnHhFZuOK2yCw7fAwSDF9ivYaGpdDLIsaHpnT3Uk74hFvops8Ph-tzQ_faMjRplsD6ITsM2uX3gI0-uOLj9CVf4kNEP0U8Bgw7mhGrC9CAPoxGAcDgx3N_7jN_dCdB94nI3s5wOWcRjgT9vKl3CJNqpF0BBt9ij0z_uLLYwdrt0ho9OoUJJYiEZqHXKHU-XBVVvO65ZRTxyuPpdWkhVIYUZpY_mw", "p": "-5RmlrjNSb9DjxHSCpyQL8-Quot0F3P2Y9z5M-VvNR-0WBmee-eb7KjN__wr2GrGiTL84e-gjZ2XnmKejtmBSDr37sEn7_kpe4QnI3jSjuIyXAtA65whCN3JLPuy38IQ6YwgbLDex3tIl0h7dr7KRk5RhzFk209ViJi9pQsFXss", "q": "v8iXW2M8bYbryTcRD1L3qNPIgbHLji05y1BC113ew3pOrOd0nZLcjWOsJ-L2XUwIUskhu_YDwpMToeHA7WveBlgumeBx3nULeRcqYA_zVFl3OmT6o6Zj5bxukFbg9PoIEum8kePh0N47bNtnkW0WEgsRt8txRstfJ-h6pxMROHE", "dp": "Sf_bsSfIkpGkwJeATcjBjJ6kNorAagmdBsC_uGkbLegWdveKK23z6ke42DwHdY_qt_58bcS7WAxrxZXCh8gog-N8fAjqw2ZpskAr9v4aCRc1sudIgEUbXm1GOGoMsk52BQxHmVDpJon3zy_tyP7Tppxw1LBNt0h9o0EyPzKfsMM", "dq": "Acv5Twvg9w26i8oOSNx4IYbKbBykUZKu5e68kZP5kE9HCWuptgg4NMLoS_9eW4Vo1o232TD23A3Qs0WQLylBjUGqPhrSNklWcC39YaUEnJex_EQR7RKUAQUA7C1EMkddZ__0mlFOPky2tdBgagZhnI2p_tTTHNyu6YrOC16sXKE", "qi": "ynaCsJj3LtVaNsgEnGvb0yBQGfjWX712lLX1VSSUTVaxmqQPkf83NytmDvGuJksMg5Hq3WI0rlOje7XBkIm_K_QxUVy9t0XcRC7QLmu4hevuYmJd-DGAIiWebji9HH5K99RbEE7b37xfkAzTEeRQAD4xN9_LlJY-4oTdDSGXrnA", "kid": "12345", "kty": "RSA"}

AUTH_CLIENT_JWKS={"keys":[{"p":"-UTsojJQES7Rxg-wyiRBMwI7qyBfjiBXkhOfhwLZPvaNFnL5O4PDZOl_5RpYSKYm3zhe1sI37P8kKLXpWKGTtahPU8pJp6wi3wKa14BjHfBoUD8vC8vPR6LPzCkaksuSLxnabmCqi5BIgM4Ktt8L365wxj3XvZk78jdqkfZ5TrU","kty":"RSA","q":"97x12F8J4rdh4Fxlnu_h8-RusL4JRFfXg3NC5Xg-sCUYA8qgObHAyQpeNj6WCN10G_OxdUaRvK-0RY0eeiAK2QgIgmQBhaRUcIk1_TE7NS30L8DbsLvJUkR38YrrSlGipMgIp2p1cPH2o0qqUREu3kBHpyibMtYJhP4GTtYo73k","d":"owLjH1SbTKdgzK85s49oWGJXQ_0JZ0Gl_eYGodAXDJFRwRnCWcqmaQ4mtve8LuQKNhyfNzGL0q5B1EwzIQUTDA53OuU_nMLQREqajA7rl_EpAJaSt41AwE183Dq61BAgQvKCNBK2av_ih_eX5fZ0uwFarL4VNmP6ac-9SbOFKYWhYPksXkw9PO8PfjtVcR8mLC48LHfc-4WDZFb_7PZEGUE7LWIqfEq_LkMOx-zyB_aAENCgyjjJ00ArFpHwK6kJtuYW_vWCTUirn3V5EddFNuR9ueSo-OptOiR3U4v6zJDGdtvISP0wjLFOfyXfhy9gFOYaA9vX7O3AtXgpgG_gAQ","e":"AQAB","qi":"eDUmJ_GRtjbLzaF-bHQzIxxV7wJ8ta2Sc60yATDh1lfMOv1dKeVm5oXJIn-wz9yUVZqALyaXOXU4ajG3prAUuueoB7cVMx03AC91p3zMdTcCmhGfX3tT2VovpdrAjB7d6EtMYV5tHSsNBpkCMZQ4Gbp0oqaJFZEvCvKL_BuPKJk","dp":"baDBjcgg7J2xxrDp6M0vG5b01RtEy0YwHV-h_ofjMczPWjswn9sgWUZUaFdA0pq4Z93r3_nFDOddaMYwnTlatD8UvF4wLJ0JLRmBLhwZ-3Xa-sf_EeoN_Ix_ZWQCeuMrJKnzJi4_c2f-ax-zGKBaIYMfuCBEvO8irTFwHkfPLC0","dq":"VznI-GUGEwhkct21fg-SLBB7FMnkc2bGX-ceX7NFxzlYSkV2wrmeWmrHHyxMIVTvw8O68MLnH1tyCqcUWwWbLC1S6a4Shx6ECJeXJc3GvgOvHX03HPQRf2DSJn62N5WkwYYY3fFy5lCbeYUZkK-PI_vX_rgiZPTNp0DVsb5f7Wk","n":"8TkBrXSAMTfBCnN1eQYUk6swUGUSVkKqim2HcbQe3vBEi7hATEiChL49z1f40w2l4qEMUpgQTUigkdacAc39I7VKaZkf0573KZa-pra0BDxOWGnqQUtseK73XM6Pn4Im9EU1fqQhSBUqOAMky40aLo4u4RFmCZRCTKMAJaVzOE0aSslmW0wN2SPQfMwqcglkAcoJhqn8kejJ7kA6j8DpR1Q0CTy9hhn63DRJSKD3Lx93g9YiBCBYXYQTBH4-ZUePPk6rHJvU6g40xbfRCWOjG6SSrEOKBL-qZGxIA_MUYJpNRH1YmHl5mzp9KahCplPBSWRaCSo4n8Q_68f-WhkujQ"}]}

def create_client_assertion():
    key_string = json.dumps(JWK_KEY)
    client_jwks = jwk.JWK.from_json(key_string)
    claims = {
        "sub": "test_app",
        "iss": "test_app",
        "aud": "http://tokendings:8080/token",
        "jti": "dsibfsdfasiafsadfasdfjkdsfbfai",
        "nbf": int(datetime.utcnow().timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(seconds=119)).timestamp()),
    }
    token = jwt.JWT(header={"alg": "RS256", "typ": "JWT"}, claims=claims)
    token.make_signed_token(client_jwks)
    return token.serialize()

@app.get("/test/token")
def request_toke():
    client_assertion_token = create_client_assertion()

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": "eyJhbGciOiJSUzI1NiIsInR5cGUiOiJKV1QifQ.eyJhdWQiOiJ0ZXN0X2FwcCIsImV4cCI6MTczNjkzOTkzMCwiaWF0IjoxNzM2ODUzNTMwLCJpc3MiOiJodHRwOi8vZmFrZV9hdXRoOjMwMDAiLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIn0.jjusK--XzD4KRCe_bHKc6KMs7foEzyR3qfOFFhSUORNa1M1GRVlWUZCPwT5QZN-QFrWAdRnCdiNThvqmGjqlOWMtAeL6omVum9lAHtbQZHbX9X0LzzPvAHY96_39M-e5TvVaxv2Bsg0tJiX_7ZifVu_UdVwwKxEhUvGVMQLwv0GnWpktU_kLJSnHPfoW-47pAFxV9Bk2zoJVkmiDQvquFT_tNduYBSQTRDf5Lw1pr3ceFb7-Ma22vTn_Hk_klO_hA3R6mkU2s41u1NL3g6um1DOseeTbEpBQjZBX-xIQHjW47laeB-Q9klxK-tbe4SNkPv6N8UsokaVsEndJfLow9w",
        "audience": "some_app"
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
