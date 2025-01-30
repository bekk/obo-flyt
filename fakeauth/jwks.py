from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import json

path = "./jwks.json"

def save_to_file(key):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(key, f)

def load_from_file():
    try:
        with open(path, "r") as f:
            key_json = json.load(f)
            print(f"file read: {key_json}")
        key = jwk.JWK.from_json(key_json)
    except:
        key = None
    return key

def get_or_create_jwk():
    key = load_from_file()
    if key == None:
        key = generate_jwk()
        save_to_file(key.export(private_key=True))
    print("pub: ", key.export_private())
    print("priv: ", key.export_public())
    return key

def generate_jwk():
    return jwk.JWK.generate(kty='RSA', size=2048, kid="1234")

def create_signed_jwt(key):
    claims = {
        "aud": "bogus",
        "iss": "http://fake_auth:3000",
        "roles": ["access_as_application"],
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    }

    token = jwt.JWT(header={"alg": "RS256"}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()

def verify_jwt(token, key):
    try:
        verified_token = jwt.JWT(key=key, jwt=token)
        return verified_token.claims
    except Exception as e:
        return f"Verification failed: {e}"

