import requests
import os
from urllib.parse import urlencode

AUTH_CLIENT_ID = os.getenv("AUTH_CLIENT_ID")
AUTH_CLIENT_SECRET = os.getenv("AUTH_CLIENT_SECRET")
AUTH_SCOPE = os.getenv("AUTH_SCOPE")
AUTH_WELL_KNOWN_URL = os.getenv("AUTH_WELL_KNOWN_URL")

def get_well_known() -> dict:
  response = requests.get(AUTH_WELL_KNOWN_URL)
  return response.json()

def get_token() -> str:
  well_known = get_well_known()

  payload = {
    "grant_type": "client_credentials",
    "client_id": AUTH_CLIENT_ID,
    "client_secret": AUTH_CLIENT_SECRET,
    "scope": AUTH_SCOPE
  }
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
  }

  response = requests.request(
    "POST",
    well_known["token_endpoint"],
    headers=headers,
    data=urlencode(payload)
  )

  response_data = response.json()
  print(response_data)

  return response_data["access_token"]