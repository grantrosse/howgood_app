"""Submit a signed application to the HowGood Senior Python Engineer endpoint.

Values come from .env in this directory. Run:

    python apply.py

The HMAC is computed over the exact bytes that are sent. Do not let the HTTP
client re-serialize the JSON, or the signature will not match.
"""

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

REQUIRED = ("name", "email", "resume", "location", "linkedin", "codeLink")


def env(name: str, default: str | None = None) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        if default is not None:
            return default
        raise SystemExit(f"Set {name} in .env")
    return value.strip()


def env_int(name: str, default: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        raise SystemExit(f"{name} in .env must be an integer") from None


def applicant_from_env() -> dict:
    payload = {
        "name": env("NAME"),
        "email": env("EMAIL"),
        "resume": env("RESUME"),
        "location": env("LOCATION"),
        "linkedin": env("LINKEDIN"),
        "codeLink": env("CODE_LINK"),
        "yearsPython": env_int("YEARS_PYTHON"),
        "yearsDjango": env_int("YEARS_DJANGO"),
    }
    repos = os.getenv("REPOS", "").strip()
    notes = os.getenv("NOTES", "").strip()
    if repos:
        payload["repos"] = repos
    if notes:
        payload["notes"] = notes
    return payload


def build_body(payload: dict) -> bytes:
    """Serialize once. These bytes are both signed and sent."""
    missing = [field for field in REQUIRED if not str(payload.get(field, "")).strip()]
    if missing:
        raise SystemExit(
            "Fill in required fields in .env: " + ", ".join(missing)
        )
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def submit(payload: dict) -> requests.Response:
    body = build_body(payload)
    signature = sign(body, env("HMAC_SECRET"))
    return requests.post(
        env("ENDPOINT"),
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-HMAC-Signature": signature,
        },
        timeout=30,
    )


def main() -> None:
    response = submit(applicant_from_env())
    print(response.status_code)
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text)


if __name__ == "__main__":
    main()
