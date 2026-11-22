import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SESSION_SECRET = os.getenv("SESSION_SECRET", "vilco_dev_secret_change_in_prod_987654321").encode()
TOKEN_TTL_SECONDS = 60 * 60 * 12  # 12 horas

_FAILED_LOGINS: Dict[str, list] = defaultdict(list)


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    _FAILED_LOGINS[ip] = [t for t in _FAILED_LOGINS[ip] if now - t < 60]
    return len(_FAILED_LOGINS[ip]) < 5


def register_failed_login(ip: str):
    _FAILED_LOGINS[ip].append(time.time())


def clear_failed_logins(ip: str):
    _FAILED_LOGINS.pop(ip, None)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"pbkdf2_sha256$100000${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, iters, salt_b64, dk_b64 = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def create_session_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    sig = hmac.new(SESSION_SECRET, raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify_session_token(token: str) -> Optional[dict]:
    try:
        raw, sig = token.split(".")
        expected_sig = hmac.new(SESSION_SECRET, raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(raw.encode()).decode())
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def _load_ed25519_keys() -> Tuple[ed25519.Ed25519PrivateKey, str]:
    b64_priv = os.getenv("ED25519_PRIVATE_KEY_B64", "").strip()
    if b64_priv:
        priv_bytes = base64.b64decode(b64_priv)
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    else:
        priv_key = ed25519.Ed25519PrivateKey.generate()
        raw_priv = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print(f"[DEV] ED25519_PRIVATE_KEY_B64={base64.b64encode(raw_priv).decode()}")

    pub_bytes = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_key, base64.b64encode(pub_bytes).decode()


PRIVATE_KEY, PUBLIC_KEY_B64 = _load_ed25519_keys()


def sign_license_certificate(payload: dict) -> dict:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = PRIVATE_KEY.sign(canonical)
    return {
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("utf-8"),
        "algorithm": "Ed25519",
    }


ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def generate_robust_license_key(app_prefix: str = "AEGS") -> str:
    prefix = "".join(c for c in app_prefix.upper() if c.isalnum())[:4].ljust(4, "X")
    part1 = "".join(secrets.choice(ALPHABET) for _ in range(4))
    part2 = "".join(secrets.choice(ALPHABET) for _ in range(4))
    base = f"VLCO-{prefix}-{part1}-{part2}"
    checksum = hashlib.sha256(base.encode()).hexdigest()[:4].upper()
    return f"{base}-{checksum}"
