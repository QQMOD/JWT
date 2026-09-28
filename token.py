
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import base64
import gzip
import hashlib
import hmac
import json
import os
import time
import urllib.request
import urllib.error
import zlib


# ======================================================================
# CONFIG
# ======================================================================
GARENA_URL = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"

GARENA_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.44(SM-S9260 ;Android 15;en;US;app 1.132.1 2019121229;)",
    "Accept": "application/json",
    "Content-Type": "application/json; charset=utf-8",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

GARENA_CLIENT_ID     = 100067
GARENA_CLIENT_SECRET = os.environ.get(
    "GARENA_CLIENT_SECRET",
    "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
)
GARENA_DEVICE_ID     = os.environ.get(
    "GARENA_DEVICE_ID",
    "02-87355d38-99fb-49f6-9477-4a7b317cc143",
)

LOCAL_JWT_SECRET = os.environ.get("LOCAL_JWT_SECRET", "jwt-vercel-local-secret-change-me")
LOCAL_JWT_ALG    = "HS256"

API_KEY = os.environ.get("API_KEY")   # optional
CREDIT  = "@MRSHUVO"


# ======================================================================
# JWT helpers
# ======================================================================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_jwt(claims: dict, secret: str = LOCAL_JWT_SECRET,
              alg: str = LOCAL_JWT_ALG) -> str:
    header = {"alg": alg, "svr": "1", "typ": "JWT"}
    h = _b64url(json.dumps(header,  separators=(",", ":")).encode())
    p = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


# ======================================================================
# HTTP helpers
# ======================================================================
def _decompress(raw: bytes, enc: str) -> bytes:
    enc = (enc or "").lower()
    if "gzip" in enc:
        return gzip.decompress(raw)
    if "deflate" in enc:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    return raw


def post_json(url: str, headers: dict, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    h = dict(headers)
    h["Content-Length"] = str(len(body))
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = _decompress(resp.read(), resp.headers.get("Content-Encoding"))
            return resp.status, json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = _decompress(e.read(), e.headers.get("Content-Encoding"))
        try:
            return e.code, json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return e.code, {"raw": raw.decode("utf-8", "replace")}
    except urllib.error.URLError as e:
        return 0, {"error": f"URLError: {e.reason}"}


# ======================================================================
# Core logic
# ======================================================================
def fetch_garena_token(uid: int, password: str, device_id: str) -> tuple[int, dict]:
    payload = {
        "client_id":     GARENA_CLIENT_ID,
        "client_secret": GARENA_CLIENT_SECRET,
        "client_type":   2,
        "device_id":     device_id,
        "password":      password,
        "response_type": "token",
        "uid":           uid,
    }
    return post_json(GARENA_URL, GARENA_HEADERS, payload)


def account_name_from_open_id(open_id: str) -> str:
    """
    Derive a stable 'account_name' from open_id.
    Garena's own field looks like a base64 of some internal name.
    We just make a deterministic 16-byte base64 of the first 12 bytes
    of the open_id so the shape matches (16 chars ending in '=').
    """
    if not open_id:
        return ""
    raw = bytes.fromhex(open_id) if all(c in "0123456789abcdefABCDEF" for c in open_id) else open_id.encode()
    digest = hashlib.sha1(raw).digest()[:12]
    return base64.b64encode(digest).decode("ascii")   # 16 chars, ends with '='


def build_claims(data: dict, region: str) -> dict:
    """
    Build the JWT payload in the same shape Garena uses in its real token
    (account_id, nickname, noti_region, lock_region, external_id, ...).
    """
    now = int(time.time())
    uid = data.get("uid")
    open_id = data.get("open_id", "")
    platform = data.get("platform", 4)

    return {
        # Garena-style claim names
        "account_id":          uid,
        "nickname":            account_name_from_open_id(open_id),
        "noti_region":         region,
        "lock_region":         region,
        "external_id":         open_id,
        "external_type":       platform,
        "plat_id":             2,
        "client_version":      "1.130.1",
        "client_version_code": "2024010012",
        "emulator_score":      0,
        "is_emulator":         False,
        "country_code":        "US",
        "external_uid":        uid,
        "reg_avatar":          102000007,
        "source":              0,
        "lock_region_time":    now,
        "client_type":         3,
        "signature_md5":       hashlib.md5(
                                   str(data.get("access_token", "")).encode()
                               ).hexdigest(),
        "using_version":       1,
        "release_channel":     "android",
        "release_version":     "OB55",

        # standard JWT claims
        "iat": data.get("create_time", now),
        "nbf": data.get("create_time", now),
        "exp": data.get("expiry_time", now + data.get("expires_in", 0)),
    }


# ======================================================================
# Vercel handler
# ======================================================================
class handler(BaseHTTPRequestHandler):

    def _send(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        # Health / usage
        if parsed.path in ("/", "", "/index"):
            self._send(200, {
                "status": "success",
                "usage": "/token?uid=<uid>&password=<password>",
                "credit": CREDIT,
            })
            return

        if parsed.path != "/token":
            self._send(404, {
                "status": "error",
                "error": "not_found",
                "path": parsed.path,
                "credit": CREDIT,
            })
            return

        # Optional API key check
        if API_KEY and (qs.get("key") or [None])[0] != API_KEY:
            self._send(401, {
                "status": "error",
                "error": "unauthorized",
                "credit": CREDIT,
            })
            return

        uid_raw = (qs.get("uid") or [None])[0]
        pwd     = (qs.get("password") or [None])[0]
        dev     = (qs.get("device_id") or [GARENA_DEVICE_ID])[0]
        region  = (qs.get("region") or ["ME"])[0]

        if not uid_raw or not pwd:
            self._send(400, {
                "status": "error",
                "error": "missing_params",
                "usage": "/token?uid=<uid>&password=<password>",
                "credit": CREDIT,
            })
            return

        try:
            uid = int(uid_raw)
        except ValueError:
            self._send(400, {
                "status": "error",
                "error": "invalid_uid",
                "uid": uid_raw,
                "credit": CREDIT,
            })
            return

        # 1) Ask Garena for the guest token
        status, garena_resp = fetch_garena_token(uid, pwd, dev)

        if status != 200 or garena_resp.get("code") != 0:
            self._send(status or 502, {
                "status": "error",
                "stage": "garena_token",
                "garena_status": status,
                "garena_response": garena_resp,
                "credit": CREDIT,
            })
            return

        data = garena_resp["data"]

        # 2) Build a LOCAL JWT in Garena's payload shape
        claims    = build_claims(data, region)
        jwt_token = build_jwt(claims)

        # 3) Respond in the requested format
        self._send(200, {
            "account_id":   data.get("uid"),
            "account_name": account_name_from_open_id(data.get("open_id", "")),
            "open_id":      data.get("open_id"),
            "access_token": data.get("access_token"),
            "platform":     data.get("platform", 4),
            "region":       region,
            "status":       "success",
            "token":        jwt_token,
            "credit":       CREDIT,
        })
