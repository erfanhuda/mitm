"""
har_exporter.py — mitmproxy addon
==================================
Captures every HTTP/HTTPS flow and writes a rich HAR 1.2 file that includes:
  • Full request/response headers, body, timing
  • Cookies (request + response, with all attributes)
  • Authorization / Bearer tokens (extracted from headers + body)
  • JWT payloads (decoded, no verification)
  • OAuth tokens found in query params or JSON bodies
  • WebStorage hints extracted from Set-Cookie / response bodies
    (localStorage / sessionStorage keys injected by pages)
  • Custom _x_meta extension block per entry for test-mock automation

Usage
-----
    mitmproxy -s har_exporter.py
    mitmproxy -s har_exporter.py --set har_output=./my_session.har
    mitmproxy -s har_exporter.py --set har_output=./out.har \
              --set har_include_binary=true \
              --set har_redact_secrets=false

Options (--set key=value)
-------------------------
  har_output          Path for the .har file          (default: ./capture.har)
  har_include_binary  Include binary response bodies  (default: false)
  har_redact_secrets  Redact sensitive token values   (default: true)
  har_capture_ws      Capture WebSocket frames        (default: true)
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
import urllib.parse
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http, websocket
from mitmproxy.connection import TransportProtocol

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_REDACT = "••••••REDACTED••••••"
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\."     # header
    r"eyJ[A-Za-z0-9_-]+\."     # payload
    r"[A-Za-z0-9_-]+"          # signature
)
_BEARER_RE = re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)")
_OAUTH_KEYS = {"access_token", "refresh_token", "id_token", "token", "code"}
_SENSITIVE_HEADER_NAMES = {
    "authorization", "x-api-key", "x-auth-token", "x-access-token",
    "x-secret", "proxy-authorization",
}


def _b64_decode_safe(segment: str) -> dict | None:
    """Decode a base64url segment into a dict, returns None on failure."""
    pad = 4 - len(segment) % 4
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * pad)
        return json.loads(raw)
    except Exception:
        return None


def _decode_jwt(token: str) -> dict[str, Any]:
    """Return {"header": {...}, "payload": {...}} for a JWT string."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    header = _b64_decode_safe(parts[0]) or {}
    payload = _b64_decode_safe(parts[1]) or {}
    return {"header": header, "payload": payload}


def _extract_jwts(text: str) -> list[dict]:
    found = []
    for match in _JWT_RE.finditer(text):
        token = match.group(0)
        decoded = _decode_jwt(token)
        found.append({"raw_token": token, "decoded": decoded})
    return found


def _extract_bearer(header_value: str) -> str | None:
    m = _BEARER_RE.search(header_value)
    return m.group(1) if m else None


def _extract_oauth_from_body(body: str) -> dict:
    """Try to pull OAuth/token fields from a JSON or form-encoded body."""
    tokens: dict[str, Any] = {}
    # JSON
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key in _OAUTH_KEYS:
                if key in data:
                    tokens[key] = data[key]
                    jwt_info = _extract_jwts(str(data[key]))
                    if jwt_info:
                        tokens[f"{key}_decoded"] = jwt_info[0]["decoded"]
        return tokens
    except Exception:
        pass
    # form-encoded
    try:
        params = dict(urllib.parse.parse_qsl(body))
        for key in _OAUTH_KEYS:
            if key in params:
                tokens[key] = params[key]
        return tokens
    except Exception:
        return {}


def _extract_oauth_from_qs(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    tokens: dict[str, Any] = {}
    for key in _OAUTH_KEYS:
        if key in params:
            tokens[key] = params[key]
    return tokens


def _parse_cookies_from_header(header_value: str) -> list[dict]:
    """Parse Cookie: header (key=val; key=val …)."""
    cookies = []
    for pair in header_value.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _, value = pair.partition("=")
            cookies.append({"name": name.strip(), "value": value.strip()})
        elif pair:
            cookies.append({"name": pair, "value": ""})
    return cookies


def _parse_set_cookie(header_value: str) -> dict:
    """Parse a single Set-Cookie header into a structured dict."""
    sc = SimpleCookie()
    try:
        sc.load(header_value)
    except Exception:
        pass
    result: dict[str, Any] = {}
    for morsel in sc.values():
        result = {
            "name": morsel.key,
            "value": morsel.value,
            "path": morsel.get("path", ""),
            "domain": morsel.get("domain", ""),
            "expires": morsel.get("expires", ""),
            "httpOnly": bool(morsel.get("httponly")),
            "secure": bool(morsel.get("secure")),
            "sameSite": morsel.get("samesite", ""),
        }
        break
    # fallback for servers that don't quote properly
    if not result:
        parts = [p.strip() for p in header_value.split(";")]
        if parts:
            name, _, value = parts[0].partition("=")
            result = {"name": name.strip(), "value": value.strip()}
            attrs = {p.split("=")[0].lower(): (p.split("=")[1] if "=" in p else True)
                     for p in parts[1:]}
            result.update({
                "path": attrs.get("path", ""),
                "domain": attrs.get("domain", ""),
                "expires": attrs.get("expires", ""),
                "httpOnly": attrs.get("httponly", False) is not False,
                "secure": attrs.get("secure", False) is not False,
                "sameSite": attrs.get("samesite", ""),
            })
    return result


def _sniff_web_storage(body: str) -> dict[str, list[dict]]:
    """
    Heuristically extract localStorage / sessionStorage key hints from
    JS response bodies (e.g. calls to localStorage.setItem('key','val')).
    """
    local: list[dict] = []
    session: list[dict] = []
    ls_re = re.compile(r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']?([^"\')\n]{0,200})')
    ss_re = re.compile(r'sessionStorage\.setItem\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']?([^"\')\n]{0,200})')
    for m in ls_re.finditer(body):
        local.append({"key": m.group(1), "value_hint": m.group(2).strip("'\" ")})
    for m in ss_re.finditer(body):
        session.append({"key": m.group(1), "value_hint": m.group(2).strip("'\" ")})
    return {"localStorage": local, "sessionStorage": session}


def _maybe_redact(value: str, redact: bool) -> str:
    return _REDACT if redact else value


def _content_type(headers) -> str:
    return headers.get("content-type", "")


def _mime_type(headers) -> str:
    ct = _content_type(headers)
    return ct.split(";")[0].strip() if ct else "application/octet-stream"


def _is_binary_mime(mime: str) -> bool:
    text_prefixes = ("text/", "application/json", "application/xml",
                     "application/javascript", "application/x-www-form-urlencoded")
    return not any(mime.startswith(p) for p in text_prefixes)


def _body_text(content: bytes, mime: str, include_binary: bool) -> tuple[str, str, int]:
    """Returns (text, encoding, size). encoding is '' or 'base64'."""
    if not content:
        return "", "", 0
    if _is_binary_mime(mime):
        if include_binary:
            return base64.b64encode(content).decode(), "base64", len(content)
        return "", "base64", len(content)
    try:
        return content.decode("utf-8", errors="replace"), "", len(content)
    except Exception:
        return base64.b64encode(content).decode(), "base64", len(content)


def _ms(seconds: float | None) -> float:
    return round((seconds or 0) * 1000, 3)


# ──────────────────────────────────────────────────────────────────────────────
# Main addon
# ──────────────────────────────────────────────────────────────────────────────

class HarExporter:
    """mitmproxy addon: capture flows → HAR 1.2 with rich token/cookie metadata."""

    def __init__(self):
        self._har: dict[str, Any] = self._empty_har()
        self._ws_frames: dict[str, list[dict]] = {}  # flow_id → frames

    # ── mitmproxy lifecycle ────────────────────────────────────────────────

    def load(self, loader):
        loader.add_option("har_output", str, "capture.har",
                          "Output path for the HAR file")
        loader.add_option("har_include_binary", bool, False,
                          "Include binary response bodies as base64")
        loader.add_option("har_redact_secrets", bool, True,
                          "Redact sensitive token values in HAR")
        loader.add_option("har_capture_ws", bool, True,
                          "Capture WebSocket frames")

    def done(self):
        self._flush()

    # ── HTTP hooks ────────────────────────────────────────────────────────

    def response(self, flow: http.HTTPFlow):
        entry = self._build_entry(flow)
        if entry:
            self._har["log"]["entries"].append(entry)

    # ── WebSocket hooks ───────────────────────────────────────────────────

    def websocket_start(self, flow: http.HTTPFlow):
        if ctx.options.har_capture_ws:
            self._ws_frames[flow.id] = []

    def websocket_message(self, flow: http.HTTPFlow):
        if not ctx.options.har_capture_ws:
            return
        if flow.id not in self._ws_frames:
            self._ws_frames[flow.id] = []
        msg = flow.websocket.messages[-1]
        self._ws_frames[flow.id].append({
            "type": "send" if msg.from_client else "receive",
            "time": datetime.fromtimestamp(msg.timestamp, tz=timezone.utc).isoformat(),
            "opcode": msg.type,
            "data": msg.content.decode("utf-8", errors="replace")
            if isinstance(msg.content, bytes) else str(msg.content),
        })

    def websocket_end(self, flow: http.HTTPFlow):
        if flow.id in self._ws_frames:
            # Attach WS frames to the last HAR entry that matches this flow
            url = flow.request.pretty_url
            for entry in reversed(self._har["log"]["entries"]):
                if entry["request"]["url"] == url:
                    entry.setdefault("_x_meta", {})["websocket_frames"] = \
                        self._ws_frames.pop(flow.id)
                    break

    # ── Build HAR entry ───────────────────────────────────────────────────

    def _build_entry(self, flow: http.HTTPFlow) -> dict | None:
        if not flow.response:
            return None

        redact = ctx.options.har_redact_secrets
        include_binary = ctx.options.har_include_binary
        req = flow.request
        res = flow.response

        # ── Timing ──────────────────────────────────────────────────────
        started = req.timestamp_start or time.time()
        send_end = req.timestamp_end or started
        res_start = res.timestamp_start or send_end
        res_end = res.timestamp_end or res_start

        timings = {
            "send": _ms(send_end - started),
            "wait": _ms(res_start - send_end),
            "receive": _ms(res_end - res_start),
        }
        total_time = sum(timings.values())

        # ── Request ──────────────────────────────────────────────────────
        req_headers = self._headers_list(req.headers, redact)
        req_cookies = self._req_cookies(req)
        req_mime = _mime_type(req.headers)
        req_body_text, req_enc, req_body_size = _body_text(req.content or b"", req_mime, True)
        req_qs = [{"name": k, "value": v}
                  for k, v in urllib.parse.parse_qsl(req.query_string or "")]

        post_data = None
        if req.content:
            post_data = {
                "mimeType": req_mime,
                "text": req_body_text,
            }
            if req_mime == "application/x-www-form-urlencoded":
                post_data["params"] = [
                    {"name": k, "value": v}
                    for k, v in urllib.parse.parse_qsl(req_body_text)
                ]

        # ── Response ─────────────────────────────────────────────────────
        res_headers = self._headers_list(res.headers, redact=False)
        res_cookies = self._res_cookies(res)
        res_mime = _mime_type(res.headers)
        res_body_text, res_enc, res_body_size = _body_text(res.content or b"", res_mime, include_binary)

        content_block: dict[str, Any] = {
            "size": res_body_size,
            "mimeType": res_mime,
        }
        if res_body_text:
            content_block["text"] = res_body_text
        if res_enc:
            content_block["encoding"] = res_enc

        # ── Token extraction ─────────────────────────────────────────────
        tokens = self._extract_tokens(req, res, req_body_text, res_body_text, redact)

        # ── Web storage hints ────────────────────────────────────────────
        storage_hints: dict[str, Any] = {}
        if res_mime in ("application/javascript", "text/javascript", "text/html"):
            storage_hints = _sniff_web_storage(res_body_text)

        # ── _x_meta block (custom extension for test-mock automation) ────
        x_meta: dict[str, Any] = {
            "flow_id": flow.id,
            "client_address": f"{flow.client_conn.peername[0]}:{flow.client_conn.peername[1]}"
            if flow.client_conn and flow.client_conn.peername else "",
            "tls": flow.server_conn.tls_established if flow.server_conn else False,
            "http_version": req.http_version,
            "tokens": tokens,
        }
        if storage_hints.get("localStorage") or storage_hints.get("sessionStorage"):
            x_meta["web_storage_hints"] = storage_hints

        # ── Assemble entry ────────────────────────────────────────────────
        entry: dict[str, Any] = {
            "startedDateTime": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
            "time": round(total_time, 3),
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "httpVersion": req.http_version,
                "headers": req_headers,
                "cookies": req_cookies,
                "queryString": req_qs,
                "headersSize": self._headers_size(req.headers),
                "bodySize": req_body_size if req.content else -1,
            },
            "response": {
                "status": res.status_code,
                "statusText": res.reason or "",
                "httpVersion": res.http_version,
                "headers": res_headers,
                "cookies": res_cookies,
                "content": content_block,
                "redirectURL": res.headers.get("location", ""),
                "headersSize": self._headers_size(res.headers),
                "bodySize": res_body_size,
            },
            "cache": {},
            "timings": timings,
            "_x_meta": x_meta,
        }
        if post_data:
            entry["request"]["postData"] = post_data

        return entry

    # ── Token extraction logic ─────────────────────────────────────────

    def _extract_tokens(
        self, req: http.Request, res: http.Response,
        req_body: str, res_body: str, redact: bool
    ) -> dict[str, Any]:
        tokens: dict[str, Any] = {}

        # Authorization header
        auth = req.headers.get("authorization", "")
        if auth:
            bearer = _extract_bearer(auth)
            if bearer:
                jwt_data = _extract_jwts(bearer)
                tokens["bearer_token"] = {
                    "value": _maybe_redact(bearer, redact),
                    "jwt": jwt_data[0]["decoded"] if jwt_data else None,
                }
            elif auth.lower().startswith("basic "):
                try:
                    decoded_basic = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
                    user, _, _ = decoded_basic.partition(":")
                    tokens["basic_auth"] = {
                        "username": user,
                        "credentials": _maybe_redact(auth[6:], redact),
                    }
                except Exception:
                    pass
            else:
                tokens["auth_header"] = _maybe_redact(auth, redact)

        # API key headers
        for hname in ("x-api-key", "x-auth-token", "x-access-token", "api-key"):
            val = req.headers.get(hname, "")
            if val:
                tokens[hname.replace("-", "_")] = _maybe_redact(val, redact)

        # CSRF tokens
        for hname in ("x-csrf-token", "x-xsrf-token"):
            val = req.headers.get(hname, "")
            if val:
                tokens[hname.replace("-", "_")] = val   # CSRF rarely needs redaction

        # OAuth in query string
        qs_oauth = _extract_oauth_from_qs(req.pretty_url)
        if qs_oauth:
            tokens["oauth_query_params"] = {
                k: _maybe_redact(v, redact) for k, v in qs_oauth.items()
            }

        # OAuth / tokens in request body
        if req_body:
            body_oauth = _extract_oauth_from_body(req_body)
            if body_oauth:
                tokens["oauth_request_body"] = {
                    k: _maybe_redact(str(v), redact) for k, v in body_oauth.items()
                }

        # OAuth / tokens in response body
        if res_body:
            body_oauth = _extract_oauth_from_body(res_body)
            if body_oauth:
                tokens["oauth_response_body"] = {
                    k: _maybe_redact(str(v), redact) for k, v in body_oauth.items()
                }

        # JWTs anywhere in response body (e.g. SSO pages, init payloads)
        if res_body:
            all_jwts = _extract_jwts(res_body)
            if all_jwts:
                tokens["jwts_in_response"] = [
                    {
                        "value": _maybe_redact(j["raw_token"], redact),
                        "decoded": j["decoded"],
                    }
                    for j in all_jwts
                ]

        return tokens

    # ── Cookie parsing ────────────────────────────────────────────────────

    def _req_cookies(self, req: http.Request) -> list[dict]:
        cookie_header = req.headers.get("cookie", "")
        if not cookie_header:
            return []
        return _parse_cookies_from_header(cookie_header)

    def _res_cookies(self, res: http.Response) -> list[dict]:
        cookies = []
        for value in res.headers.get_all("set-cookie"):
            parsed = _parse_set_cookie(value)
            if parsed:
                cookies.append(parsed)
        return cookies

    # ── Utilities ─────────────────────────────────────────────────────────

    @staticmethod
    def _headers_list(headers, redact: bool = False) -> list[dict]:
        result = []
        for name, value in headers.items():
            if redact and name.lower() in _SENSITIVE_HEADER_NAMES:
                value = _REDACT
            result.append({"name": name, "value": value})
        return result

    @staticmethod
    def _headers_size(headers) -> int:
        try:
            return sum(len(k) + len(v) + 4 for k, v in headers.items())
        except Exception:
            return -1

    @staticmethod
    def _empty_har() -> dict:
        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "mitmproxy-har-exporter",
                    "version": "1.0.0",
                    "comment": "Rich HAR capture for test-mock automation",
                },
                "browser": {"name": "mitmproxy", "version": "unknown"},
                "pages": [],
                "entries": [],
            }
        }

    def _flush(self):
        path = Path(ctx.options.har_output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self._har, f, indent=2, default=str)
        n = len(self._har["log"]["entries"])
        logger.info(f"[har_exporter] Wrote {n} entries → {path.resolve()}")


# ── mitmproxy entry point ──────────────────────────────────────────────────
def load(loader):
    # Called by mitmproxy to detect the addon's option declarations
    pass


addon = HarExporter()
addons = [addon]
