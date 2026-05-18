# mitm - Interceptor & Visualizer

A lightweight HTTP/HTTPS interceptor and SSR traffic visualization platform built using Python and mitmproxy.

## Features

- HTTP/HTTPS interception
- SSR request detection
- Next.js / Nuxt.js hydration analysis
- Live sequence diagram dashboard
- mitmweb integration
- JSON flow export
- Request/response logging
- Web UI visualization

## mitmproxy HAR Exporter + Mock Server

A two-file toolkit for capturing real HTTP sessions and replaying them as a
local mock server for automated test suites.

-----

## Files

|File                |Purpose                                                |
|--------------------|-------------------------------------------------------|
|`har_exporter.py`   |mitmproxy addon — captures flows into a rich HAR file  |
|`har_mock_server.py`|Standalone HTTP server — replays the HAR for test mocks|

-----

## Installation

```bash
pip install mitmproxy
```

No other dependencies are needed. Both files use the Python standard library
plus mitmproxy itself.

-----

## 1. Capture traffic with mitmproxy

```bash
# Basic capture
mitmproxy -s har_exporter.py

# With options
mitmproxy -s har_exporter.py \
  --set har_output=./session.har \
  --set har_include_binary=false \
  --set har_redact_secrets=true \
  --set har_capture_ws=true

# Headless / CI
mitmdump -s har_exporter.py --set har_output=./ci_capture.har
```

Configure your browser / app to proxy through `127.0.0.1:8080`.

When you quit mitmproxy (`q`), the HAR file is written automatically.

### Addon options

|Option              |Default      |Description                            |
|--------------------|-------------|---------------------------------------|
|`har_output`        |`capture.har`|Output path                            |
|`har_include_binary`|`false`      |Include binary bodies as base64        |
|`har_redact_secrets`|`true`       |Redact token values with `••REDACTED••`|
|`har_capture_ws`    |`true`       |Capture WebSocket frames               |

-----

## 2. What’s captured

### Tokens

|Source                           |What’s extracted                              |
|---------------------------------|----------------------------------------------|
|`Authorization: Bearer …`        |Token value + JWT header/payload decoded      |
|`Authorization: Basic …`         |Username (password redacted by default)       |
|`x-api-key`, `x-auth-token`, etc.|Raw value                                     |
|`x-csrf-token`, `x-xsrf-token`   |Value (not redacted)                          |
|Query string                     |`access_token`, `code`, `token`, …            |
|Request body (JSON / form)       |`access_token`, `refresh_token`, `id_token`, …|
|Response body (JSON)             |Same fields + any JWT strings found anywhere  |

### Cookies

- Full request cookie list (name + value)
- Full response `Set-Cookie` attributes: Path, Domain, Expires, HttpOnly, Secure, SameSite

### Web Storage hints

Heuristically extracted from JS/HTML response bodies:

- `localStorage.setItem('key', 'value')` → key + value hint
- `sessionStorage.setItem('key', 'value')` → key + value hint

### WebSocket frames

If `har_capture_ws=true`, frames are stored in `_x_meta.websocket_frames`
per entry (type, timestamp, opcode, data).

-----

## 3. HAR structure (_x_meta extension)

Each entry contains a custom `_x_meta` block:

```json
"_x_meta": {
  "flow_id": "abc123",
  "client_address": "127.0.0.1:54321",
  "tls": true,
  "http_version": "HTTP/2.0",
  "tokens": {
    "bearer_token": {
      "value": "eyJ...",
      "jwt": {
        "header": { "alg": "RS256", "typ": "JWT" },
        "payload": { "sub": "user_42", "exp": 1780000000 }
      }
    },
    "oauth_response_body": {
      "access_token": "ya29.xxx",
      "refresh_token": "1//yyy"
    }
  },
  "web_storage_hints": {
    "localStorage": [{ "key": "auth_token", "value_hint": "eyJ..." }],
    "sessionStorage": []
  }
}
```

-----

## 4. Replay with the mock server

```bash
# Start mock server on port 8080
python har_mock_server.py session.har

# Custom port
python har_mock_server.py session.har --port 3000

# Strict: 404 for any unmatched request
python har_mock_server.py session.har --strict

# Simulate real network latency
python har_mock_server.py session.har --real-timing

# Fixed latency (0.2 s per request)
python har_mock_server.py session.har --latency 0.2

# Print token/cookie summary and exit
python har_mock_server.py session.har --show-tokens
```

### Request matching priority

1. **Exact**: method + path + full query string
1. **Path + method**: ignores query string
1. **Path only**: any method
1. **No match**: empty 200 (or 404 in `--strict` mode)

### Token summary output (`--show-tokens`)

```json
{
  "bearer_tokens": [ { "value": "••REDACTED••", "jwt": { ... } } ],
  "api_keys": [],
  "oauth_flows": [ { "oauth_response_body": { "access_token": "••" } } ],
  "csrf_tokens": [ "abc123def456" ],
  "cookies": {
    "session_id": { "name": "session_id", "value": "xyz", "httpOnly": true }
  },
  "web_storage_hints": {
    "localStorage": [ { "key": "auth_token", "value_hint": "eyJ..." } ],
    "sessionStorage": []
  }
}
```

-----

## 5. Using in test suites

### pytest example

```python
import pytest, subprocess, time, requests

@pytest.fixture(scope="session")
def mock_server():
    proc = subprocess.Popen(
        ["python", "har_mock_server.py", "session.har",
         "--port", "9999", "--strict"]
    )
    time.sleep(0.5)  # let it start
    yield "http://127.0.0.1:9999"
    proc.terminate()

def test_login_flow(mock_server):
    r = requests.post(f"{mock_server}/api/auth/login",
                      json={"username": "test", "password": "x"})
    assert r.status_code == 200
    assert "access_token" in r.json()
```

### Importing as a library

```python
from har_mock_server import HarIndex

index = HarIndex("session.har")
summary = index.token_summary()

# Inject captured Bearer token into your test client
token = summary["bearer_tokens"][0]["value"]
headers = {"Authorization": f"Bearer {token}"}
```

-----

## 6. Tips

- Run `mitmdump` (not `mitmproxy`) in CI pipelines for headless capture.
- Use `--set har_redact_secrets=false` when you need real token values
  for replay (only on private, secured environments).
- Combine with `responses` or `httpretty` Python libraries if you need
  request interception inside the test process rather than a real server.
- WebSocket frame replay is stored in `_x_meta` but not yet served by
  the mock server — extend `MockHandler` with a WS upgrade handler
  if needed.

## Stack

- Python
- mitmproxy
- mitmweb
- HTML/CSS/JavaScript

## Project Structure

```text
project/
├── ssr_interceptor.py
├── web/
│   ├── index.html
│   ├── style.css
│   └── app.js
└── flows/
    └── flows.json
```

## Installation

```bash
pip install mitmproxy
```

## Run Interceptor

```bash
mitmweb -s ssr_interceptor.py
```

mitmweb UI:

```text
http://127.0.0.1:8081
```

## Run Dashboard

```bash
cd web
python -m http.server 9000
```

Dashboard:

```text
http://127.0.0.1:9000
```

## Supported Targets

- Next.js
- Nuxt.js
- Remix
- Angular Universal
- React SSR
- GraphQL APIs

## Example Use Cases

- SSR reverse engineering
- API discovery
- Traffic inspection
- Cache analysis
- Hydration debugging
- Security testing

## License
MIT
