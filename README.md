# mitm

# SSR Interceptor Visualizer

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