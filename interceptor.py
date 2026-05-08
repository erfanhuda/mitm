import json
import re
from mitmproxy import http

SSR_FRAMEWORK_HEADERS = [
    "x-nextjs-cache",
    "x-powered-by",
    "x-vercel-cache",
    "server",
]

SSR_PATTERNS = [
    "__NEXT_DATA__",
    "__NUXT__",
    "window.__INITIAL_STATE__",
    "window.__PRELOADED_STATE__",
]

API_PATTERNS = [
    "/api/",
    "/graphql",
    "/_next/data/",
]

class SSRInterceptor:

    def request(self, flow: http.HTTPFlow):

        request = flow.request

        print("\n========== REQUEST ==========")
        print(f"URL: {request.pretty_url}")
        print(f"Method: {request.method}")

        # Detect SSR API requests
        for pattern in API_PATTERNS:
            if pattern in request.path:
                print(f"[+] SSR API Detected: {request.path}")

        # Log cookies
        if "cookie" in request.headers:
            print("[+] Cookies:")
            print(request.headers["cookie"])

        # Add custom header
        request.headers["X-Intercepted"] = "mitmproxy"

        # Force no-cache
        request.headers["Cache-Control"] = "no-cache"

    def response(self, flow: http.HTTPFlow):

        response = flow.response
        request = flow.request

        content_type = response.headers.get("content-type", "")

        print("\n========== RESPONSE ==========")
        print(f"Status: {response.status_code}")
        print(f"URL: {request.pretty_url}")

        # Detect SSR framework
        for header in SSR_FRAMEWORK_HEADERS:
            if header in response.headers:
                print(f"[+] SSR Header: {header}")
                print(f"    {response.headers[header]}")

        # Process HTML pages
        if "text/html" in content_type:

            html = response.get_text(errors="ignore")

            # Detect hydration payloads
            for pattern in SSR_PATTERNS:
                if pattern in html:
                    print(f"[+] SSR Hydration Found: {pattern}")

            # Extract Next.js hydration data
            next_data_match = re.search(
                r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>',
                html,
                re.DOTALL,
            )

            if next_data_match:
                try:
                    next_data = json.loads(next_data_match.group(1))

                    print("[+] NEXT_DATA Extracted")

                    page = next_data.get("page")
                    build_id = next_data.get("buildId")

                    print(f"    Page: {page}")
                    print(f"    Build ID: {build_id}")

                    # Extract props
                    props = next_data.get("props", {})
                    print(f"    Props Keys: {list(props.keys())}")

                except Exception as e:
                    print(f"[!] Parse Error: {e}")

            # Inject banner into HTML
            modified_html = html.replace(
                "</body>",
                """
                <div style="
                    position:fixed;
                    top:0;
                    left:0;
                    width:100%;
                    background:red;
                    color:white;
                    z-index:9999;
                    padding:5px;
                    text-align:center;
                ">
                    Intercepted by mitmproxy
                </div>
                </body>
                """
            )

            response.set_text(modified_html)

        # Process JSON APIs
        elif "application/json" in content_type:

            try:
                data = response.json()

                print("[+] JSON API Response")

                if isinstance(data, dict):
                    print(f"Keys: {list(data.keys())[:10]}")

            except Exception:
                pass


addons = [
    SSRInterceptor()
]