import json
import os
import time
from mitmproxy import http

FLOW_FILE = "flows/flows.json"

os.makedirs("flows", exist_ok=True)

flows = []

class SSRVisualizer:

    def request(self, flow: http.HTTPFlow):

        entry = {
            "id": flow.id,
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "host": flow.request.host,
            "type": "request",
        }

        flows.append(entry)

        self.save()

    def response(self, flow: http.HTTPFlow):

        content_type = flow.response.headers.get(
            "content-type", ""
        )

        entry = {
            "id": flow.id,
            "timestamp": time.time(),
            "status": flow.response.status_code,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "host": flow.request.host,
            "content_type": content_type,
            "type": "response",
        }

        flows.append(entry)

        self.save()

    def save(self):

        with open(FLOW_FILE, "w") as f:
            json.dump(flows[-300:], f, indent=2)

addons = [
    SSRVisualizer()
]