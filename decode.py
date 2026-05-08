import re
import hashlib

SUSPICIOUS_PATTERNS = {

    "eval": r"eval\s*\(",

    "function_packer":
        r"function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)",

    "base64":
        r"atob\s*\(|btoa\s*\(",

    "hex_encoded":
        r"\\x[0-9a-fA-F]{2}",

    "unicode_encoded":
        r"\\u[0-9a-fA-F]{4}",

    "cryptojs":
        r"CryptoJS",

    "aes":
        r"AES\.decrypt|AES\.encrypt",

    "webassembly":
        r"WebAssembly",

    "dynamic_import":
        r"import\s*\(",

    "debugger":
        r"\bdebugger\b",

    "fingerprinting":
        r"canvas|webgl|fingerprint",

    "setinterval_eval":
        r"setInterval\s*\(\s*function",

    "large_array":
        r"\[[0-9,\s]{500,}\]",

    "wasm_loader":
        r"\.wasm",

}

def response(self, flow):
    content_type = flow.response.headers.get(
    "content-type", ""
)

JS_MIME_TYPES = [
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
]

if any(mime in content_type for mime in JS_MIME_TYPES):

    js = flow.response.get_text(errors="ignore")

    print("\n========== JS ANALYSIS ==========")

    print(f"URL: {flow.request.pretty_url}")

    findings = []

    for name, pattern in SUSPICIOUS_PATTERNS.items():

        if re.search(pattern, js, re.IGNORECASE):

            findings.append(name)

    if findings:

        print("[+] Suspicious Patterns Detected")

        for item in findings:
            print(f"    - {item}")

    # Entropy estimation
    entropy_score = len(set(js)) / max(len(js), 1)

    if entropy_score > 0.30:
        print("[+] High entropy JS detected")

    # SHA256 fingerprint
    sha256 = hashlib.sha256(
        js.encode(errors="ignore")
    ).hexdigest()

    print(f"[+] SHA256: {sha256}")

    # Very long lines
    long_lines = max(
        [len(line) for line in js.splitlines()] or [0]
    )

    if long_lines > 2000:
        print("[+] Minified/Packed JS likely")

    # Save suspicious JS
    if findings:

        filename = f"flows/js_{flow.id}.js"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(js)

        print(f"[+] Saved suspicious JS: {filename}")
