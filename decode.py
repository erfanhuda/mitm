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
