"""Evidence engine: sanitisation, truncation, hashing, encrypted raw retention."""
from __future__ import annotations

import hashlib
import re

# Order matters: block patterns first.
_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([A-Za-z0-9_.-]{0,40}(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
                r"private[_-]?key)[A-Za-z0-9_.-]{0,40}\s*[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{3,})"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]{1,})@"), r"\1[REDACTED]@"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED API KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED JWT]"),
    (re.compile(r"(?i)\b(snmp-server community\s+)\S+"), r"\1[REDACTED]"),
]


def sanitize(text: str, known_secrets: tuple[str, ...] = (), max_chars: int = 64_000) -> tuple[str, bool]:
    """Return (sanitised_text, truncated)."""
    for s in known_secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "[REDACTED]")
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    text = text.replace("\x00", "")
    truncated = len(text) > max_chars
    if truncated:
        half = max_chars // 2
        text = text[:half] + f"\n...[truncated {len(text) - max_chars} chars]...\n" + text[-half:]
    return text, truncated


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
