"""Immutable change plans: canonical serialisation + hash."""
from __future__ import annotations

import hashlib
import json


def canonicalize(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(canonical: str) -> str:
    return hashlib.sha256(canonical.encode()).hexdigest()
