"""Small, defensive parsers used by rule-based diagnostics."""
from __future__ import annotations

import re


def parse(name: str | None, output: str):
    fn = globals().get(f"_p_{name}") if name else None
    if fn is None:
        return None
    try:
        return fn(output)
    except Exception:
        return None


def _p_df(out: str):
    rows = []
    for line in out.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[4].endswith("%") and parts[4][:-1].isdigit():
            rows.append({"filesystem": parts[0], "use_pct": int(parts[4][:-1]), "mount": parts[5]})
    return rows


def _p_free(out: str):
    for line in out.splitlines():
        if line.startswith("Mem:"):
            p = line.split()
            total, avail = int(p[1]), int(p[6]) if len(p) > 6 else int(p[3])
            return {"total_mb": total, "available_mb": avail, "avail_pct": round(100 * avail / max(total, 1), 1)}
    return None


def _p_loadavg(out: str):
    p = out.split()
    return {"load1": float(p[0]), "load5": float(p[1]), "load15": float(p[2])}


def _p_failed_units(out: str):
    return [l.lstrip("●* \t").split()[0] for l in out.strip().splitlines() if l.lstrip("●* \t").strip()]


def _p_state_word(out: str):
    m = re.search(r"[A-Za-z-]+", out.strip().splitlines()[0] if out.strip() else "")
    return m.group(0).lower() if m else ""
