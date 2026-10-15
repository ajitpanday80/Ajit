"""Typed operation registry — the only vocabulary the platform can execute.

There is no "run arbitrary command" operation.  Each operation declares typed,
pattern-validated parameters, a fixed command template, its risk class and (for
mutations) its backup strategy, post-check and rollback candidates.  Connectors
accept only a ``RenderedCommand`` produced here.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable


class Risk(IntEnum):
    READ = 0
    MUTATE = 1
    DESTRUCTIVE = 2


class RecoveryLevel(IntEnum):
    NONE = 0
    EXPORT_ONLY = 1   # state captured, but no tested way to restore it
    VERIFIED = 2      # state captured and a rollback op exists and is authorised


class UnknownOperation(KeyError):
    pass


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Param:
    name: str
    kind: str = "str"                 # str | int | enum
    pattern: str | None = None        # fullmatch for str
    choices: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    default: object | None = None
    required: bool = True
    forbid: tuple[str, ...] = ()      # forbidden substrings


@dataclass(frozen=True)
class Probe:
    """A read-only operation + predicate used for preconditions, post-checks and state capture."""
    operation: str
    params: dict = field(default_factory=dict)   # values may reference step params as "{name}"
    expect: tuple = ("exit0",)                    # ("exit0",) | ("contains", s) | ("regex", p) | ("equals", s)


@dataclass(frozen=True)
class OperationSpec:
    name: str
    description: str
    risk: Risk
    device_types: frozenset
    interpreter: str                  # argv | powershell | http | cli
    params: tuple[Param, ...] = ()
    argv: tuple[str, ...] = ()        # tokens, "{param}" substituted whole-token or inline
    script: str = ""                  # powershell template
    parser: str | None = None
    success_codes: tuple[int, ...] = (0,)
    # --- mutation metadata
    backup: str | None = None         # backup strategy name
    min_recovery: RecoveryLevel = RecoveryLevel.VERIFIED
    precondition: Probe | None = None
    state_probe: Probe | None = None  # captured before/after
    verify: Probe | None = None       # post-check (may use {param})
    rollback_candidates: tuple[str, ...] = ()
    timeout: int = 30


@dataclass(frozen=True)
class RenderedCommand:
    operation: str
    interpreter: str
    argv: tuple[str, ...] = ()
    script: str = ""
    params: dict = field(default_factory=dict)
    timeout: int = 30

    @property
    def display(self) -> str:
        if self.interpreter == "powershell":
            return "powershell: " + self.script
        if self.interpreter == "http":
            return f"http {self.params.get('method', 'GET')} {self.params.get('path', '/')}"
        return " ".join(shlex.quote(a) for a in self.argv)

    @property
    def shell_line(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


REGISTRY: dict[str, OperationSpec] = {}


def register(spec: OperationSpec) -> OperationSpec:
    if spec.name in REGISTRY:
        raise ValueError(f"duplicate operation {spec.name}")
    if spec.risk == Risk.READ and (spec.backup or spec.rollback_candidates):
        raise ValueError("read operations take no backup/rollback")
    if spec.risk > Risk.READ and not (spec.backup and spec.state_probe and spec.verify):
        raise ValueError(f"mutating operation {spec.name} needs backup, state_probe and verify")
    REGISTRY[spec.name] = spec
    return spec


def get_spec(name: str) -> OperationSpec:
    try:
        return REGISTRY[name]
    except KeyError:
        raise UnknownOperation(name) from None


def validate_params(spec: OperationSpec, params: dict | None) -> dict:
    params = dict(params or {})
    known = {p.name for p in spec.params}
    extra = set(params) - known
    if extra:
        raise ValidationError(f"{spec.name}: unexpected parameters {sorted(extra)}")
    out: dict = {}
    for p in spec.params:
        if p.name not in params or params[p.name] is None:
            if p.default is not None:
                out[p.name] = p.default
                continue
            if p.required:
                raise ValidationError(f"{spec.name}: missing parameter '{p.name}'")
            continue
        v = params[p.name]
        if p.kind == "int":
            if isinstance(v, bool) or not isinstance(v, (int, str)) or not re.fullmatch(r"-?\d{1,9}", str(v)):
                raise ValidationError(f"{spec.name}.{p.name}: must be an integer")
            v = int(v)
            if (p.min is not None and v < p.min) or (p.max is not None and v > p.max):
                raise ValidationError(f"{spec.name}.{p.name}: out of range")
        elif p.kind == "enum":
            if v not in p.choices:
                raise ValidationError(f"{spec.name}.{p.name}: must be one of {list(p.choices)}")
        else:
            if not isinstance(v, str) or not v or len(v) > 255:
                raise ValidationError(f"{spec.name}.{p.name}: must be a non-empty string (<=255)")
            if p.pattern and not re.fullmatch(p.pattern, v):
                raise ValidationError(f"{spec.name}.{p.name}: invalid format")
            if any(f in v for f in p.forbid):
                raise ValidationError(f"{spec.name}.{p.name}: forbidden content")
        out[p.name] = v
    return out


def _sub(template: str, params: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(params[m.group(1)]) if m.group(1) in params else m.group(0), template)


def _ps_quote(v) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def render(spec: OperationSpec, params: dict | None) -> RenderedCommand:
    p = validate_params(spec, params)
    if spec.interpreter == "powershell":
        script = re.sub(r"\{(\w+)\}", lambda m: _ps_quote(p[m.group(1)]) if m.group(1) in p else m.group(0), spec.script)
        return RenderedCommand(spec.name, "powershell", script=script, params=p, timeout=spec.timeout)
    if spec.interpreter in ("argv", "cli"):
        return RenderedCommand(spec.name, spec.interpreter, argv=tuple(_sub(t, p) for t in spec.argv),
                               params=p, timeout=spec.timeout)
    return RenderedCommand(spec.name, spec.interpreter, params=p, timeout=spec.timeout)


def resolve_probe_params(probe: Probe, step_params: dict) -> dict:
    return {k: (_sub(v, step_params) if isinstance(v, str) else v) for k, v in probe.params.items()}


# shared validators -----------------------------------------------------------
UNIT = r"[A-Za-z0-9][A-Za-z0-9@_.:-]{0,99}\.(service|socket|timer|mount|target)|[A-Za-z0-9][A-Za-z0-9@_-]{0,99}"
HOST = r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|[0-9a-fA-F:]{2,45}"
WIN_NAME = r"[A-Za-z0-9 _.-]{1,100}"
