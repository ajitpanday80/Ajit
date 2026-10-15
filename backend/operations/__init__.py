from backend.operations.registry import (  # noqa: F401
    OperationSpec, Param, RecoveryLevel, Risk, RenderedCommand, UnknownOperation, ValidationError,
    REGISTRY, get_spec, render, validate_params,
)
from backend.operations import linux, windows, voip, web, network  # noqa: F401  (register ops)
