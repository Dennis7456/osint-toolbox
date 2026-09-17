from __future__ import annotations

import json
import sysconfig
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_FILENAMES = {
    "case": "case.schema.json",
    "record": "record.schema.json",
}

FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _is_timezone_aware_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.tzinfo is not None


def _schema_directory() -> Path:
    module_path = Path(__file__).resolve()
    candidates = [
        module_path.parents[2] / "schemas",
        module_path.parents[1] / "share" / "osint-toolbox" / "schemas",
        Path(sysconfig.get_path("data")) / "share" / "osint-toolbox" / "schemas",
    ]
    for directory in candidates:
        if all((directory / filename).is_file() for filename in SCHEMA_FILENAMES.values()):
            return directory
    searched = ", ".join(str(path) for path in candidates)
    raise RuntimeError(f"OSINT Toolbox runtime schemas were not found; searched: {searched}")


@lru_cache(maxsize=2)
def _validator(kind: str) -> Draft202012Validator:
    if kind not in SCHEMA_FILENAMES:
        raise ValueError(f"Unknown schema kind: {kind}")
    path = _schema_directory() / SCHEMA_FILENAMES[kind]
    with path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FORMAT_CHECKER)


def validation_issues(kind: str, value: Any) -> list[str]:
    errors = sorted(
        _validator(kind).iter_errors(value),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    issues: list[str] = []
    for error in errors:
        location = "$"
        for part in error.absolute_path:
            location += f"[{part}]" if isinstance(part, int) else f".{part}"
        issues.append(f"{location}: {error.message}")
    return issues


def validate_or_raise(kind: str, value: Any, label: str) -> None:
    issues = validation_issues(kind, value)
    if issues:
        raise ValueError(f"{label} failed JSON Schema validation: " + "; ".join(issues))
