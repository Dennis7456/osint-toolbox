from __future__ import annotations

import os
import shutil
import subprocess
import sys
import sysconfig
from importlib.util import find_spec
from importlib.metadata import PackageNotFoundError, distribution
from importlib.resources import files
from pathlib import Path
from typing import Any

from .locking import LOCK_BACKEND


def _distributed_asset_available(name: str, project_root: Path | None = None) -> bool:
    source_root = project_root or Path(__file__).resolve().parents[2]
    candidates = [
        source_root / name,
        Path(sysconfig.get_path("data")) / "share" / "osint-toolbox" / name,
    ]
    try:
        installed_distribution = distribution("osint-toolbox")
        candidates.append(Path(installed_distribution.locate_file("share/osint-toolbox/" + name)))
    except PackageNotFoundError:
        pass
    return any(path.is_file() for path in candidates)


def system_check() -> dict[str, Any]:
    commands = {}
    for name in ("docker", "exiftool", "ffprobe", "tesseract", "ocrmypdf", "pdftotext", "sherlock", "openssl"):
        path = shutil.which(name)
        commands[name] = {"available": bool(path), "path": path or ""}
    compose_available = False
    if commands["docker"]["available"]:
        check = subprocess.run(
            [commands["docker"]["path"], "compose", "version"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        compose_available = check.returncode == 0
    resource_root = files("osint_toolbox").joinpath("data")
    package_files = {
        name: resource_root.joinpath(name).is_file()
        for name in ("tools.json", "query_recipes.json", "workflows.json")
    }
    expected_assets = {
        "schemas/case.schema.json",
        "schemas/record.schema.json",
        "templates/redaction-policy.json",
        "deploy/compose.yaml",
    }
    project_root = Path(__file__).resolve().parents[2]
    distributed_assets = {
        name: _distributed_asset_available(name, project_root)
        for name in sorted(expected_assets)
    }
    return {
        "python": {
            "version": ".".join(str(item) for item in sys.version_info[:3]),
            "supported": sys.version_info >= (3, 11),
        },
        "package_files": package_files,
        "distributed_assets": distributed_assets,
        "commands": commands,
        "python_packages": {
            "jsonschema": find_spec("jsonschema") is not None,
            "reportlab": find_spec("reportlab") is not None,
        },
        "case_locking": LOCK_BACKEND,
        "docker_compose": compose_available,
        "searxng": {
            "adapter_url_configured": bool(os.environ.get("OSINT_SEARXNG_URL")),
            "local_settings_present": (Path.cwd() / "deploy/searxng/settings.yml").is_file(),
        },
        "network_checks_performed": False,
    }


def render_system_check(check: dict[str, Any]) -> str:
    lines = [
        f"Python {check['python']['version']}: {'PASS' if check['python']['supported'] else 'FAIL (3.11+ required)'}",
        f"Package files: {'PASS' if all(check['package_files'].values()) else 'FAIL'}",
        f"Distributed assets: {'PASS' if all(check['distributed_assets'].values()) else 'FAIL'}",
        f"Runtime JSON Schema: {'available' if check['python_packages']['jsonschema'] else 'FAIL'}",
        f"Case locking: {check['case_locking']}",
        f"Docker Compose: {'available' if check['docker_compose'] else 'not available'}",
        f"SearXNG adapter URL: {'configured' if check['searxng']['adapter_url_configured'] else 'not configured'}",
        f"Local SearXNG settings: {'present' if check['searxng']['local_settings_present'] else 'not created (optional)'}",
        f"PDF reporting: {'available' if check['python_packages']['reportlab'] else 'not installed (install osint-toolbox[pdf])'}",
        "Local analyzers:",
    ]
    for name in ("exiftool", "ffprobe", "tesseract", "ocrmypdf", "pdftotext"):
        state = check["commands"][name]
        lines.append(f"  {name:<10} {'available' if state['available'] else 'not installed'}")
    lines.extend([
        f"Sherlock runner: {'available' if check['commands']['sherlock']['available'] else 'not installed (optional)'}",
        f"Ed25519 signing: {'available' if check['commands']['openssl']['available'] else 'not installed (OpenSSL required)'}",
    ])
    lines.append("Network checks: not performed")
    return "\n".join(lines)
