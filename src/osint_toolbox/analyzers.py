from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .case import add_artifact_bytes, add_derivation, assert_case_mutable
from .util import ensure_case, read_jsonl


ANALYZERS = {
    "exiftool": {
        "executable": "exiftool",
        "description": "Extract embedded file and media metadata as JSON.",
    },
    "ffprobe": {
        "executable": "ffprobe",
        "description": "Extract audio/video container and stream metadata as JSON.",
    },
    "tesseract": {
        "executable": "tesseract",
        "description": "Extract English OCR text locally without uploading the artifact.",
    },
    "ocrmypdf": {
        "executable": "ocrmypdf",
        "description": "Create a local searchable-PDF derivative while preserving the original PDF.",
    },
}


def _artifact(case_dir: Path, artifact_id: str) -> dict[str, object]:
    for artifact in read_jsonl(case_dir / "artifacts.jsonl"):
        if artifact.get("artifact_id") == artifact_id:
            return artifact
    raise ValueError(f"Unknown artifact ID: {artifact_id}")


def _run(command: list[str]) -> bytes:
    try:
        process = subprocess.run(
            command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("Analyzer exceeded the 300-second execution limit") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()[-1000:]
        raise ValueError(f"Analyzer failed with exit code {process.returncode}: {detail}")
    return process.stdout


def _version(tool: str, executable: str) -> str:
    if tool == "exiftool":
        command = [executable, "-ver"]
    elif tool == "ffprobe":
        command = [executable, "-version"]
    else:
        command = [executable, "--version"]
    output = _run(command).decode("utf-8", errors="replace").splitlines()
    return output[0].strip() if output else "unknown"


def analyze_artifact(
    case: str | Path,
    artifact_id: str,
    analyzer: str,
    actor: str = "operator",
) -> dict[str, object]:
    analyzer = analyzer.lower()
    if analyzer not in ANALYZERS:
        raise ValueError(f"Unknown analyzer: {analyzer}")
    case_dir = ensure_case(case)
    assert_case_mutable(case_dir)
    parent = _artifact(case_dir, artifact_id)
    executable = shutil.which(ANALYZERS[analyzer]["executable"])
    if not executable:
        raise ValueError(f"{ANALYZERS[analyzer]['executable']} is not installed or not on PATH")
    input_path = (case_dir / str(parent["stored_path"])).resolve()
    if case_dir not in input_path.parents or not input_path.is_file():
        raise ValueError(f"Artifact file is missing or outside the case: {artifact_id}")
    temporary_output = ""
    if analyzer == "exiftool":
        command = [executable, "-j", "-G1", "-a", "-s", str(input_path)]
        suffix = "json"
        mime_type = "application/json"
        topic = "derived-metadata"
        output = _run(command)
    elif analyzer == "ffprobe":
        command = [executable, "-v", "error", "-show_format", "-show_streams", "-print_format", "json", str(input_path)]
        suffix = "json"
        mime_type = "application/json"
        topic = "derived-metadata"
        output = _run(command)
    elif analyzer == "tesseract":
        command = [executable, str(input_path), "stdout", "-l", "eng"]
        suffix = "txt"
        mime_type = "text/plain"
        topic = "derived-text"
        output = _run(command)
    else:
        with tempfile.TemporaryDirectory(prefix=".ocrmypdf-", dir=case_dir / "artifacts") as temporary:
            temporary_output = str(Path(temporary) / "output.pdf")
            command = [
                executable, "--skip-text", "--output-type", "pdf", "--optimize", "0",
                str(input_path), temporary_output,
            ]
            _run(command)
            output_path = Path(temporary_output)
            if not output_path.is_file():
                raise ValueError("OCRmyPDF completed without creating an output PDF")
            output = output_path.read_bytes()
        suffix = "pdf"
        mime_type = "application/pdf"
        topic = "derived-document"
    child = add_artifact_bytes(
        case_dir, output, f"{artifact_id}-{analyzer}.{suffix}", str(parent.get("source_url", "")),
        topic,
        f"Derived from {artifact_id} using {analyzer}", actor, mime_type,
    )
    sanitized_command = []
    for part in command:
        if part == str(input_path):
            sanitized_command.append("<case-artifact>")
        elif temporary_output and part == temporary_output:
            sanitized_command.append("<derived-output>")
        else:
            sanitized_command.append(part)
    derivation = add_derivation(
        case_dir, artifact_id, str(child["artifact_id"]), analyzer, _version(analyzer, executable),
        [Path(executable).name, *sanitized_command[1:]],
        "Absolute temporary paths were replaced with placeholders in the logged command.", actor,
    )
    return {"artifact": child, "derivation": derivation}
