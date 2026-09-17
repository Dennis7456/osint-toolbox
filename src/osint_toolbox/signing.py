from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .exports import verify_bundle
from .util import read_json, sha256_bytes, sha256_file, utc_now, write_json


SIGNATURE_FORMAT = "osint-toolbox.bundle-signature/1"
PASSWORD_ENVIRONMENT = "OSINT_SIGNING_KEY_PASSWORD"


def _openssl() -> str:
    executable = shutil.which("openssl")
    if not executable:
        raise ValueError("Bundle signing requires OpenSSL on PATH")
    return executable


def _run(command: list[str], timeout: int = 30) -> bytes:
    try:
        process = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Signing command could not complete: {Path(command[0]).name}") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()[-1000:]
        raise ValueError(f"Signing command failed with exit code {process.returncode}: {detail}")
    return process.stdout


def _password_arguments() -> list[str]:
    if os.environ.get(PASSWORD_ENVIRONMENT):
        return ["-passin", f"env:{PASSWORD_ENVIRONMENT}"]
    return []


def _manifest_bytes(bundle: Path) -> bytes:
    try:
        with zipfile.ZipFile(bundle, "r") as archive:
            return archive.read("MANIFEST.json")
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise ValueError(f"Bundle manifest could not be read: {exc}") from exc


def sign_bundle_manifest(
    bundle: str | Path,
    private_key: str | Path,
    output: str | Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    bundle_path = Path(bundle).expanduser().resolve()
    key_path = Path(private_key).expanduser().resolve()
    if not key_path.is_file():
        raise ValueError(f"Private key is not a file: {key_path}")
    valid, issues = verify_bundle(bundle_path)
    if not valid:
        raise ValueError("Bundle integrity verification failed before signing: " + "; ".join(issues))
    openssl = _openssl()
    password_args = _password_arguments()
    key_description = _run([openssl, "pkey", "-in", str(key_path), *password_args, "-text_pub", "-noout"])
    if b"ED25519" not in key_description.upper():
        raise ValueError("Bundle signing requires an Ed25519 private key")
    public_der = _run([openssl, "pkey", "-in", str(key_path), *password_args, "-pubout", "-outform", "DER"])
    manifest = _manifest_bytes(bundle_path)
    with tempfile.TemporaryDirectory(prefix="osint-signature-") as temporary:
        manifest_path = Path(temporary) / "MANIFEST.json"
        signature_path = Path(temporary) / "MANIFEST.sig"
        manifest_path.write_bytes(manifest)
        _run([
            openssl,
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key_path),
            *password_args,
            "-rawin",
            "-in",
            str(manifest_path),
            "-out",
            str(signature_path),
        ])
        signature = signature_path.read_bytes()
    metadata: dict[str, Any] = {
        "signature_format": SIGNATURE_FORMAT,
        "algorithm": "Ed25519",
        "signature_encoding": "base64",
        "signed_at_utc": utc_now(),
        "bundle_file": bundle_path.name,
        "bundle_sha256": sha256_file(bundle_path),
        "manifest_member": "MANIFEST.json",
        "manifest_sha256": sha256_bytes(manifest),
        "public_key_der_sha256": sha256_bytes(public_der),
        "signature": base64.b64encode(signature).decode("ascii"),
        "signing_tool": _run([openssl, "version"]).decode("utf-8", errors="replace").strip()[:300],
    }
    destination = (
        Path(output).expanduser().resolve()
        if output
        else bundle_path.with_suffix(bundle_path.suffix + ".signature.json")
    )
    write_json(destination, metadata)
    return destination, metadata


def verify_bundle_signature(
    bundle: str | Path,
    signature_file: str | Path,
    public_key: str | Path,
) -> tuple[bool, list[str]]:
    bundle_path = Path(bundle).expanduser().resolve()
    signature_path = Path(signature_file).expanduser().resolve()
    public_key_path = Path(public_key).expanduser().resolve()
    issues: list[str] = []
    valid_bundle, bundle_issues = verify_bundle(bundle_path)
    issues.extend(f"Bundle integrity: {issue}" for issue in bundle_issues)
    if not signature_path.is_file():
        issues.append(f"Signature metadata is not a file: {signature_path}")
    if not public_key_path.is_file():
        issues.append(f"Public key is not a file: {public_key_path}")
    if issues:
        return False, issues
    try:
        metadata = read_json(signature_path)
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"Signature metadata could not be read: {exc}"]
    if not isinstance(metadata, dict):
        return False, ["Signature metadata must be a JSON object"]
    if metadata.get("signature_format") != SIGNATURE_FORMAT:
        issues.append("Unsupported signature metadata format")
    if metadata.get("algorithm") != "Ed25519" or metadata.get("signature_encoding") != "base64":
        issues.append("Signature metadata does not declare Ed25519/base64")
    if metadata.get("bundle_file") != bundle_path.name:
        issues.append("Signature metadata names a different bundle")
    if metadata.get("bundle_sha256") != sha256_file(bundle_path):
        issues.append("Bundle SHA-256 does not match signature metadata")
    try:
        manifest = _manifest_bytes(bundle_path)
    except ValueError as exc:
        return False, [str(exc)]
    if metadata.get("manifest_sha256") != sha256_bytes(manifest):
        issues.append("Manifest SHA-256 does not match signature metadata")
    try:
        signature = base64.b64decode(str(metadata.get("signature", "")), validate=True)
    except (ValueError, TypeError):
        signature = b""
        issues.append("Signature value is not valid base64")
    if not signature:
        issues.append("Signature value is empty")
    try:
        openssl = _openssl()
        public_der = _run([
            openssl, "pkey", "-pubin", "-in", str(public_key_path), "-pubout", "-outform", "DER"
        ])
    except ValueError as exc:
        issues.append(str(exc))
        return False, issues
    if metadata.get("public_key_der_sha256") != sha256_bytes(public_der):
        issues.append("Public-key fingerprint does not match signature metadata")
    if issues:
        return False, issues
    with tempfile.TemporaryDirectory(prefix="osint-signature-verify-") as temporary:
        manifest_path = Path(temporary) / "MANIFEST.json"
        raw_signature_path = Path(temporary) / "MANIFEST.sig"
        manifest_path.write_bytes(manifest)
        raw_signature_path.write_bytes(signature)
        try:
            process = subprocess.run(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key_path),
                    "-rawin",
                    "-in",
                    str(manifest_path),
                    "-sigfile",
                    str(raw_signature_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, [f"Signature verification could not complete: {exc}"]
    if process.returncode != 0:
        issues.append("Ed25519 signature verification failed")
    return valid_bundle and not issues, issues
