#!/usr/bin/env python3
"""Verify the immutable audit base, current amendment, and evidence manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = ROOT / "audit"
CURRENT_PATH = AUDIT_DIR / "current.toml"
MANIFEST_PATH = AUDIT_DIR / "manifest.json"
ASVS_REFERENCE = re.compile(r"\bv5\.0\.0-(\d+\.\d+\.\d+)\b")


def fail(message: str) -> None:
    raise SystemExit(f"audit-pack: {message}")


def run(*args: str) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        fail(f"{' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "hayate-auth-audit-pack/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except Exception as exc:
        fail(f"could not download {url}: {exc}")


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


def referenced_audit_path(value: str) -> Path:
    candidate = (AUDIT_DIR / value).resolve()
    if not candidate.is_relative_to(AUDIT_DIR.resolve()):
        fail(f"audit reference escapes audit/: {value}")
    if not candidate.is_file():
        fail(f"audit reference does not exist: {value}")
    return candidate


def load_review() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    current = load_toml(CURRENT_PATH)
    if current.get("schema") != 1:
        fail("audit/current.toml has an unsupported schema")
    base = load_toml(referenced_audit_path(current["base"]))
    amendment = load_toml(referenced_audit_path(current["amendment"]))
    for field in ("version", "tag", "commit"):
        if amendment["base"][field] != base["target"][field]:
            fail(f"amendment base {field} does not match the frozen base target")
    return current, base, amendment


def verify_target(target: dict[str, Any], *, label: str) -> None:
    frozen = target["target"]
    tag = frozen["tag"]
    if run("git", "cat-file", "-t", tag) != "tag":
        fail(f"{label} {tag} is not an annotated tag")
    resolved = run("git", "rev-list", "-n", "1", tag)
    if resolved != frozen["commit"]:
        fail(f"{label} {tag} resolves to {resolved}, expected {frozen['commit']}")

    with tempfile.TemporaryDirectory(prefix="hayate-auth-audit-gpg-") as gnupg_home:
        env = {**os.environ, "GNUPGHOME": gnupg_home}
        key = ROOT / "audit" / "maintainer-signing-key.asc"
        imported = subprocess.run(
            ["gpg", "--batch", "--import", str(key)],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        if imported.returncode:
            fail(f"could not import pinned signing key:\n{imported.stdout}{imported.stderr}")
        fingerprints = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--fingerprint"],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        if fingerprints.returncode:
            fail("could not inspect pinned signing key")
        primary = frozen["primary_signing_key_fingerprint"]
        if f"fpr:::::::::{primary}:" not in fingerprints.stdout:
            fail(f"pinned key does not contain primary fingerprint {primary}")
        verified = subprocess.run(
            ["git", "verify-tag", "--raw", tag],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        signature_status = verified.stdout + verified.stderr
        subkey = frozen["tag_signing_subkey_fingerprint"]
        if verified.returncode or f"[GNUPG:] VALIDSIG {subkey} " not in signature_status:
            fail(f"{tag} does not have a valid signature from pinned subkey {subkey}")

    for kind, artifact in sorted(target["artifacts"].items()):
        actual = sha256(download(artifact["url"]))
        if actual != artifact["sha256"]:
            fail(
                f"{label} {kind} {artifact['filename']} SHA-256 is {actual}, "
                f"expected {artifact['sha256']}"
            )


def verify_asvs(base: dict[str, Any], amendment: dict[str, Any]) -> None:
    standard = base["standards"]["asvs"]
    data = download(standard["url"])
    actual = sha256(data)
    if actual != standard["sha256"]:
        fail(f"official ASVS CSV SHA-256 is {actual}, expected {standard['sha256']}")

    rows = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    official_ids = {row["req_id"] for row in rows}
    ledger_text = (ROOT / "docs" / "asvs.md").read_text(encoding="utf-8")
    references = set(ASVS_REFERENCE.findall(ledger_text))
    if not references:
        fail("docs/asvs.md has no versioned ASVS references")
    unknown = sorted(f"v5.0.0-{req}" for req in references if f"V{req}" not in official_ids)
    if unknown:
        fail(f"unknown ASVS references: {', '.join(unknown)}")

    expected = amendment["ledger"]
    actual_counts = {
        status: len(re.findall(rf"^\| .+ \| {status} \|", ledger_text, re.MULTILINE))
        for status in ("covered", "external", "gap")
    }
    if actual_counts != expected:
        fail(f"ledger counts are {actual_counts}, expected {expected}")


def verify_evidence(target: dict[str, Any], *, label: str) -> None:
    tag = target["target"]["tag"]
    archive = subprocess.run(
        ["git", "archive", "--format=tar", tag],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if archive.returncode:
        fail(f"could not export {label} evidence tree {tag}: {archive.stderr.decode()}")

    with tempfile.TemporaryDirectory(prefix="hayate-auth-audit-target-") as target_dir:
        with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as source:
            source.extractall(target_dir, filter="data")
        frozen_root = Path(target_dir)
        for relative in target["scope"]["evidence_paths"]:
            if not (frozen_root / relative).is_file():
                fail(f"{label} evidence path does not exist in {tag}: {relative}")
        result = subprocess.run(
            ["uv", "run", "--locked", "pytest", "--collect-only", "-q"],
            cwd=frozen_root,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            fail(f"could not collect {label} tests from {tag}:\n{result.stdout}{result.stderr}")
        collected = set(result.stdout.splitlines())
    missing = sorted(set(target["scope"]["test_nodes"]) - collected)
    if missing:
        fail(f"{label} test evidence was not collected: {', '.join(missing)}")


def target_identity(target: dict[str, Any]) -> dict[str, str]:
    return {field: target["target"][field] for field in ("name", "version", "tag", "commit")}


def build_manifest(
    current: dict[str, Any],
    base: dict[str, Any],
    amendment: dict[str, Any],
) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    manifest_files = set(base["scope"]["manifest_files"])
    manifest_files.update(current["scope"]["manifest_files"])
    for relative in sorted(manifest_files):
        path = ROOT / relative
        if not path.is_file():
            fail(f"manifest input does not exist: {relative}")
        data = path.read_bytes()
        files[relative] = {"bytes": len(data), "sha256": sha256(data)}
    return {
        "schema": 2,
        "base": target_identity(base),
        "review_target": target_identity(amendment),
        "files": files,
    }


def verify_manifest(
    current: dict[str, Any],
    base: dict[str, Any],
    amendment: dict[str, Any],
    *,
    write: bool,
) -> None:
    expected = build_manifest(current, base, amendment)
    serialized = json.dumps(expected, indent=2, sort_keys=True) + "\n"
    if write:
        MANIFEST_PATH.write_text(serialized, encoding="utf-8")
        print(f"wrote {MANIFEST_PATH.relative_to(ROOT)}")
        return
    if not MANIFEST_PATH.is_file():
        fail("audit/manifest.json is missing; run with --write")
    if MANIFEST_PATH.read_text(encoding="utf-8") != serialized:
        fail("audit/manifest.json is stale; review changes and run with --write")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify the committed manifest")
    mode.add_argument("--write", action="store_true", help="regenerate the manifest")
    args = parser.parse_args()

    current, base, amendment = load_review()
    verify_target(base, label="base")
    verify_target(amendment, label="review target")
    verify_asvs(base, amendment)
    verify_evidence(base, label="base")
    verify_evidence(amendment, label="review target")
    verify_manifest(current, base, amendment, write=args.write)
    if args.check:
        print("audit-pack: base, review target, standards, evidence, and manifest verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
