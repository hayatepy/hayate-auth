#!/usr/bin/env python3
"""Verify the frozen audit target and its deterministic evidence manifest."""

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
import tempfile
import tomllib
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TARGET_PATH = ROOT / "audit" / "target.toml"
MANIFEST_PATH = ROOT / "audit" / "manifest.json"
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


def load_target() -> dict[str, Any]:
    with TARGET_PATH.open("rb") as source:
        return tomllib.load(source)


def verify_target(target: dict[str, Any]) -> None:
    frozen = target["target"]
    tag = frozen["tag"]
    if run("git", "cat-file", "-t", tag) != "tag":
        fail(f"{tag} is not an annotated tag")
    resolved = run("git", "rev-list", "-n", "1", tag)
    if resolved != frozen["commit"]:
        fail(f"{tag} resolves to {resolved}, expected {frozen['commit']}")

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

    for path in target["scope"]["immutable_paths"]:
        result = subprocess.run(
            ["git", "diff", "--quiet", tag, "--", path],
            cwd=ROOT,
            check=False,
        )
        if result.returncode == 1:
            fail(f"frozen source path differs from {tag}: {path}")
        if result.returncode > 1:
            fail(f"git diff failed for frozen source path: {path}")

    for kind in ("wheel", "sdist"):
        artifact = target["artifacts"][kind]
        actual = sha256(download(artifact["url"]))
        if actual != artifact["sha256"]:
            fail(f"{artifact['filename']} SHA-256 is {actual}, expected {artifact['sha256']}")


def verify_asvs(target: dict[str, Any]) -> None:
    standard = target["standards"]["asvs"]
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

    expected = target["ledger"]
    actual_counts = {
        status: len(re.findall(rf"^\| .+ \| {status} \|", ledger_text, re.MULTILINE))
        for status in ("covered", "external", "gap")
    }
    if actual_counts != expected:
        fail(f"ledger counts are {actual_counts}, expected {expected}")


def verify_evidence(target: dict[str, Any]) -> None:
    for relative in target["scope"]["evidence_paths"]:
        if not (ROOT / relative).is_file():
            fail(f"evidence path does not exist: {relative}")

    collected = set(run("uv", "run", "pytest", "--collect-only", "-q").splitlines())
    missing = sorted(set(target["scope"]["test_nodes"]) - collected)
    if missing:
        fail(f"test evidence was not collected: {', '.join(missing)}")


def build_manifest(target: dict[str, Any]) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for relative in sorted(target["scope"]["manifest_files"]):
        path = ROOT / relative
        if not path.is_file():
            fail(f"manifest input does not exist: {relative}")
        data = path.read_bytes()
        files[relative] = {"bytes": len(data), "sha256": sha256(data)}
    return {
        "schema": 1,
        "target": {
            "name": target["target"]["name"],
            "version": target["target"]["version"],
            "tag": target["target"]["tag"],
            "commit": target["target"]["commit"],
        },
        "files": files,
    }


def verify_manifest(target: dict[str, Any], *, write: bool) -> None:
    expected = build_manifest(target)
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

    target = load_target()
    verify_target(target)
    verify_asvs(target)
    verify_evidence(target)
    verify_manifest(target, write=args.write)
    if args.check:
        print("audit-pack: target, standards, evidence, and manifest verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
