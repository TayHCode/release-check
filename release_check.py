#!/usr/bin/env python3
"""Conservative, local release auditing. Python 3.11+, Git, no runtime packages."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import fnmatch
import hashlib
import html
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
if sys.version_info < (3, 11):
    version = ".".join(str(part) for part in sys.version_info[:3])
    message = f"release-check needs Python 3.11 or newer; you have {version}. See README Quickstart for the no-admin uv/Python 3.12 route."
    if "--json" in sys.argv[1:]:
        print(json.dumps({"ready": False, "error": "audit-incomplete", "code": "python-version", "verdict": "INCOMPLETE", "message": message}), file=sys.stderr)
    else:
        print(message, file=sys.stderr)
    raise SystemExit(2)
import tomllib
import tokenize
import unicodedata

VERSION = "0.3.0"
PASS_LIMITATIONS = "This is not a complete secret scanner. Encoded, split or obfuscated secrets or personal data may be missed, as may unlisted names. Run a dedicated secret scanner too and read the export yourself before publishing."
BLOCKED_EXPORT_WARNING = "EXPORT BLOCKED: the requested destination was not created. The *.BLOCKED folder is a plain private folder, not a Git repository, and may contain credentials or personal data. Read README-BLOCKED.txt. Do not publish it or run git init in it; delete it after fixing the source, then export to a new folder."
AUDIT_RECORD = "release-check-audit.json"
BLOCKED_README = "README-BLOCKED.txt"
MISSING_EXECUTABLE_OUTPUT = b"Declared executable was not found in the verification environment."
MEDIA = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".pdf", ".mp4", ".mov", ".wav", ".mp3", ".heic"}
GENERATED = {".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build"}
DEFAULT_EXCLUDES = [".git", ".env", ".env.*", "*.env", ".npmrc", "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*", "*.pem", "*.key", "*.p12", "*.pfx", "credentials*", "*token.json", ".git-credentials", ".netrc", ".pgpass", ".htpasswd", "kubeconfig", ".pypirc", "*.jks", "*.keystore", "terraform.tfstate", "*.tfstate", ".docker/config.json", "keystore.properties", ".kube/config"]
EXPORT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
PATTERNS = {
    "email": r'''(?<![\w.+-])(?:[\w.+-]+|"[^"\r\n]+")@[\w.-]+\.[a-zA-Z]{2,}(?![\w.-])''',
    "phone": r"(?<!\w)(?:(?:\+|00)\d(?:[ .-]?\d){7,14}|[2-9]\d{9}|0\d{3,4}[ .-]\d{6}|(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4})(?!\w)",
    "home-path": r"(?:/(?:mnt/home|home|Volumes)/[^/\s\"'<>]+|/Users/[^/\s\"'<>]+|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"'<>]+|\\\\[\w.-]+\\home\\[^\\/\s\"'<>]+|(?<![\w~])~[A-Za-z0-9_.-]+/)",
    "tailnet-host": r"\b[\w.-]+\.ts\.net\b",
    "mac-address": r"(?<![\w:.-])(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})(?![\w:.-])|(?i:\b(?:MAC|NIC)\s+([0-9a-f]{12})\b)",
    "internal-host": r"(?<![\w.-])(?:[\w-]+(?:\.[\w-]+)*\.(?:internal|local|lan|corp|intranet|private|test|localdomain|home(?:\.arpa)?)(?:\.[\w-]+)*|[a-z][a-z-]*-\d{2})(?![\w.-]|\()|\\\\[\w.-]+\\[\w$.-]+",
    "private-repo-url": r"(?:https?://|git@)(?:gitlab|github|git|gitea)\.(?:internal|local|lan|corp)[^\s\"'<>]*",
}
SECRET_PATTERNS = {
    "private-key": r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    "github-token": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
    "aws-key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "api-key": r"\b(?:sk-(?:proj-|ant-api\d+-)?(?=[A-Za-z0-9_-]*[A-Z0-9])[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{15,})\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    "credential-url": r"[a-z][a-z0-9+.-]*://(?:[^\s/:@]*:[^\s/@]+|[^\s/:@]{20,})@[^\s]+",
    "assigned-secret": r'''(?i)(?<![\w-])["']?[a-z0-9_-]*(?:password|passwd|pass|pwd|secret|token|credential|auth|private[_-]?key|access[_-]?key|api[_-]?key|key|client[_-]?key[_-]?data|certificate[_-]?key[_-]?data|private[_-]?key[_-]?id)["']?\s*(?::|=(?!=))\s*("[^"\r\n]*"|'[^'\r\n]*'|[^\s"',;}\]]+)''',
    "provider-token": r"\b(?:glpat-[A-Za-z0-9_-]{20,}|shp(?:at|ca)_[a-fA-F0-9]{32}|sq0(?:atp|csp)-[A-Za-z0-9_-]{20,}|dop_v1_[a-fA-F0-9]{64}|key-[a-fA-F0-9]{32}|(?:SK|AC)[a-fA-F0-9]{32}|\d{6,12}:AA[A-Za-z0-9_-]{33,35}|[a-fA-F0-9]{32}-us\d+|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}|whsec_[A-Za-z0-9]{20,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,})(?![A-Za-z0-9_-])",
    "basic-auth": r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}",
    "curl-auth": r'''(?i)\bcurl\b[^\r\n]*?\s(?:-u|--user)(?:\s+|=)["']?[^\s:"']+:[^\s"']+''',
    "cli-secret": r'''(?i)(?:--(?:password|passwd|pwd|secret|token|credential|auth|api[-_]key)(?:\s+|=)|\bsshpass\s+-p\s*|\bmysql\b[^\r\n]*?\s-p|(?<![\w-])-p(?=[A-Za-z0-9+/=_-]{8,}\b))("[^"\r\n]*"|'[^'\r\n]*'|[^\s"';]+)''',
    "xml-secret": r"(?i)<(?:password|passwd|pass|pwd|secret|token|credential|auth|private[_-]?key|access[_-]?key|api[_-]?key)>([^<\r\n]+)</",
    "prose-secret": r'''(?i)\b(?:password|passwd|pass|pwd|secret|token|credential|auth|key)\s+(?:is\s+)?("[^"\r\n]*"|'[^'\r\n]*'|[^\s"'<>;]+)''',
    "password-hash": r"\$(?:apr1|2[aby]|6)\$[^\s\"']+",
    "pgpass": r"(?m)^[^:#\s]+:(?:\d+|\*):[^:\s]+:[^:\s]+:[^\s]+$",
    "netrc-password": r'''(?i)(?:\b(?:machine|login)\s+[^\r\n]+?\bpassword\s+|^\s*password\s+)(?!is\s|[:=])("[^"\r\n]*"|'[^'\r\n]*'|\S+)''',
    "context-secret": r"(?<![\w])[a-fA-F0-9]{32}(?![\w])",

    "webhook-url": r"https://(?:hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9_-]+|(?:discord(?:app)?\.com)/api(?:/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+|[\w.-]+\.webhook\.office\.com/webhookb2/[^\s\"'<>]+)",
    "bearer": r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{16,})",
}


ROLES = {"quickstart", "tests", "lint", "types", "build", "syntax"}
GROUPS = [
    ("private terms", lambda f: f["kind"] == "denylist"),
    ("emails", lambda f: f["kind"] == "email"),
    ("IP addresses", lambda f: f["kind"] in {"ipv4", "ipv6", "tailnet-ip", "mac-address"}),
    ("internal host names", lambda f: f["kind"] in {"internal-host", "tailnet-host"}),
    ("home paths", lambda f: f["kind"] == "home-path"),
    ("credentials", lambda f: f["category"] == "secrets"),
    ("phone numbers", lambda f: f["kind"] == "phone"),
    ("private repository references", lambda f: f["kind"] == "private-repo-url"),
    ("license and attribution", lambda f: f["category"] == "license"),
    ("verification", lambda f: f["scope"] == "verification"),
    ("documentation and tests", lambda f: f["category"] == "quality"),
    ("media and binary files", lambda f: f["category"] == "media"),
    ("scan coverage", lambda f: f["category"] == "coverage"),
]
HISTORY_FIX = "This is in old commits or commit metadata and cannot be fixed by editing files. Make a one-commit copy with --export, then scan and verify that copy."
FIXES: dict[str, str] = {
    "denylist": "Remove or replace the private term at this line. Term hits cannot be approved.",
    "email": "Remove the address or replace it with a role address you want public. If it is a deliberate public example, approve it in release-check.json.",
    "phone": "Remove the number, or approve it in release-check.json if it is a deliberate example.",
    "ipv4": "Replace the address with a documentation address or a placeholder. Approve loopback or documentation addresses in release-check.json.",
    "ipv6": "Replace the address with a documentation address or a placeholder. Approve loopback or documentation addresses in release-check.json.",
    "tailnet-ip": "Replace the address with a documentation address or a placeholder. Approve loopback or documentation addresses in release-check.json.",
    "mac-address": "Remove the hardware address or approve this exact deliberate example in release-check.json.",
    "internal-host": "Replace the host name with a placeholder. Approve it in release-check.json only if it is not a real machine.",
    "tailnet-host": "Replace the host name with a placeholder. Approve it in release-check.json only if it is not a real machine.",
    "home-path": "Replace the path with a relative path or a placeholder.",
    "private-repo-url": "Remove the reference to the private repository.",
    **dict.fromkeys(SECRET_PATTERNS, "Remove the credential and revoke it at the provider. Deleting the text does not make it safe. Credential findings cannot be approved."),
    "entropy": "This looks like a random secret. Remove it, or split it so it no longer looks like one. It cannot be approved.",
    "credential-file": "Do not ship this file. Delete it or add it to the manifest exclusions, and revoke anything it held.",
    "manual-review": "Open the file, check what it shows and its embedded metadata, then approve this exact file in release-check.json.",
    "binary-review": "The tool cannot read this file. Confirm it must ship, then approve this exact file or exclude it.",
    "lfs-content-not-scanned": "Large-file content is stored elsewhere and was not scanned. Replace the pointer with the real file or exclude it.",
    "symlink": "Links are never followed or exported. Replace the link with a real file or remove it.",
    "unreadable": "The file could not be read. Fix its permissions or remove it.",
    "missing-tracked-file": "A tracked file is missing from the folder. Restore it or commit its removal.",
    "shallow-history": "The clone has partial history. Use a full clone so old commits can be scanned.",
    "no-commits": "The repository has no commits. Commit the files first.",
    "submodule": "Submodules are not scanned or exported. Remove the submodule or vendor the code with its license.",
    "unsupported-file": "This entry is not a regular file and was left out of the export. Replace it with a regular file or remove it.",
    "missing-license": "Add a LICENSE file. Only standard MIT or canonical Apache-2.0 text passes automatically.",
    "unrecognized-or-modified-license": "Restore standard MIT or canonical Apache-2.0 wording. Other or modified license terms do not pass automatically.",
    "invalid-license-owner-disposition": "Supply the exact reviewed upstream URL, full commit, verbatim LICENSE hash and three differences. Keep the upstream file unchanged; malformed or mismatched dispositions block.",
    "license-metadata-mismatch": "Make the license field in pyproject.toml match the LICENSE file.",
    "dynamic-license-or-dependencies": "Declare the license and dependencies as fixed values in pyproject.toml.",
    "dependency-ecosystem-manual-review": "This tool can only check Python dependency licenses. Review this ecosystem's dependency licenses by hand.",
    "vendored-attribution-review": "Confirm every vendored project keeps its license and notice.",
    "excluded-attribution": "A license or notice file is excluded from the export. Remove that exclusion.",
    "dependency-license-review": "This dependency's license is unknown, incompatible or lacks a license file. Replace it or record evidence under dependency_licenses.",
    "dependency-metadata-failed": "Installed package metadata could not be read. Check that the project installs cleanly.",
    "historical-attribution-missing": "A license or notice file from history is missing. Restore it.",
    "historical-attribution-changed": "Attribution text from history was removed. Restore the original lines.",
    "missing-document": "Create this file. A README says what the tool does, how to install it, one usage example and its limitations.",
    "missing-issue-templates": "Add a Markdown issue template (.md) or YAML issue form (.yml or .yaml) under .github/ISSUE_TEMPLATE.",
    "missing-limitations": "Add a README heading that contains \"Limitations\" and say plainly where the tool fails.",
    "missing-tests": "Add at least one test file matching tests/test*.py.",
    "quickstart-not-declared": "List the README install and first-run commands under quickstart in release-check.json.",
    "test-command-not-declared": "Add a check with role \"tests\" to release-check.json.",
    "configured-check-not-declared": "A lint or type tool is configured but has no matching check in release-check.json. Add it.",
    "verification-not-configured": "Declare quickstart and checks in release-check.json so they can be run.",
    "verification-not-run": "Run again with --verify to execute the declared commands in a clean clone.",
    "quickstart-document-mismatch": "The command in release-check.json differs from that line of the document. Make them identical.",
    "quickstart-document-missing": "The document named in the quickstart entry does not exist. Create it or correct the entry.",
    "venv-creation-failed": "Verification could not create a venv; quickstart and tests did not run. No-admin fix: install uv into your home using the official script and re-run --verify, or use --verify-no-venv if the manifest declares stdlib_only. Details: Linux/macOS: curl -LsSf https://astral.sh/uv/install.sh | sh; Windows PowerShell: powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\". Follow the installer PATH instructions, then re-run the same command. Verification tried python -m venv, available uv venv and virtualenv with pip. An administrator can install the matching python3-venv package on Debian/Ubuntu, Python via Homebrew on macOS, or Python via winget on Windows. This run did not execute the quickstart or tests.",
    "no-venv-not-stdlib": "--verify-no-venv requires stdlib_only: true in the manifest and no declared project dependencies. Use --verify for projects that install packages.",
    "command-not-found": "A declared executable was not found in the fresh verification environment. Install the required tool in an earlier quickstart step, or correct the command in release-check.json.",
    "command-failed": "A declared command failed in the clean clone. Run it yourself in a fresh clone to see why.",
    "project-not-installed": "The quickstart did not install the project. Make the first quickstart command install it.",
    "export-content-mismatch": "A file changed while it was being exported. Export again into a new folder.",
    "audit-incomplete": "The audit stopped early. Fix the stated problem and run again."
}


ERRORS: dict[str, str] = {
    "export-not-clean": "The export folder is not a single clean commit. Export again into a new folder.",
    "denylist-required": "Pass --denylist FILE or set RELEASE_CHECK_DENYLIST. The README shows how to make the file.",
    "denylist-not-found": "The private-terms file does not exist.",
    "denylist-schema": "The private-terms file is empty or not in a supported format. Private-term coverage is INCOMPLETE: no real private terms were configured. Add your own private terms outside the source repository.",
    "denylist-example": "Private-term coverage is INCOMPLETE: placeholder/example terms remain; no real private terms are configured in an all-example list. Replace every shipped placeholder with your own private terms outside the source repository, then run again.",
    "denylist-json": "The private-terms file is not valid JSON. Correct the JSON syntax and run again.",
    "denylist-encoding": "The private-terms file must be UTF-8 (an optional UTF-8 BOM is accepted). Save it as UTF-8, not UTF-16 or a legacy encoding.",
    "denylist-inside-source": "Keep the private-terms file outside the repository being audited.",
    "reports-inside-source": "Choose a reports folder outside the repository being audited.",
    "repo-not-found": "The repository folder does not exist.",
    "not-a-git-repository": "That folder is not a git repository.",
    "not-repository-root": "Point at the top folder of the repository, not a folder inside it.",
    "manifest-not-found": "The requested --manifest file does not exist.",
    "manifest-schema": "The manifest is unreadable or invalid JSON/schema. Check --manifest or release-check.json against the README fields.",
    "manifest-encoding": "The manifest must be UTF-8 (an optional UTF-8 BOM is accepted). Save release-check.json or --manifest as UTF-8, not UTF-16 or a legacy encoding.",
    "manifest-path": "Manifest exclusions must be relative paths inside the repository.",
    "export-destination-exists": "The export folder already exists. Choose a new, empty path.",
    "export-inside-source": "Put the export outside the repository being audited.",
    "export-parent-of-source": "The export folder cannot contain the repository being audited.",
    "export-contains-denylist": "The export folder cannot contain the private-terms file.",
    "invalid-timeout": "--timeout must be 1 or more.",
    "command-role": "The manifest has an invalid command role.",
    "command-schema": "The manifest has an invalid command entry.",
    "quickstart-document-path": "The manifest has an invalid quickstart document path.",
    "invalid-digest": "--check-digest needs the 64-character digest from the report.",
    "invalid-arguments": "Run release-check --help.",
    "audit-incomplete": "The audit could not finish. Nothing was verified."
}


class AuditError(Exception):
    """Errors use a fixed code; only deliberate diagnostics may add details."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.detail = detail


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally includes the offending argument, which may be a secret.
        print_error("invalid-arguments", self.json_mode)
        raise SystemExit(2)


def print_error(code: str, json_mode: bool, detail: str | None = None):
    if json_mode:
        error = {"ready": False, "error": "audit-incomplete", "code": code}
        if code == 'denylist-example':
            error.update(verdict='INCOMPLETE', message=ERRORS[code])
        if detail:
            error["message"] = ERRORS[code] + " " + detail
        print(json.dumps(error), file=sys.stderr)
    else:
        print(f"release-check {VERSION}\nVERDICT: INCOMPLETE\nReason: {code} - {ERRORS[code]}" + (" " + detail if detail else ""), file=sys.stderr)


def fingerprint(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8", "surrogateescape")
    return hashlib.sha256(value).hexdigest()[:16]


def opaque_secret(value: str) -> bool:
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", value) or value.startswith("sha256:"):
        return False
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values()) if value else 0
    return entropy >= 4.3 and bool(re.search(r"[a-z]", value) and re.search(r"[A-Z]", value) and re.search(r"\d", value))


class Terms(list):
    """Terms retain input order; optional domain entries remain private too."""
    internal_domains: list[str]


def normalize(text: str) -> str:
    return re.sub(r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]", "", unicodedata.normalize("NFKC", text))


def term_pattern(term: str) -> str:
    term = normalize(term)
    parts = re.split(r"[\s_\-\u2010-\u2015]+", term)
    pattern = r"[\s_\-\u2010-\u2015]*".join(re.escape(p) for p in parts if p)
    if len(term) <= 3 and term.isalnum():
        pattern = r"(?<![A-Za-z0-9])" + pattern + r"(?![A-Za-z0-9])"
    return pattern


def normalize_personal(line: str) -> str:
    line = html.unescape(re.sub(r"%([a-fA-F0-9]{2})", lambda m: chr(int(m.group(1), 16)), line))
    line = re.sub(r"\s*(?:\[at\]|\(at\))\s*", "@", line, flags=re.I)
    line = re.sub(r"\s*(?:\[dot\]|\(dot\))\s*", ".", line, flags=re.I)
    line = line.replace("[.]", ".")
    return re.sub(r"(?<=\d)\s*\.\s*(?=\d)", ".", line)


def host_example(value: str) -> bool:
    return bool(re.fullmatch(r"(?i)(?:macos|node|utf|sha|base|iso)-\d+", value)
                or re.fullmatch(r"(?i)(?:self|ctx|this|config|request)\.(?:local|internal|home)", value)
                or re.search(r"(?i)\.(?:local|internal|home)\.(?:json|toml|ini|yaml|yml|py|js|ts|cfg)$", value))


def integrity_value(line: str, value: str, path: str) -> bool:
    if re.fullmatch(r"sha(?:256|384|512)-[A-Za-z0-9+/=]+", value):
        return True
    # Only recognised hash fields are exempt, never arbitrary lockfile contents.
    lock = Path(path).name in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock"}
    return lock and bool(re.search(r"(?i)(?:integrity|checksum|hash|sha256)\s*[\"']?\s*[:=]", line)) and bool(re.fullmatch(r"(?:sha(?:256|384|512)[:-])?[A-Za-z0-9+/=]+", value))


def load_terms(path: Path) -> list[str]:
    """Accept JSON arrays, {terms: [...]}, category-based JSON, or newline lists."""
    if not path.is_file():
        raise AuditError("denylist-not-found")
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except UnicodeError:
        raise AuditError("denylist-encoding") from None
    domains = []
    if path.suffix.lower() == ".json" or raw.lstrip().startswith(("[", "{")):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as error:
            raise AuditError("denylist-json", f"Syntax error at line {error.lineno}, column {error.colno}.") from None
        if isinstance(obj, dict):
            domains = obj.get("internal_domains", [])
        if isinstance(obj, list):
            terms = obj
        elif isinstance(obj, dict) and isinstance(obj.get("terms"), list):
            terms = obj["terms"]
        elif isinstance(obj, dict) and isinstance(obj.get("categories"), dict):
            terms = []
            for category in obj["categories"].values():
                values = category.get("terms") if isinstance(category, dict) else category
                if not isinstance(values, list):
                    raise AuditError("denylist-schema")
                terms.extend(values)
        else:
            raise AuditError("denylist-schema")
    else:
        terms = [line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")]
    if not terms or any(not isinstance(t, str) or not t.strip() for t in terms):
        raise AuditError("denylist-schema")
    normalized = [re.sub(r"[\s_-]+", " ", normalize(t).strip().casefold()) for t in terms]
    if (any(t.startswith("replace with ") for t in normalized)
            or all(t in {"example", "placeholder", "your name", "your username", "your employer", "your machine", "your town"} for t in normalized)):
        raise AuditError("denylist-example")
    if not isinstance(domains, list) or any(not isinstance(d, str) or not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", d) for d in domains):
        raise AuditError("denylist-schema")
    result = Terms(terms)
    result.internal_domains = [d.lower() for d in domains]
    return result


def git(repo: Path, *args: str) -> bytes:
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0", TZ="UTC")
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=environment)
    if result.returncode:
        raise AuditError("git-read-failed")
    return result.stdout


def commit_text(raw: bytes) -> bytes:
    """Include author, committer and message; public signatures aren't secrets."""
    headers, separator, message = raw.partition(b"\n\n")
    identity = b"\n".join(line for line in headers.splitlines() if line.startswith((b"author ", b"committer ", b"encoding ")))
    return identity + separator + message


def match_path(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, p) or fnmatch.fnmatchcase(Path(path).name, p) or path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in patterns)


def credential_file(path: str) -> bool:
    name = Path(path).name.lower()
    nested = any(path.lower().endswith("/" + special) for special in (".docker/config.json", ".kube/config"))
    return nested or match_path(path.lower(), DEFAULT_EXCLUDES[1:]) or bool(re.search(r"(?:^|[_.-])(?:tokens?|credentials|id_rsa|id_ed25519|id_dsa|id_ecdsa)(?:[_.-]|$)", name))


def literal_secret(match: re.Match, line: str, path: str, in_literal: bool = False) -> str | None:
    value = match.group(1)
    quoted = value.startswith(('"', "'"))
    if not quoted and re.match(r"<[^>\r\n]*>", line[match.start(1):]):
        return None
    if quoted:
        value = value[1:-1]
    if not value or re.fullmatch(r"(?i)(?:change[_-]?me|your[_-].*|example|example[_-](?:key|token|password)|placeholder.*|dummy|xxx+|\.{3,}|<[^>]*>)", value):
        return None
    if not quoted and value in {"None", "null", "true", "false"}:
        return None
    if re.match(r"(?:os\.environ(?:\[|\.get\()|os\.getenv\(|process\.env(?:\.|\[)|env\(|\$\{)", value):
        return None
    if not quoted and not in_literal and Path(path).suffix == ".py" and value.startswith(("(", "[")):
        return None
    if not quoted and not in_literal and Path(path).suffix == ".py" and ")" in line[match.start(1):] and re.match(r"[a-zA-Z_]\w*(?:\.\w+)*\(", value):
        return None
    if not quoted and line[match.end():].startswith(('"', "'")) and (not in_literal or value.lower() in {"r", "b", "f", "u", "rb", "br", "rf", "fr"}):
        return None
    if re.match(r'''(?i)["']?key["']?\s*[:=]''', match.group()):
        # A generic key also names public map/license/sort fields. Explicit
        # password/token labels and provider formats do not get this exemption.
        if value in {"mit", "other", "unlicense", "unlicensed", "None", "null", "true", "false"} or value.casefold() in {identifier.casefold() for identifier in COMPATIBLE} or re.fullmatch(r"[a-z][a-z0-9-]*-\d+\.\d+(?:-only|-or-later)?", value):
            return None
        if not quoted and re.fullmatch(r"[a-z-]{1,19}", value):
            return None
    if not quoted and not in_literal and Path(path).suffix == ".py" and re.fullmatch(r"[A-Za-z_]\w*[):]*", value):
        return None  # Python names and type annotations are references, not literals.
    if re.match(r"\s*(?:\+|\*|%)", line[match.end():]):
        return None
    return value


def validate_repo(repo: Path):
    if not repo.is_dir():
        raise AuditError("repo-not-found")
    try:
        toplevel = Path(os.fsdecode(git(repo, "rev-parse", "--show-toplevel")).strip()).resolve()
    except AuditError:
        raise AuditError("not-a-git-repository") from None
    if toplevel != repo:
        raise AuditError("not-repository-root")


def protected(path: str) -> bool:
    return bool(re.search(r"(?:^|/)(?:LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*|UPSTREAM[^/]*|THIRD_PARTY[^/]*)$", path, re.I))


class Scanner:
    def __init__(self, terms: list[str], private_repos: list[str] = (), approvals: list[dict] = ()):
        self.terms = terms
        self.term_patterns = [re.compile(term_pattern(t), re.I) for t in terms]
        self.internal_domains = getattr(terms, "internal_domains", [])
        self.private_repos = list(private_repos)
        self.approvals = list(approvals)
        self.findings: list[dict] = []
        self.stats = Counter()
        self.seen = set()

    def safe_path(self, path: str) -> str:
        # Paths themselves can contain private terms, emails, IPs or tokens.
        original = path
        path = normalize(path)
        if any(re.search(r"(?<![\w.-])(?:[\w-]+\.)*" + re.escape(domain) + r"(?![\w.-])", normalize_personal(path), re.I) for domain in self.internal_domains):
            return "[path-" + fingerprint(original) + "]"
        for pattern in self.term_patterns:
            if pattern.search(path):
                return "[path-" + fingerprint(original) + "]"
        for pattern in [*PATTERNS.values(), *SECRET_PATTERNS.values(), r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"]:
            if re.search(pattern, path, re.I):
                return "[path-" + fingerprint(original) + "]"
        if any(url.casefold() in path.casefold() for url in self.private_repos):
            return "[path-" + fingerprint(original) + "]"
        if re.search(r"[0-9A-Fa-f]*:[0-9A-Fa-f:]+", path):
            return "[path-" + fingerprint(original) + "]"
        if any(opaque_secret(value) for value in re.findall(r"[A-Za-z0-9_/+=-]{32,}", path)):
            return "[path-" + fingerprint(original) + "]"
        return original.replace("\n", "[newline]").replace("\r", "[return]").replace("\t", "[tab]")

    def add(self, scope: str, category: str, kind: str, path: str, line: int = 0, value: str | bytes = b"", term_index: int | None = None, object_id: str | None = None):
        item = {"scope": scope, "category": category, "kind": kind, "path": self.safe_path(path), "line": line, "fingerprint": fingerprint(value)}
        if term_index is not None:
            item["term_index"] = term_index
        if object_id:
            item["object"] = object_id
        # Approvals are specific to category, kind, path, scope and fingerprint.
        # Denylist hits and credentials can never be waived.
        item["reviewed"] = category in {"personal", "media"} and kind != "denylist" and any(all(a.get(k) == item[k] for k in ("scope", "kind", "path", "fingerprint")) for a in self.approvals)
        key = tuple(sorted(item.items()))
        if key not in self.seen:
            self.seen.add(key)
            self.findings.append(item)

    def text(self, raw: bytes, scope: str, path: str, object_id: str | None = None):
        self.stats[scope + "_bytes"] += len(raw)
        # Wide-character media metadata and text files still receive term/secret checks.
        encodings = ["utf-8"]
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or (raw and raw.count(b"\0") / len(raw) > .15):
            encodings += ["utf-16-le", "utf-16-be"]
        for encoding in encodings:
            text = normalize(raw.decode(encoding, errors="replace"))
            for index, term in enumerate(self.terms):
                for match in self.term_patterns[index].finditer(text):
                    self.add(scope, "personal", "denylist", path, text.count("\n", 0, match.start()) + 1, match.group(), index, object_id)
            spans = []
            if Path(path).suffix == ".py":
                try:
                    for token in tokenize.generate_tokens(io.StringIO(text).readline):
                        if token.type in {tokenize.COMMENT, tokenize.STRING}:
                            spans.append((token.start, token.end))
                except (tokenize.TokenError, IndentationError, SyntaxError):
                    pass
            lines = text.splitlines()
            for number, line in enumerate(lines, 1):
                personal_line = normalize_personal(line)
                for domain in self.internal_domains:
                    for match in re.finditer(r"(?<![\w.-])(?:[\w-]+\.)*" + re.escape(domain) + r"(?![\w.-])", personal_line, re.I):
                        self.add(scope, "personal", "internal-host", path, number, match.group(), object_id=object_id)
                for kind, pattern in PATTERNS.items():
                    for match in re.finditer(pattern, personal_line, re.I):
                        if kind == "email" and re.fullmatch(r"(?:[0-9]+\+)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?@users\.noreply\.github\.com", match.group(), re.I):
                            continue
                        if kind == "internal-host" and host_example(match.group()):
                            continue
                        self.add(scope, "personal", kind, path, number, match.group(), object_id=object_id)
                for url in self.private_repos:
                    # Match HTTPS, SSH and bare owner/repo references to known private repos.
                    ref = re.sub(r"^(?:https?://github.com/|git@github.com:)", "", url).removesuffix(".git").rstrip("/")
                    for match in re.finditer(re.escape(ref), line, re.I):
                        self.add(scope, "personal", "private-repo-url", path, number, match.group(), object_id=object_id)
                for candidate in re.finditer(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[\w-]+)?(?![\w:])", personal_line):
                    value = candidate.group()
                    if value == "::" and not (candidate.start() > 0 and line[candidate.start() - 1] in "\"'["):
                        continue  # classifier/prose punctuation, not an address literal
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    kind = "tailnet-ip" if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10") else "ipv" + str(address.version)
                    self.add(scope, "personal", kind, path, number, value, object_id=object_id)
                webhook_spans = [m.span() for m in re.finditer(SECRET_PATTERNS["webhook-url"], line)]
                data_spans = [m.span() for m in re.finditer(r"data:[^;\s]+;base64,[A-Za-z0-9+/]+={0,2}", line, re.I)]
                for kind, pattern in SECRET_PATTERNS.items():
                    for match in re.finditer(pattern, line):
                        position = match.start(1) if kind in {"assigned-secret", "cli-secret", "xml-secret", "prose-secret", "netrc-password"} else match.start()
                        in_literal = any(start <= (number, position) < end for start, end in spans)
                        value = literal_secret(match, line, path, in_literal or kind != "assigned-secret") if kind in {"assigned-secret", "cli-secret", "xml-secret", "prose-secret", "netrc-password"} else match.group(match.lastindex or 0)
                        if kind == "prose-secret" and not re.search(r"\bis\s+", match.group(), re.I) and (len(value or "") < 12 or (len(value or "") < 20 and not re.search(r"password\s+", match.group(), re.I))):
                            continue
                        if value is not None:
                            self.add(scope, "secrets", kind, path, number, value, object_id=object_id)
                for match in re.finditer(r"(?<![\w+/=-])[A-Za-z0-9_/+=-]{32,}(?![\w+/=-])", line):
                    value = match.group()
                    if any(start <= match.start() and match.end() <= end for start, end in webhook_spans + data_spans):
                        continue
                    if "/" in value and any(m.start() <= match.start() < m.end() for m in re.finditer(r'''[a-z][a-z0-9+.-]*://[^\s"'<>]+''', line, re.I)):
                        # Evaluate URL segments separately; concatenating ordinary
                        # host/path words must not manufacture a base64 secret.
                        if not any(opaque_secret(part) for part in value.split("/")):
                            continue
                    # A hexadecimal content digest is not itself a credential. Explicit
                    # key formats and labelled secrets above still take precedence.
                    preceding = lines[number - 2][-40:] if number > 1 else ""
                    surrounding = line[:match.start()] + " " + line[match.end():]
                    context_text = re.sub(r"(?<=[a-z])(?=[A-Z])", "_", preceding + "\n" + surrounding)
                    context = re.search(r"(?i)(?<![a-z])(?:key|token|secret|auth|signing)(?![a-z])", context_text)
                    if not integrity_value(line, value, path) and (opaque_secret(value) or (context and (re.fullmatch(r"[a-fA-F0-9]{32,}", value) or len(value) >= 40))):
                        self.add(scope, "secrets", "entropy", path, number, value, object_id=object_id)

    def file(self, raw: bytes, scope: str, path: str, object_id: str | None = None):
        self.stats[scope + "_files"] += 1
        self.text(path.encode("utf-8", errors="surrogateescape"), scope, path, object_id)
        self.text(raw, scope, path, object_id)
        if credential_file(path):
            self.add(scope, "secrets", "credential-file", path, value=raw, object_id=object_id)
        if Path(path).suffix.lower() in MEDIA:
            self.add(scope, "media", "manual-review", path, value=raw, object_id=object_id)
        elif Path(path).suffix.lower() in {".zip", ".gz", ".tar", ".7z", ".exe", ".dll", ".so", ".sqlite", ".db", ".bin"} or (b"\0" in raw and not raw.startswith((b"\xff\xfe", b"\xfe\xff"))):
            self.add(scope, "media", "binary-review", path, value=raw, object_id=object_id)
        if raw.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            self.add(scope, "coverage", "lfs-content-not-scanned", path, value=raw, object_id=object_id)

    def tree(self, repo: Path):
        submodules = submodule_paths(repo)
        for rel in sorted(submodules):
            self.add("tree", "coverage", "submodule", rel)
        tracked = {p.decode("utf-8", "surrogateescape") for p in git(repo, "ls-files", "-z").split(b"\0") if p}
        for root, dirs, files in os.walk(repo, followlinks=False):
            relative = Path(root).relative_to(repo)
            dirs[:] = [d for d in dirs if d != ".git" and (relative / d).as_posix() not in submodules and (d not in GENERATED or any(p.startswith((relative / d).as_posix() + "/") for p in tracked))]
            for name in files + [d for d in dirs if (Path(root) / d).is_symlink()]:
                path = Path(root) / name
                rel = path.relative_to(repo).as_posix()
                if name == ".git" or rel in submodules:
                    continue
                if path.is_symlink():
                    raw = os.readlink(path).encode()
                    self.file(raw, "tree", rel)
                    self.add("tree", "coverage", "symlink", rel, value=raw)
                else:
                    try:
                        self.file(path.read_bytes(), "tree", rel)
                    except OSError:
                        self.add("tree", "coverage", "unreadable", rel)
        # Missing tracked files must not disappear silently from coverage.
        for rel in tracked:
            if not (repo / rel).exists() and not (repo / rel).is_symlink():
                self.add("tree", "coverage", "missing-tracked-file", rel)

    def history(self, repo: Path):
        if git(repo, "rev-parse", "--is-shallow-repository").strip() == b"true":
            self.add("history", "coverage", "shallow-history", "@git")
        self.text(git(repo, "for-each-ref", "--format=%(refname)\n%(taggername)\n%(taggeremail)\n%(contents)"), "metadata", "@refs")
        self.text(git(repo, "config", "--local", "--list"), "metadata", "@config")
        commits = git(repo, "rev-list", "--all", "--reflog").splitlines()
        self.stats["history_commits"] = len(commits)
        if not commits:
            self.add("history", "coverage", "no-commits", "@git")
        seen = set()
        for commit in commits:
            oid = commit.decode("ascii")
            self.text(commit_text(git(repo, "cat-file", "commit", oid)), "metadata", "@commit/" + oid[:12], oid)
            entries = git(repo, "ls-tree", "-r", "-z", oid).split(b"\0")
            for entry in filter(None, entries):
                metadata, path = entry.split(b"\t", 1)
                mode, kind, blob = metadata.split()
                rel = path.decode("utf-8", "surrogateescape")
                key = (blob, path, mode)
                if key in seen:
                    continue
                seen.add(key)
                if kind != b"blob":
                    self.add("history", "coverage", "submodule", rel, object_id=oid)
                    continue
                raw = git(repo, "cat-file", "blob", blob.decode())
                self.file(raw, "history", rel, blob.decode())
                if mode == b"120000":
                    self.add("history", "coverage", "symlink", rel, value=raw, object_id=oid)


def manifest_for(repo: Path, path: Path | None) -> dict:
    explicit = path is not None
    path = path.expanduser() if explicit else repo / "release-check.json"
    if not path.exists() and not path.is_symlink():
        if explicit:
            raise AuditError("manifest-not-found")
        return {"exclude": [], "approvals": [], "quickstart": [], "checks": []}
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except UnicodeError:
        raise AuditError("manifest-encoding") from None
    except OSError:
        raise AuditError("manifest-schema") from None
    try:
        obj = json.loads(raw)
    except ValueError:
        raise AuditError("manifest-schema") from None
    if not isinstance(obj, dict) or any(k not in {"exclude", "approvals", "quickstart", "checks", "license", "dependency_licenses", "license_owner_disposition", "stdlib_only"} for k in obj):
        raise AuditError("manifest-schema")
    if type(obj.get("stdlib_only", False)) is not bool:
        raise AuditError("manifest-schema")
    for key in ("exclude", "approvals", "quickstart", "checks"):
        obj.setdefault(key, [])
        if not isinstance(obj[key], list):
            raise AuditError("manifest-schema")
    if any(not isinstance(item, dict) for key in ("approvals", "quickstart", "checks") for item in obj[key]):
        raise AuditError("manifest-schema")
    if not isinstance(obj.get("dependency_licenses", {}), dict):
        raise AuditError("manifest-schema")
    if any(not isinstance(p, str) or p.startswith("/") or ".." in Path(p).parts for p in obj["exclude"]):
        raise AuditError("manifest-path")
    if explicit:
        validate_commands(obj)
    return obj


def validate_commands(manifest: dict):
    for item in [*manifest["quickstart"], *manifest["checks"]]:
        if item.get("role", "quickstart") not in ROLES:
            raise AuditError("command-role")
        argv = item.get("argv")
        if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or "\0" in a for a in argv):
            raise AuditError("command-schema")
    for item in manifest["quickstart"]:
        doc = item.get("file", "README.md")
        if not isinstance(doc, str) or Path(doc).is_absolute() or ".." in Path(doc).parts:
            raise AuditError("quickstart-document-path")


def normalized_license(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def apache_license(text: str) -> bool:
    """Match ASF/SPDX terms exactly; only wrapping and standard tails vary.

    Sources: https://www.apache.org/licenses/LICENSE-2.0.txt and
    https://spdx.org/licenses/Apache-2.0.html. The appendix is optional;
    its identifying copyright fields may be filled in. A standard applied
    boilerplate notice may replace the instructional appendix.
    """
    body, marker, tail = text.partition("END OF TERMS AND CONDITIONS")
    if not marker or hashlib.sha256(normalized_license(body + marker).encode()).hexdigest() != "59d8f0ba87ad9a2f1a431123c8d16646e5b89ba53653e818f16d136d77263c99":
        return False
    if not tail.strip():
        return True
    # Only replace the identifying fields, never grant/disclaimer wording.
    tail = re.sub(r"Copyright (?:\[yyyy\] \[name of copyright owner\]|\d{4}(?:[-, ]\d{4})* [^\r\n]+?)(?=\s+Licensed under the Apache License)",
                  "Copyright [yyyy] [name of copyright owner]", tail)
    digest = hashlib.sha256(normalized_license(tail).encode()).hexdigest()
    return digest in {"15e0e14d590e112dcf1801fb0ca4a74c6178f468147941bfe6840cb55fa84ca4",
                      "108bfed552130bbe29d30b1526c0c443629be89bb82fd495357b7305db0693a1"}


def known_upstream_license(text: str) -> bool:
    """Identify the normalized, observed upstream file for retention checks only."""
    return hashlib.sha256(normalized_license(text).encode()).hexdigest() == "a2016109f78ae6b763dd66c84d3fa11c61389c6b787d4b50bc02d2ea9c883a2a"


def upstream_license_disposition(path: Path, text: str, manifest: dict) -> dict | None:
    """Accept only the reviewed upstream's exact three normalized term variants.

    This is recorded owner evidence, not automatic canonical recognition.
    Hash the verbatim bytes; never rewrite the retained license.
    """
    evidence = manifest.get("license_owner_disposition")
    differences = [
        {"canonical": "submitted to Licensor", "upstream": "submitted to the Licensor"},
        {"canonical": "received by Licensor", "upstream": "received by the Licensor"},
        {"canonical": "within such NOTICE file, excluding those notices",
         "upstream": "within such NOTICE file, excluding any notices"},
    ]
    if (not isinstance(evidence, dict)
            or set(evidence) != {"reviewed", "spdx", "path", "source_url", "upstream_commit", "sha256", "differences"}
            or evidence.get("reviewed") is not True
            or evidence.get("spdx") != "Apache-2.0" or evidence.get("path") != path.name
            or path.name != "LICENSE"
            or evidence.get("source_url") != "https://github.com/prime-radiant-inc/engineering-notebook"
            or evidence.get("upstream_commit") != "b0a34caa4b59e466652572310fd043a9548027c2"
            or evidence.get("sha256") != "9177a3b208fb5034ae89ec90ed3c1f4192ca6825ef19699f5d62beace22bcbf5"
            or evidence.get("sha256") != hashlib.sha256(path.read_bytes()).hexdigest()
            or evidence.get("differences") != differences or not known_upstream_license(text)):
        return None
    normalized = normalized_license(text)
    body, marker, _ = normalized.partition("END OF TERMS AND CONDITIONS")
    if not marker or hashlib.sha256((body + marker).encode()).hexdigest() != "a14c5bd2f88659c252bbac195ceb4c19e26f829132b552ffbddd26cb8b41a7d8":
        return None
    for difference in differences:
        if normalized.count(difference["upstream"]) != 1:
            return None
        normalized = normalized.replace(difference["upstream"], difference["canonical"], 1)
    return evidence if apache_license(normalized) else None


def apache_attribution_audit(repo: Path, scanner: Scanner, destination: Path | None = None, scope: str = "tree"):
    """Retain observed Apache upstream notices and copyright in local history.

    No remote is consulted. Unknown upstream history remains an owner review.
    Deleted source files need not retain notices that no longer pertain; the
    distribution's license and NOTICE files must survive.
    """
    if not (repo / ".git").exists():
        return
    seen: set[tuple[bytes, bytes]] = set()
    for commit in git(repo, "rev-list", "--all", "--reflog").splitlines():
        entries = [entry.split(b"\t", 1) for entry in
                   filter(None, git(repo, "ls-tree", "-r", "-z", commit.decode()).split(b"\0"))]
        license_blobs = [metadata.split()[2] for metadata, raw_path in entries
                         if raw_path.upper() in {b"LICENSE", b"LICENSE.MD", b"LICENSE.TXT", b"COPYING"}
                         and metadata.split()[1] == b"blob" and metadata.split()[0] != b"120000"]
        if not any(b"Apache License" in git(repo, "cat-file", "blob", blob.decode()) for blob in license_blobs):
            continue
        for metadata, raw_path in entries:
            mode, kind, blob = metadata.split()
            if kind != b"blob" or mode == b"120000" or (blob, raw_path) in seen:
                continue
            seen.add((blob, raw_path))
            path = raw_path.decode("utf-8", "surrogateescape")
            target = (destination or repo) / path
            attribution_file = protected(path)
            if not target.is_file() or target.is_symlink():
                if attribution_file:
                    scanner.add(scope, "license", "historical-attribution-missing", path, value=metadata)
                continue
            old = git(repo, "cat-file", "blob", blob.decode()).decode("utf-8", "replace")
            current_text = target.read_text(errors="replace")
            current = normalized_license(current_text)
            if Path(path).name.upper() in {"LICENSE", "LICENSE.MD", "LICENSE.TXT", "COPYING"} and apache_license(old) and not apache_license(current_text):
                scanner.add(scope, "license", "historical-attribution-changed", path, value=old)
            if Path(path).name.upper() in {"LICENSE", "LICENSE.MD", "LICENSE.TXT", "COPYING"} and known_upstream_license(old) and git(repo, "cat-file", "blob", blob.decode()) != target.read_bytes():
                scanner.add(scope, "license", "historical-attribution-changed", path, value=old)
            if attribution_file and "NOTICE" in Path(path).name.upper():
                notices = [line.strip() for line in old.splitlines() if line.strip()]
            else:
                notices = re.findall(r"(?im)^[ \t]*(?:[#/*;! -]+[ \t]*)?(Copyright[^\r\n]*)$", old)
            if any(not re.search(re.escape(normalized_license(notice)) + r"(?!\w)", current) for notice in notices):
                scanner.add(scope, "license", "historical-attribution-changed", path, value=old)


def license_audit(repo: Path, scanner: Scanner, manifest: dict) -> dict:
    candidates = [p for p in repo.iterdir() if p.name.upper() in {"LICENSE", "LICENSE.MD", "LICENSE.TXT", "COPYING"}]
    result = {"status": "blocked", "identifier": None, "dependencies": "not-verified"}
    if not candidates:
        scanner.add("tree", "license", "missing-license", "LICENSE")
        return result
    text = candidates[0].read_text(errors="replace")
    disposition = upstream_license_disposition(candidates[0], text, manifest)
    if "license_owner_disposition" in manifest and disposition is None:
        scanner.add("tree", "license", "invalid-license-owner-disposition", candidates[0].name)
    # Compare all standard MIT grant/disclaimer wording, allowing wrapping and owner/year.
    canonical_hash = "fe2a9817987f862eaced948f0468c7f51d2fedfc48c5c505b246a49a3870e9a5"
    normalize = lambda t: re.sub(r"\s+", " ", t[t.find("Permission is hereby granted"):]).strip()
    if "MIT License" in text and "Permission is hereby granted" in text and hashlib.sha256(normalize(text).encode()).hexdigest() == canonical_hash:
        result.update(status="pass", identifier="MIT")
    elif apache_license(text):
        result.update(status="pass", identifier="Apache-2.0")
    elif disposition:
        result.update(status="pass", identifier="Apache-2.0", owner_disposition=disposition)
    else:
        scanner.add("tree", "license", "unrecognized-or-modified-license", candidates[0].name, value=text)
    project = {}
    if (repo / "pyproject.toml").exists():
        project = tomllib.loads((repo / "pyproject.toml").read_text()).get("project", {})
        declared = project.get("license")
        if isinstance(declared, dict) and "text" in declared:
            declared = declared["text"]
        if isinstance(declared, str) and declared != result["identifier"]:
            scanner.add("tree", "license", "license-metadata-mismatch", "pyproject.toml", value=declared)
        if "dynamic" in project and any(x in project["dynamic"] for x in ("dependencies", "license")):
            scanner.add("tree", "license", "dynamic-license-or-dependencies", "pyproject.toml")
    if (repo / "package.json").exists():
        package = json.loads((repo / "package.json").read_text())
        declared = package.get("license") if isinstance(package, dict) else None
        if isinstance(declared, str) and declared != result["identifier"]:
            scanner.add("tree", "license", "license-metadata-mismatch", "package.json", value=declared)
    apache_attribution_audit(repo, scanner)
    # Unknown ecosystems do not become a false green.
    for name in ("package.json", "Cargo.toml", "go.mod", "pom.xml", "Gemfile", "composer.json", "build.gradle", "build.gradle.kts", "Package.swift", "environment.yml", "Pipfile", "setup.py", "setup.cfg"):
        if (repo / name).exists():
            scanner.add("tree", "license", "dependency-ecosystem-manual-review", name)
    for path in repo.glob("*.csproj"):
        scanner.add("tree", "license", "dependency-ecosystem-manual-review", path.name)
    if (repo / "pyproject.toml").exists() and "poetry" in tomllib.loads((repo / "pyproject.toml").read_text()).get("tool", {}):
        scanner.add("tree", "license", "dependency-ecosystem-manual-review", "pyproject.toml")
    for name in ("vendor", "vendored", "third_party", "third-party"):
        if (repo / name).is_dir():
            scanner.add("tree", "license", "vendored-attribution-review", name)
    deps = bool(project.get("dependencies") or project.get("optional-dependencies"))
    for path in repo.glob("*requirements*.txt"):
        if any(line.strip() and not line.lstrip().startswith("#") for line in path.read_text().splitlines()):
            deps = True
    if not deps:
        result["dependencies"] = "stdlib-only"
    # Attribution is never silently discarded, even when an export manifest excludes it.
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d != ".git" and d not in GENERATED]
        for name in files:
            rel = (Path(root) / name).relative_to(repo).as_posix()
            if protected(rel) and match_path(rel, [*DEFAULT_EXCLUDES, *manifest["exclude"]]):
                scanner.add("tree", "license", "excluded-attribution", rel)
    return result


def quality_audit(repo: Path, scanner: Scanner, manifest: dict):
    for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
        if not (repo / name).is_file():
            scanner.add("tree", "quality", "missing-document", name)
    if not any((repo / ".github/ISSUE_TEMPLATE").glob("*.y*ml")) and not any((repo / ".github/ISSUE_TEMPLATE").glob("*.md")):
        scanner.add("tree", "quality", "missing-issue-templates", ".github/ISSUE_TEMPLATE")
    try:
        readme = (repo / "README.md").read_text(encoding="utf-8", errors="replace") if (repo / "README.md").is_file() else ""
    except OSError:
        readme = ""
    if not re.search(r"^#+\s+.*(?:limitations|known issues|where it fails)", readme, re.I | re.M):
        scanner.add("tree", "quality", "missing-limitations", "README.md")
    if not any((repo / "tests").rglob("test*.py")):
        scanner.add("tree", "quality", "missing-tests", "tests")
    if not manifest["quickstart"]:
        scanner.add("tree", "quality", "quickstart-not-declared", "release-check.json")
    if not any(item.get("role") == "tests" for item in manifest["checks"]):
        scanner.add("tree", "quality", "test-command-not-declared", "release-check.json")
    config = tomllib.loads((repo / "pyproject.toml").read_text()).get("tool", {}) if (repo / "pyproject.toml").exists() else {}
    for name, role in (("ruff", "lint"), ("mypy", "types")):
        if name in config and not any(item.get("role") == role for item in manifest["checks"]):
            scanner.add("tree", "quality", "configured-check-not-declared", "pyproject.toml", value=role)


def submodule_paths(repo: Path) -> set[str]:
    return {os.fsdecode(entry.split(b"\t", 1)[1])
            for entry in git(repo, "ls-files", "--stage", "-z").split(b"\0")
            if entry.startswith(b"160000 ")}


def export_destination_error(*paths: Path) -> AuditError:
    existing = [str(path) for path in paths if path.exists() or path.is_symlink()]
    return AuditError("export-destination-exists", "In the way: " + ", ".join(json.dumps(path).replace("\\\\", "\\") for path in existing)
                      + ". Keep these folders and rerun the same command with --export NEW_DIR, where NEW_DIR and NEW_DIR.BLOCKED do not exist.")


def copy_tree(repo: Path, target: Path, manifest: dict, scanner: Scanner):
    if target.exists() or target.is_symlink():
        raise export_destination_error(target)
    if target == repo or repo in target.parents:
        raise AuditError("export-inside-source")
    if target in repo.parents:
        raise AuditError("export-parent-of-source")
    target.mkdir(mode=0o700, parents=True)
    if git(repo, "rev-parse", "--is-shallow-repository").strip() == b"true":
        scanner.add("export", "coverage", "shallow-history", "@git")
    excluded = [*DEFAULT_EXCLUDES, *manifest["exclude"]]
    tracked = {p.decode("utf-8", "surrogateescape") for p in git(repo, "ls-files", "-z").split(b"\0") if p}
    submodules = submodule_paths(repo)
    for rel in sorted(submodules):
        scanner.add("export", "coverage", "submodule", rel)
    copied = {}
    left = set(untracked_files(repo, tracked))
    for root, dirs, files in os.walk(repo, followlinks=False):
        relative = Path(root).relative_to(repo)
        dirs[:] = [d for d in dirs if d != ".git" and (relative / d).as_posix() not in submodules and not match_path((relative / d).as_posix(), excluded) and (d not in GENERATED or any(p.startswith((relative / d).as_posix() + "/") for p in tracked))]
        for name in files:
            source = Path(root) / name
            rel = source.relative_to(repo).as_posix()
            if name == ".git" or rel in submodules or match_path(rel, excluded) or credential_file(rel):
                continue
            if rel not in tracked:
                left.add(rel)
                continue
            if source.is_symlink() or not source.is_file():
                scanner.add("export", "coverage", "unsupported-file", rel)
                continue
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            raw = source.read_bytes()
            copied[rel] = hashlib.sha256(raw).hexdigest()
            dest.write_bytes(raw)
            dest.chmod(0o700 if source.stat().st_mode & 0o111 else 0o600)
        for name in dirs:
            if (Path(root) / name).is_symlink():
                rel = (relative / name).as_posix()
                if rel not in tracked:
                    left.add(rel)
                    continue
                scanner.add("export", "coverage", "unsupported-file", rel)
    git(target, "init", "-q", "--template=", "-b", "main")
    (target / ".git/hooks").mkdir(mode=0o700)
    (target / ".git/info").mkdir(mode=0o700)
    (target / ".git/info/exclude").write_bytes(b"")
    (target / ".git/description").write_bytes(b"Clean source export\n")
    (target / ".git/config").write_bytes(EXPORT_CONFIG)
    # Explicit paths only; no remote, hooks, original identity or original history.
    paths = [str(p.relative_to(target)) for p in target.rglob("*") if p.is_file() and ".git" not in p.relative_to(target).parts]
    for start in range(0, len(paths), 100):
        git(target, "--literal-pathspecs", "add", "-f", "--", *paths[start:start + 100])
    git(target, "-c", "user.name=Release Export", "-c", "user.email=release-export", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "Clean source export")
    (target / ".git/COMMIT_EDITMSG").unlink()
    for rel, expected in copied.items():
        dest = target / rel
        try:
            matches = not dest.is_symlink() and hashlib.sha256(dest.read_bytes()).hexdigest() == expected
        except OSError:
            matches = False
        if not matches:
            scanner.add("export", "coverage", "export-content-mismatch", rel)
    return {"files": copied, "not_exported": sorted(left)}


def blocked_artifact(target: Path) -> bool:
    return target.is_dir() and not (target / ".git").exists() and not (target / ".git").is_symlink() and (target / BLOCKED_README).is_file()


def quarantine_export(target: Path):
    """Remove only this run's generated Git metadata, including secret blobs."""
    metadata = target / ".git"
    record = metadata / AUDIT_RECORD
    if record.is_file():
        (target / AUDIT_RECORD).write_bytes(record.read_bytes())
        (target / AUDIT_RECORD).chmod(0o600)
    warning = target / BLOCKED_README
    warning.write_text(BLOCKED_EXPORT_WARNING + "\n\nThis folder is NOT a release. Fix the source and create a new verified export.\n", encoding="utf-8")
    warning.chmod(0o600)
    if metadata.is_dir() and not metadata.is_symlink():
        def remove_readonly(function, path, _error):
            os.chmod(path, 0o700)
            function(path)
        shutil.rmtree(metadata, onerror=remove_readonly)


def export_digest(target: Path) -> str:
    try:
        if blocked_artifact(target):
            content = hashlib.sha256(b"release-check blocked artifact v1\0")
            for file in sorted(target.rglob("*"), key=lambda p: p.relative_to(target).as_posix()):
                if file.is_symlink() or not (file.is_dir() or file.is_file()):
                    raise AuditError("export-not-clean")
                content.update(file.relative_to(target).as_posix().encode("utf-8", "surrogateescape") + b"\0")
                content.update(str(file.stat().st_mode & 0o111).encode() + b"\0" + str(file.stat().st_mtime_ns).encode() + b"\0")
                content.update((b"directory" if file.is_dir() else file.read_bytes()) + b"\0")
            return content.hexdigest()
        metadata = target / ".git"
        if (metadata.is_symlink() or not metadata.is_dir()
                or (metadata / "config").is_symlink()
                or (metadata / "config").read_bytes() != EXPORT_CONFIG
                or (metadata / "HEAD").read_bytes() != b"ref: refs/heads/main\n"):
            raise AuditError("export-not-clean")
        # Exports have no template hooks and only loose, reachable objects. Check
        # the inventory before running Git: alternates/grafts/attributes cannot
        # influence the check or cause reads outside the export.
        fixed = {"HEAD", "config", "description", "index", "info/exclude", "refs/heads/main", "logs/HEAD", "logs/refs/heads/main"}
        if (metadata / AUDIT_RECORD).exists():
            fixed.add(AUDIT_RECORD)
        entries = {p.relative_to(metadata).as_posix(): p for p in metadata.rglob("*")}
        for rel, file in entries.items():
            if file.is_symlink() or not (file.is_dir() or file.is_file()):
                raise AuditError("export-not-clean")
            if file.is_file() and rel not in fixed and not re.fullmatch(r"objects/[a-f0-9]{2}/[a-f0-9]{38}", rel):
                raise AuditError("export-not-clean")
        objects = {"objects/" + oid[:2] + "/" + oid[2:] for oid in git(target, "rev-list", "--objects", "--no-object-names", "--all").decode().splitlines()}
        allowed_files = fixed | objects
        allowed_dirs = {"hooks", "info", "objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/tags", "logs", "logs/refs", "logs/refs/heads"} | {Path(p).parent.as_posix() for p in objects}
        if {r for r, p in entries.items() if p.is_file()} != allowed_files or {r for r, p in entries.items() if p.is_dir()} != allowed_dirs:
            raise AuditError("export-not-clean")
        if git(target, "fsck", "--full", "--strict", "--unreachable", "--no-reflogs").strip():
            raise AuditError("export-not-clean")
        oid = git(target, "rev-parse", "HEAD").strip()
        committer = next(line for line in git(target, "cat-file", "commit", oid.decode()).splitlines() if line.startswith(b"committer "))
        expected_log = b"0" * 40 + b" " + oid + b" " + committer.removeprefix(b"committer ") + b"\tcommit (initial): Clean source export\n"
        if ((metadata / "description").read_bytes() != b"Clean source export\n"
                or (metadata / "info/exclude").read_bytes()
                or any((metadata / name).read_bytes() != expected_log for name in ("logs/HEAD", "logs/refs/heads/main"))):
            raise AuditError("export-not-clean")
        if (git(target, "rev-list", "--count", "--all").strip() != b"1"
                or git(target, "rev-list", "--count", "HEAD").strip() != b"1"
                or git(target, "for-each-ref", "--format=%(refname)").splitlines() != [b"refs/heads/main"]
                or git(target, "remote").strip()
                or git(target, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
                or git(target, "status", "--porcelain", "--untracked-files=all")):
            raise AuditError("export-not-clean")
        content = hashlib.sha256()
        tracked = sorted(p for p in git(target, "ls-files", "-z").split(b"\0") if p)
        expected_dirs = {parent.as_posix() for raw in tracked for parent in Path(os.fsdecode(raw)).parents if str(parent) != "."}
        actual_dirs = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_dir() and ".git" not in p.relative_to(target).parts}
        if actual_dirs != expected_dirs:
            raise AuditError("export-not-clean")
        for raw in tracked:
            file = target / os.fsdecode(raw)
            if file.is_symlink() or not file.is_file():
                raise AuditError("export-not-clean")
            content.update(raw + b"\0" + str(file.stat().st_mode & 0o111).encode() + b"\0" + str(file.stat().st_mtime_ns).encode() + b"\0")
            content.update(file.read_bytes() + b"\0")
        for rel in sorted(entries):
            file = entries[rel]
            content.update(rel.encode() + b"\0" + (b"directory" if file.is_dir() else file.read_bytes()) + b"\0")
        return hashlib.sha256(git(target, "rev-parse", "HEAD").strip() + b"\0" + content.hexdigest().encode()).hexdigest()
    except (AuditError, OSError):
        raise AuditError("export-not-clean") from None


def safe_environment(home: Path, bin_dir: Path) -> dict:
    # Credentials, Git config, application caches and provider opt-ins do not inherit.
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = [str(bin_dir)]
    git_executable = shutil.which("git")
    if git_executable:
        paths.append(str(Path(git_executable).parent))
    environment = {"HOME": str(home), "TMPDIR": str(home), "TEMP": str(home), "TMP": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "XDG_CACHE_HOME": str(home / "cache"), "XDG_CONFIG_HOME": str(home / "config")}
    if sys.platform == "win32":
        system_root = os.environ.get("SystemRoot", os.environ.get("WINDIR", ""))
        if system_root:
            environment.update(SystemRoot=system_root, WINDIR=system_root)
            paths.extend([str(Path(system_root) / "System32"), system_root])
        environment.update(USERPROFILE=str(home), APPDATA=str(home / "AppData/Roaming"), LOCALAPPDATA=str(home / "AppData/Local"), PATHEXT=".COM;.EXE;.BAT;.CMD")
    else:
        paths.extend(["/usr/local/bin", "/usr/bin", "/bin"])
    environment["PATH"] = os.pathsep.join(dict.fromkeys(paths))
    return environment


def command(argv: list[str], cwd: Path, env: dict, timeout: int) -> tuple[int, bytes]:
    # A timeout kills the process group, including any subprocess the test spawned.
    with tempfile.TemporaryFile() as output:
        # Windows otherwise searches the parent's PATH when creating a process.
        executable = shutil.which(argv[0], path=env.get("PATH", ""))
        if executable is None:
            return 127, MISSING_EXECUTABLE_OUTPUT
        process = subprocess.Popen([executable, *argv[1:]], cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                taskkill = Path(env["SystemRoot"]) / "System32/taskkill.exe"
                subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if process.poll() is None:
                    process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = 124
        output.seek(0)
        return code, output.read(8 * 1024 * 1024)


METADATA_SCRIPT = '''import importlib.metadata as m, json
out=[]
for d in m.distributions():
 if d.metadata.get('Name','').lower() in {'pip','setuptools'}: continue
 out.append({'name':d.metadata.get('Name'), 'version':d.version,
 'expression':d.metadata.get('License-Expression'), 'license':d.metadata.get('License'),
 'classifiers':d.metadata.get_all('Classifier',[]),
 'license_files':[{'path':str(p),'hash':__import__('hashlib').sha256(d.locate_file(p).read_bytes()).hexdigest()}
 for p in (d.files or []) if any(x in str(p).upper() for x in ('LICENSE','COPYING','NOTICE')) and d.locate_file(p).is_file()]})
print(json.dumps(out))'''

COMPATIBLE = {"MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "PSF-2.0", "0BSD", "Unlicense", "CC0-1.0", "Python-2.0", "MPL-2.0", "MIT-CMU", "CNRI-Python", "Zlib", "BSL-1.0", "Apache-2.0 WITH LLVM-exception"}
CLASSIFIERS = {"MIT License": "MIT", "Apache Software License": "Apache-2.0", "BSD License": "BSD", "ISC License (ISCL)": "ISC", "Python Software Foundation License": "PSF-2.0", "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0"}


def compatible_license(label: str | None) -> bool:
    if not isinstance(label, str):
        return False
    parts = re.split(r"\s+(?:AND|OR)\s+", label.strip("()"))
    return bool(label) and all(p.strip("() ") in COMPATIBLE for p in parts)


def dependency_audit(raw: bytes, repo: Path, scanner: Scanner, manifest: dict) -> dict:
    packages = json.loads(raw)
    count = 0
    dispositions = []
    for package in packages:
        name = package["name"] or "unknown"
        label = package["expression"]
        if not label:
            text = (package["license"] or "").strip()
            if compatible_license(text):
                label = text
            elif "MIT License" in text and "Permission is hereby granted" in text:
                label = "MIT"
            else:
                labels = {value for ending, value in CLASSIFIERS.items() if any(c.endswith(":: " + ending) for c in package["classifiers"])}
                if len(labels) == 1:
                    label = labels.pop()
        # BSD classifiers omit the clause count; project evidence must specify it.
        evidence = manifest.get("dependency_licenses", {}).get(name.lower())
        if evidence and isinstance(evidence, dict) and evidence.get("version") == package["version"] and any(evidence.get("sha256") == f["hash"] for f in package["license_files"]):
            label = evidence.get("spdx")
        disposition = evidence.get("owner_disposition") if isinstance(evidence, dict) else None
        accepted = (not package["license_files"] and isinstance(disposition, dict)
                    and evidence.get("version") == package["version"]
                    and disposition.get("reviewed") is True
                    and isinstance(disposition.get("source_url"), str) and bool(disposition["source_url"].strip())
                    and compatible_license(disposition.get("spdx"))
                    and (compatible_license(label) or (not label and not (package["license"] or "").strip())))
        if accepted:
            label = disposition["spdx"]
            dispositions.append({"package": name, "version": package["version"], "owner_disposition": disposition})
        # Conservative SPDX expression handling: unknown or copyleft branches block.
        if not compatible_license(label) or (not package["license_files"] and not accepted):
            scanner.add("verification", "license", "dependency-license-review", "@dependency/" + name, value=json.dumps(package, sort_keys=True))
            count += 1
    return {"packages": len(packages), "blocked": count, "owner_dispositions": dispositions}


def verification_venv(workspace: Path, timeout: int) -> tuple[Path | None, bytes, str]:
    """Use the current Python first; external builders get the same clean HOME."""
    env_dir = workspace / "venv"
    environment = safe_environment(workspace / "home", Path(sys.executable).parent)
    attempts = [("venv", [sys.executable, "-m", "venv", str(env_dir)])]
    uv = shutil.which("uv")
    virtualenv = shutil.which("virtualenv")
    if uv:
        attempts.append(("uv", [uv, "venv", "--seed", "--python", sys.executable, str(env_dir)]))
    if virtualenv:
        attempts.append(("virtualenv", [virtualenv, "--python", sys.executable, str(env_dir)]))
    output = b""
    for route, argv in attempts:
        if env_dir.exists():
            shutil.rmtree(env_dir)
        code, output = command(argv, workspace, environment, timeout)
        python = env_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        if not code and python.is_file():
            return python, output, route
    return None, output, "not-run"


def verification_argv(argv: list[str], python: Path) -> list[str]:
    """Resolve portable Python launchers to the selected verification interpreter."""
    if argv[0] in {"python", "python3", "python" + str(sys.version_info.major) + "." + str(sys.version_info.minor)}:
        return [str(python), *argv[1:]]
    if argv[0] == "py":
        return [str(python), *argv[2 if argv[:2] == ["py", "-3"] else 1:]]
    return list(argv)


def verify(repo: Path, report_dir: Path, scanner: Scanner, manifest: dict, timeout: int) -> dict:
    return verify_with_mode(repo, report_dir, scanner, manifest, timeout)


def verify_with_mode(repo: Path, report_dir: Path, scanner: Scanner, manifest: dict, timeout: int, no_venv: bool = False) -> dict:
    results = []
    result = {"status": "blocked", "commands": results, "dependencies": None,
              "isolation": "current-interpreter (less isolated)" if no_venv else "venv"}
    validate_commands(manifest)
    if no_venv:
        project = tomllib.loads((repo / "pyproject.toml").read_text()).get("project", {}) if (repo / "pyproject.toml").exists() else {}
        if not manifest.get("stdlib_only") or project.get("dependencies") or project.get("optional-dependencies") or project.get("dynamic"):
            scanner.add("verification", "quality", "no-venv-not-stdlib", "release-check.json")
            return result
    if not manifest["quickstart"] or not manifest["checks"]:
        scanner.add("verification", "quality", "verification-not-configured", "release-check.json")
        return result
    for item in [*manifest["quickstart"], *manifest["checks"]]:
        argv = item["argv"]
        if item in manifest["quickstart"]:
            doc = item.get("file", "README.md")
            if not (repo / doc).is_file():
                scanner.add("verification", "quality", "quickstart-document-missing", doc)
                return result
            try:
                lines = (repo / doc).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                scanner.add("verification", "quality", "quickstart-document-missing", doc)
                return result
            number = item.get("line", 0)
            if not isinstance(number, int) or not 1 <= number <= len(lines) or shlex.split(lines[number - 1]) != argv:
                scanner.add("verification", "quality", "quickstart-document-mismatch", doc, number if isinstance(number, int) else 0)
                return result
    with tempfile.TemporaryDirectory(prefix="verify-", dir=report_dir) as tmp:
        workspace = Path(tmp)
        snapshot = workspace / "snapshot"
        copy_tree(repo, snapshot, manifest, scanner)
        clean = workspace / "clean"
        git(workspace, "clone", "-q", "--no-local", str(snapshot), str(clean))
        if no_venv:
            python = Path(sys.executable)
        else:
            python, output, route = verification_venv(workspace, timeout)
            result["isolation"] = route
            if python is None:
                scanner.add("verification", "quality", "venv-creation-failed", "release-check.json", value=output)
                return result
        bin_dir = python.parent
        environment = safe_environment(workspace / "home", bin_dir)
        for step, item in enumerate([*manifest["quickstart"], *manifest["checks"]], 1):
            argv = verification_argv(item["argv"], python)
            code, output = command(argv, clean, environment, timeout)
            results.append({"step": step, "role": item.get("role", "quickstart"), "exit_code": code, "output_fingerprint": fingerprint(output)})
            if code:
                scanner.add("verification", "quality", "command-not-found" if code == 127 and output == MISSING_EXECUTABLE_OUTPUT else "command-failed", item.get("file", "release-check.json"), item.get("line", 0), output)
                return result
        if no_venv:
            result["status"] = "pass"
            return result
        code, output = command([str(python), "-c", METADATA_SCRIPT], clean, environment, timeout)
        if code:
            scanner.add("verification", "license", "dependency-metadata-failed", "pyproject.toml", value=output)
        else:
            result["dependencies"] = dependency_audit(output, clean, scanner, manifest)
        # Verification must really install declared packages, not merely run help.
        if (clean / "pyproject.toml").exists():
            project = tomllib.loads((clean / "pyproject.toml").read_text()).get("project", {})
            installed = {p["name"].lower().replace("_", "-") for p in json.loads(output)} if not code else set()
            if project.get("name", "").lower().replace("_", "-") not in installed:
                scanner.add("verification", "quality", "project-not-installed", "pyproject.toml")
        result["status"] = "pass" if not code and result["dependencies"]["blocked"] == 0 else "blocked"
    return result


def audit(repo: Path, terms: list[str], manifest: dict, private_repos: list[str], verify_commands: bool, report_dir: Path, timeout: int) -> dict:
    return audit_with_mode(repo, terms, manifest, private_repos, verify_commands, report_dir, timeout)


def audit_with_mode(repo: Path, terms: list[str], manifest: dict, private_repos: list[str], verify_commands: bool, report_dir: Path, timeout: int, no_venv: bool = False) -> dict:
    scanner = Scanner(terms, private_repos, manifest["approvals"])
    scanner.tree(repo)
    scanner.history(repo)
    licensing = license_audit(repo, scanner, manifest)
    quality_audit(repo, scanner, manifest)
    if verify_commands:
        verification = verify_with_mode(repo, report_dir, scanner, manifest, timeout, True) if no_venv else verify(repo, report_dir, scanner, manifest, timeout)
        if verification.get("dependencies") is not None:
            licensing["dependencies"] = "pass" if not verification["dependencies"]["blocked"] else "blocked"
    else:
        verification = {"status": "not-run", "commands": []}
        scanner.add("verification", "quality", "verification-not-run", "release-check.json")
    unresolved = [f for f in scanner.findings if not f["reviewed"]]
    return {"version": VERSION, "ready": not unresolved, "counts": dict(Counter(f["category"] for f in unresolved)), "reviewed_count": sum(f["reviewed"] for f in scanner.findings), "stats": dict(scanner.stats), "license": licensing, "verification": verification, "findings": scanner.findings}


def group_of(finding: dict) -> str:
    return next((label for label, test in GROUPS if test(finding)), "scan coverage")


def fix_for(finding: dict) -> str:
    scope = finding["scope"]
    if finding.get("why") == "source-only" and scope in {"history", "metadata"}:
        return "Informational: this finding belongs to the SOURCE repository. Its history and Git metadata were not copied into the export. Keep the source private." + (" Revoke any exposed credential at the provider." if finding["category"] == "secrets" else "")
    snapshot = finding.get("origin") == "export" and scope in {"history", "metadata"}
    if finding["kind"] == "missing-document":
        return {
            "CONTRIBUTING.md": "Create CONTRIBUTING.md with instructions for setting up development, running tests and proposing changes.",
            "SECURITY.md": "Create SECURITY.md with supported versions and a private way to report vulnerabilities.",
        }.get(finding["path"], FIXES["missing-document"])
    if finding["category"] == "personal" and finding["kind"] != "denylist":
        if finding.get("reviewed"):
            return f'Approval covers only scope "{scope}". Other scopes require separate approvals.'
        if finding["kind"] == "email" and scope == "metadata" and (finding["path"].startswith("@commit/") or finding["path"] == "@config"):
            return "Git contains an author or committer email address. Use --verify --export to make a one-commit copy with generic authorship and no source Git config. Keep the original history private. Editing working files cannot remove commit metadata; do not approve a real personal address just to pass."
        approval = f'This finding still lacks approval in scope "{scope}". A deliberate public example needs an approval for this scope in release-check.json.'
        return approval + " " + (HISTORY_FIX if scope in {"history", "metadata"} and not snapshot else FIXES[finding["kind"]])
    if finding["scope"] in {"history", "metadata"} and finding["category"] in {"personal", "secrets"} and not snapshot:
        return HISTORY_FIX + (" Revoke the credential at the provider." if finding["category"] == "secrets" else "")
    return FIXES.get(finding["kind"], "Review this item by hand and run again.")


def finding_location(finding: dict) -> str:
    path, line = finding["path"], finding["line"]
    if path.startswith("@commit/"):
        field = {1: "author metadata", 2: "committer metadata"}.get(line, "message or encoding metadata")
        return "commit " + finding.get("object", path.removeprefix("@commit/")) + " " + field
    if path == "@config":
        return ".git/config (local Git configuration, entry " + str(line) + ")"
    return path + (":" + str(line) if line else "")


def record_export_audit(target: Path, report: dict) -> dict:
    classification = classify(report)
    verification = report["verification"]
    record = {"format": 1, "verdict": classification["verdict"],
              "blocking_count": len(classification["blocking"]),
              "verified": verification["status"] == "pass",
              "isolation": verification.get("isolation", "not-run"),
              "commit": git(target, "rev-parse", "HEAD").strip().decode("ascii")}
    path = target / ".git" / AUDIT_RECORD
    path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return record


def read_export_audit(target: Path) -> dict | None:
    try:
        blocked = blocked_artifact(target)
        record = json.loads((target / AUDIT_RECORD if blocked else target / ".git" / AUDIT_RECORD).read_text(encoding="utf-8"))
        if (not isinstance(record, dict) or type(record.get("format")) is not int or record["format"] != 1
                or record.get("verdict") not in {"PASS", "FIX-THESE"}
                or type(record.get("blocking_count")) is not int or record["blocking_count"] < 0
                or type(record.get("verified")) is not bool
                or record.get("isolation") not in {"venv", "uv", "virtualenv", "current-interpreter (less isolated)", "not-run"}
                or (record["verified"] and record["isolation"] == "not-run")
                or (not blocked and record.get("commit") != git(target, "rev-parse", "HEAD").strip().decode("ascii"))
                or (record["verdict"] == "PASS" and (record["blocking_count"] != 0 or not record["verified"]))):
            return None
        return record
    except (OSError, ValueError, TypeError, AuditError):
        return None


def classify(report: dict) -> dict:
    target = report.get("export", report)
    key = lambda f: tuple(f[k] for k in ("category", "kind", "path", "line", "fingerprint"))
    blocking, warnings = [], []
    for finding in target["findings"]:
        finding["group"] = group_of(finding)
        finding.pop("why", None)
        if finding["reviewed"]:
            finding.update(severity="warning", why="acknowledged")
            warnings.append(finding)
        else:
            finding["severity"] = "blocking"
            blocking.append(finding)
    if "export" in report:
        target_keys = {key(f) for f in target["findings"]}
        for finding in report["findings"]:
            finding["group"] = group_of(finding)
            finding.pop("why", None)
            finding["severity"] = "warning" if finding["reviewed"] else "blocking"
            if finding["reviewed"]:
                finding["why"] = "acknowledged"
            if not finding["reviewed"] and (finding["scope"] in {"history", "metadata"} or key(finding) not in target_keys):
                finding.update(severity="warning", why="source-only")
                warnings.append(finding)
    verdict = "PASS" if target["ready"] and not blocking else "FIX-THESE"
    return {"verdict": verdict, "blocking": blocking, "warnings": warnings}


def untracked_files(repo: Path, tracked: set[str]) -> list[str]:
    submodules = submodule_paths(repo)
    paths = []
    for root, dirs, files in os.walk(repo, followlinks=False):
        relative = Path(root).relative_to(repo)
        dirs[:] = [d for d in dirs if d != ".git" and (relative / d).as_posix() not in submodules and (d not in GENERATED or any(p.startswith((relative / d).as_posix() + "/") for p in tracked))]
        for name in files + [d for d in dirs if (Path(root) / d).is_symlink()]:
            rel = (relative / name).as_posix()
            if name != ".git" and rel not in tracked:
                paths.append(rel)
    return sorted(paths)


def scrub_plan(report: dict, repo: Path, manifest: dict, scanner: Scanner) -> dict:
    tracked = {os.fsdecode(p) for p in git(repo, "ls-files", "-z").split(b"\0") if p}
    excluded = [*DEFAULT_EXCLUDES, *manifest["exclude"]]
    drop = [scanner.safe_path(p) for p in tracked if credential_file(p) or any(match_path(a.as_posix(), excluded) for a in (Path(p), *Path(p).parents) if a.as_posix() != ".")]
    left = untracked_files(repo, tracked)
    unresolved = [f for f in report["findings"] if not f["reviewed"]]
    history = [f for f in unresolved if f["scope"] in {"history", "metadata"}]
    classes = {label: {"history": 0, "files": 0} for label, _ in GROUPS[:6]}
    for finding in unresolved:
        label = group_of(finding)
        if label in classes and finding["scope"] in {"tree", "history", "metadata"}:
            classes[label]["files" if finding["scope"] == "tree" else "history"] += 1
    return {
        "working_changes": bool(git(repo, "status", "--porcelain", "--untracked-files=no")),
        "drop_files": sorted(drop),
        "replace_or_remove": [f for f in unresolved if f["scope"] == "tree" and f["category"] in {"personal", "secrets"}],
        "flatten_history": True,
        "review_media": [f for f in unresolved if f["category"] == "media"],
        "preserve_attribution": True,
        "not_exported": [scanner.safe_path(p) for p in left[:50]],
        "not_exported_count": len(left),
        "history": {"commits": report["stats"].get("history_commits", 0), "findings": len(history)},
        "by_class": classes,
    }


def build_plan(report: dict, scrub: dict) -> list[dict]:
    target = report.get("export", report)
    steps = []
    def add(identifier, actor, text, status=None):
        steps.append({"id": identifier, "actor": actor, "status": status or ("needed" if actor == "you" else "done" if "export" in report else "planned"), "text": text})
    commits = scrub['history']['commits']
    add("read", "tool", f"Read the SOURCE working files and all {commits} {'commit' if commits == 1 else 'commits'} of local history. Change nothing in the repository.", "done")
    if scrub["drop_files"]:
        add("drop-excluded", "tool", f"Leave out {len(scrub['drop_files'])} tracked files that match the built-in or manifest exclusions.")
    if scrub["not_exported_count"]:
        add("leave-untracked", "tool", f"Leave out {scrub['not_exported_count']} files git does not track. They stay in your folder.")
    add("drop-history", "tool", f"Discard all history. The export gets one new commit. This removes {scrub['history']['findings']} findings from history and commit metadata; matching working-file content still needs fixing.")
    add("generic-commit", "tool", "Write that commit with a generic author, a UTC date, no remote and no hooks.")
    add("keep-notices", "tool", "Copy license and notice files unchanged. Stop if one from history is missing.")
    blocking = [f for f in target["findings"] if not f["reviewed"]]
    content = [f for f in blocking if f["scope"] == "tree" and f["category"] in {"personal", "secrets"}]
    media = [f for f in blocking if f["scope"] == "tree" and f["category"] == "media"]
    other = [f for f in blocking if f["scope"] == "tree" and f not in content and f not in media]
    if content:
        counts = Counter(group_of(f) for f in content)
        classes = ", ".join(f"{label}: {counts[label]}" for label, _ in GROUPS if counts[label])
        add("fix-content", "you", f"Edit {len(content)} findings in files that will ship, then run again: {classes}.")
    if other:
        add("fix-other", "you", f"Fix {len(other)} license, documentation, test or coverage items listed under BLOCKING.")
    if media:
        add("review-media", "you", f"Look at {len(media)} media or binary files and record each approval in release-check.json.")
    add("rescan", "tool", "Scan the export again, including its new commit.")
    if target["verification"]["status"] != "not-run":
        verified = target["verification"]["status"] == "pass" and not any(f["scope"] == "verification" for f in blocking)
        add("verify", "tool", "Run the declared quickstart and checks in a fresh clone with an empty HOME and a new virtual environment.", "done" if verified else "planned")
    else:
        add("verify", "you", "Run again with --verify so the declared commands are executed.")
    add("digest", "tool", "Record the export digest so you can prove later that nothing changed.")
    add("publish", "you", "Publish only after a clean export verdict, a PASS from --check-digest, the test list and owner approval. release-check never publishes.")
    return steps


def test_list(report: dict, manifest: dict, scanner: Scanner) -> list[dict]:
    target = report.get("export", report)
    results = {r["step"]: r for r in target["verification"].get("commands", [])}
    items = []
    def automatic(identifier, step, text):
        result = results.get(step)
        status = "not run" if result is None else "passed" if result["exit_code"] == 0 else "failed"
        items.append({"id": identifier, "kind": "automatic", "status": status, "text": text})
    def manual(identifier, text):
        items.append({"id": identifier, "kind": "manual", "status": "to do", "text": text})
    for number, entry in enumerate(manifest["quickstart"], 1):
        path = entry.get("file", "README.md")
        path = path if isinstance(path, str) else "README.md"
        safe = scanner.safe_path(path)
        if Path(path).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", path):
            safe = "[path-" + fingerprint(path) + "]"
        line = entry.get("line", 0)
        line = line if type(line) is int else 0
        automatic(f"quickstart-{number}", number, f"Quickstart step {number} ({safe} line {line}) works in a clean clone.")
    for number, entry in enumerate(manifest["checks"], 1):
        role = entry.get("role")
        role = role if isinstance(role, str) and role in ROLES else "other"
        automatic(f"check-{number}", len(manifest["quickstart"]) + number, f"The declared {role} check (release-check.json checks, entry {number}) passes in a clean clone.")
    findings = report["findings"] + (target["findings"] if "export" in report else [])
    history = sum(not f["reviewed"] and f["scope"] in {"history", "metadata"} for f in report["findings"])
    manual("fresh-clone", "Clone the export into an empty folder, ideally on another machine or user account, and follow the README from its first line. Nothing may depend on files, tools or logins only you have.")
    if "export" in report:
        manual("inspect-commit", "Read the export's single commit with `git log --format=fuller -1`. Author, committer, date and message must be generic.")
    manual("publish-export-not-original", f"Only after a clean export verdict, PASS from --check-digest and owner approval, publish the export folder as a new repository. Do not switch the original repository to public: its old commits were not rewritten ({history} findings in history).")
    if any(f["category"] == "secrets" for f in findings):
        manual("rotate-credentials", "Revoke or replace every credential the audit found, including those only in old commits.")
    media = {f["path"] for f in findings if f["category"] == "media"}
    if media:
        manual("review-media", f"Open each of the {len(media)} media or binary files and check its contents and embedded metadata.")
    manual("license-holder", "Confirm the license and the copyright line name who you want shown publicly.")
    if target["license"].get("dependencies") != "stdlib-only" or any(f["kind"] in {"vendored-attribution-review", "dependency-ecosystem-manual-review"} for f in findings):
        manual("third-party", "Check that every dependency and every copied file has a license that allows redistribution, and that its notice is kept.")
    manual("hosting-side", "Check what this tool cannot see on the hosting site: repository name and description, topics, issues, pull requests, wiki, releases, CI logs and stored secrets.")
    if any(f["kind"] in {"manual-review", "binary-review", "lfs-content-not-scanned", "submodule", "symlink"} for f in findings):
        manual("unreadable-content", "Check content this tool cannot read: text inside images, archives, large-file objects, submodules and link targets.")
    if "export" in report:
        digest = target.get("digest", "DIGEST")
        manual("confirm-digest", f"Immediately before publishing, run `release-check <export-folder> --check-digest {digest}` and publish only if it says PASS.")
    manual("after-publish", "Right after publishing, open the public page while signed out and repeat the quickstart from there.")
    return items


def format_text(report: dict) -> str:
    target = report.get("export", report)
    classified = {
        "blocking": [f for f in target["findings"] if not f["reviewed"]],
        "warnings": [f for f in target["findings"] if f["reviewed"]] +
                    ([f for f in report["findings"] if f.get("why") == "source-only"] if "export" in report else []),
    }
    verdict = report.get("verdict", "INCOMPLETE")
    lines = [f"release-check {report['version']}", "", f"VERDICT: {verdict}"]
    if verdict == "PASS":
        lines.append("The declared checks passed and no detected findings block the judged target. Finish TEST BEFORE PUBLISHING and manual review.")
        lines.append(PASS_LIMITATIONS)
    if len(classified['blocking']) == 1 and classified['blocking'][0]['kind'] == 'verification-not-run':
        lines.append("No content or repository problems found. The single reason for FIX-THESE is verification-not-run: run with --verify.")
    if any(f['kind'] == 'venv-creation-failed' for f in classified['blocking']):
        lines.append("Verification could not create a venv; quickstart and tests did not run.")
        lines.append("No-admin fix: install uv into your home with the official script (README), then re-run --verify; or use --verify-no-venv for a declared stdlib-only project. Details follow under BLOCKING.")
    lines += ["Judged: " + ("the export (one commit, no history)" if "export" in report and target['ready'] else "the blocked export snapshot (no Git repository, no history)" if "export" in report else "the source repository"),
              f"Blocking: {len(classified['blocking'])}   Warnings: {len(classified['warnings'])}"]
    if "export" in report and not target["ready"]:
        lines.append("WARNING: " + BLOCKED_EXPORT_WARNING)
    stats = target.get("stats", {})
    commits = stats.get('history_commits', 0)
    lines.append(f"Scanned: {stats.get('tree_files', 0)} working files, {commits} {'commit' if commits == 1 else 'commits'}" + (" in the temporary export snapshot; SOURCE history is informational" if "export" in report else ""))
    if report.get("scrub_plan", {}).get("working_changes"):
        lines.append("NOTICE: Tracked files have uncommitted or staged changes. Exports use current working bytes.")
    for key, title in (("blocking", "BLOCKING - fix these, then run again"), ("warnings", "WARNINGS - reported, not blocking")):
        lines += ["", title]
        findings = classified[key]
        if not findings:
            lines.append("   none")
        number = 0
        for label, _ in GROUPS:
            group = sorted((f for f in findings if group_of(f) == label), key=lambda f: (f["path"], f["line"], f["kind"]))
            if not group:
                continue
            number += 1
            why = ", " + ", ".join(sorted({f["why"] for f in group})) if key == "warnings" else ""
            lines.append(f"{number}. {label} ({len(group)}{why})")
            for finding in group[:10]:
                location = finding_location(finding)
                term = "   term " + str(finding["term_index"]) if "term_index" in finding else ""
                scope = "export snapshot (approval scope " + finding['scope'] + ")" if finding.get('origin') == 'export' and finding['scope'] in {'history', 'metadata'} else "SOURCE " + finding['scope'] if finding.get('why') == 'source-only' else finding['scope']
                lines.append(f"   {finding['kind']}   {location}   {scope}   id {finding['fingerprint']}{term}")
            if len(group) > 10:
                lines.append(f"   ... and {len(group) - 10} more in report.md")
            for fix in dict.fromkeys(fix_for(f) for f in group):
                lines.append("   Fix: " + fix)
    dispositions = (target.get("verification", {}).get("dependencies") or {}).get("owner_dispositions", [])
    if dispositions:
        lines += ["", "OWNER LICENSE DISPOSITIONS (no installed license file)"]
        lines += ["   " + json.dumps(item, sort_keys=True) for item in dispositions]
    if target.get("license", {}).get("owner_disposition"):
        lines += ["", "OWNER UPSTREAM LICENSE DISPOSITION (verbatim file evidence)",
                  "   " + json.dumps(target["license"]["owner_disposition"], sort_keys=True)]
    lines += ["", "PLAN"]
    for number, step in enumerate(report.get("plan", []), 1):
        lines.append(f" {number}. [{step['actor']}, {step['status']}] {step['text']}")
    if report.get("scrub_plan", {}).get("by_class"):
        lines.append("   Scrub class counts:")
    for label, counts in report.get("scrub_plan", {}).get("by_class", {}).items():
        lines.append(f"   {label}: {counts['files']} in SOURCE files, {counts['history']} in SOURCE history")
    lines += ["", "TEST BEFORE PUBLISHING"]
    for number, item in enumerate(report.get("pre_publish_tests", []), 1):
        lines.append(f" {number}. [{item['status']}] {item['text']}")
    if "export" in report and "digest" in report["export"]:
        lines += ["", "Export digest: " + report["export"]["digest"]]
        if not target["ready"]:
            lines.append("Export folder: requested destination + .BLOCKED (never publish)")
    verification = target.get("verification", {})
    lines.append("Verification: " + ("verified" if verification.get("status") == "pass" else "not verified") + " (" + ("no-venv; " if verification.get("isolation", "").startswith("current-interpreter") else "") + verification.get("isolation", "not-run") + ")")
    locator = report.get("report", "report.json").removesuffix("report.json")
    lines += ["", "REPORT: " + locator + "report.md and report.json, under your reports folder"]
    return ("\n".join(lines) + "\n").encode("ascii", "backslashreplace").decode("ascii")


def format_markdown(report: dict) -> str:
    lines = format_text(report).splitlines()
    lines[0] = "# " + lines[0]
    for index, line in enumerate(lines):
        if line.startswith(("VERDICT:", "BLOCKING", "WARNINGS", "PLAN", "TEST BEFORE PUBLISHING", "REPORT:")):
            lines[index] = "## " + line
    lines += ["", "## All findings", "", "| Scope | Kind | Path | Line | Fingerprint | Term index | Reviewed |", "| --- | --- | --- | ---: | --- | ---: | --- |"]
    findings = report["findings"] + report.get("export", {}).get("findings", [])
    for finding in findings:
        location = finding_location(finding) if finding["scope"] == "metadata" else finding["path"]
        path = location.replace("|", "&#124;").replace("<", "&lt;").replace(">", "&gt;")
        origin = "export snapshot" if finding.get('origin') == 'export' else "SOURCE" if 'export' in report else "source"
        lines.append(f"| {origin}: {finding['scope']} | {finding['kind']} | {path} | {finding['line']} | {finding['fingerprint']} | {finding.get('term_index', '')} | {finding['reviewed']} |")
    target = report.get("export", report)
    lines += ["", "License: " + json.dumps(target["license"], sort_keys=True), "", "Verification: " + json.dumps(target["verification"], sort_keys=True)]
    return ("\n".join(lines) + "\n").encode("ascii", "backslashreplace").decode("ascii")


def write_reports(directory: Path, report: dict):
    markdown = format_markdown(report)
    content = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    for name, text in (("report.json", content), ("report.md", markdown)):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = PrivateParser(prog="release-check", description=__doc__, epilog="Audit first, fix the blockers, then export with --verify.")
    parser.json_mode = "--json" in raw_args
    parser.add_argument("repo", type=Path, help="Repository root to audit")
    parser.add_argument("--denylist", type=Path, default=os.environ.get("RELEASE_CHECK_DENYLIST") or None, help="Private terms file outside the repository (or RELEASE_CHECK_DENYLIST)")
    parser.add_argument("--reports", type=Path, default=os.environ.get("RELEASE_CHECK_REPORTS", "~/.local/state/release-check"), help="Private reports folder (or RELEASE_CHECK_REPORTS)")
    parser.add_argument("--manifest", type=Path, help="Use an external manifest instead of release-check.json")
    parser.add_argument("--private-repo", action="append", default=[], help="Known-private repo URL or owner/name; kept out of reports")
    verification_args = parser.add_mutually_exclusive_group()
    verification_args.add_argument("--verify", action="store_true", help="Execute reviewed quickstart and checks in a fresh clone and venv")
    verification_args.add_argument("--verify-no-venv", action="store_true", help="For declared stdlib-only projects: fresh clone and HOME, current interpreter (less isolated)")
    parser.add_argument("--timeout", type=int, default=300, help="Seconds allowed per declared command (default: 300)")
    parser.add_argument("--scrub-plan", action="store_true", help="Include the scrub-plan document after the legacy JSON summary")
    parser.add_argument("--json", action="store_true", help="Print the legacy JSON summary instead of readable text")
    parser.add_argument("--export", type=Path, help="Build a one-commit copy in a new folder outside the source")
    parser.add_argument("--check-digest", metavar="HEX", help="Check an export against its reported digest without a terms file")
    args = parser.parse_args(raw_args)
    os.umask(0o077)
    directory = None
    owned_export = None
    try:
        if args.check_digest is not None:
            if not re.fullmatch(r"[a-fA-F0-9]{64}", args.check_digest):
                raise AuditError("invalid-digest")
            repo = args.repo.expanduser().resolve()
            if not blocked_artifact(repo):
                validate_repo(repo)
            try:
                unchanged = export_digest(repo) == args.check_digest.lower()
            except AuditError as error:
                if str(error) != "export-not-clean":
                    raise
                unchanged = False
            record = read_export_audit(repo) if unchanged else None
            clean = not blocked_artifact(repo) and unchanged and record is not None and record["verdict"] == "PASS" and record["blocking_count"] == 0 and record["verified"]
            verdict = "PASS" if clean else "FIX-THESE"
            if clean:
                text = "DIGEST MATCHES AND THE EXPORT IS CLEAN: 0 blocking findings (PASS)"
            elif unchanged and record is not None:
                text = f"DIGEST MATCHES BUT THE EXPORT WAS NOT CLEAN: {record['blocking_count']} blocking findings (FIX-THESE)"
            elif unchanged:
                text = "DIGEST MATCHES BUT THE EXPORT WAS NOT CLEAN: unknown blocking findings (FIX-THESE). No valid recorded audit; export again with --verify."
            else:
                text = "The export changed or is not a single clean commit. File contents, modes and modification times are part of the digest, as is Git metadata. Restoring bytes alone may not restore the digest. Export again into a new folder."
            print(f"release-check {VERSION}\nVERDICT: {verdict}\n{text}")
            verification_text = "not verified" if unchanged else "not established because the digest does not match"
            if record and record["verified"]:
                verification_text = "verified (--verify-no-venv; current interpreter, less isolated)" if record["isolation"].startswith("current-interpreter") else "verified (--verify; fresh " + record["isolation"] + ")"
            print("Verification: " + verification_text)
            if clean:
                print(PASS_LIMITATIONS)
            return 0 if clean else 1
        if not args.denylist:
            raise AuditError("denylist-required")
        repo = args.repo.expanduser().resolve()
        validate_repo(repo)
        denylist = Path(args.denylist).expanduser().resolve()
        if denylist == repo or repo in denylist.parents:
            raise AuditError("denylist-inside-source")
        terms = load_terms(denylist)
        manifest = manifest_for(repo, args.manifest)
        scanner = Scanner(terms, args.private_repo, manifest["approvals"])
        root = Path(args.reports).expanduser().resolve()
        if root == repo or repo in root.parents:
            raise AuditError("reports-inside-source")
        if args.export:
            target = args.export.expanduser().resolve()
            if target == denylist or target in denylist.parents:
                raise AuditError("export-contains-denylist")
            blocked = target.with_name(target.name + ".BLOCKED")
            if any(path.exists() or path.is_symlink() for path in (target, blocked)):
                raise export_destination_error(target, blocked)
            if target == repo or repo in target.parents:
                raise AuditError("export-inside-source")
            if target in repo.parents:
                raise AuditError("export-parent-of-source")
        if args.timeout < 1:
            raise AuditError("invalid-timeout")
        # Raw repository names never become report directory names if they contain a term.
        common_dir = Path(git(repo, "rev-parse", "--git-common-dir").decode().strip())
        if not common_dir.is_absolute():
            common_dir = repo / common_dir
        repo_name = common_dir.resolve().parent.name if common_dir.name == ".git" else repo.name
        name = scanner.safe_path(repo_name)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        directory = root / name / stamp
        directory.mkdir(mode=0o700, parents=True)
        directory.chmod(0o700)
        run_audit = (lambda *params: audit_with_mode(*params, no_venv=True)) if args.verify_no_venv else audit
        report = run_audit(repo, terms, manifest, args.private_repo, args.verify or args.verify_no_venv, directory, args.timeout)
        report["scrub_plan"] = scrub_plan(report, repo, manifest, scanner)
        if args.export:
            requested_target = args.export.expanduser().resolve()
            target = requested_target.with_name(requested_target.name + ".BLOCKED")
            if not args.json:
                print("Export starts in a private *.BLOCKED folder; the requested destination is created only after a clean verdict.")
            if target.exists() or target.is_symlink():
                raise export_destination_error(target)
            owned_export = target
            copied = copy_tree(repo, target, manifest, scanner)
            export_report = run_audit(target, terms, manifest_for(target, args.manifest), args.private_repo, args.verify or args.verify_no_venv, directory, args.timeout)
            for finding in scanner.findings:
                export_report["findings"].append(finding)
                export_report["counts"][finding["category"]] = export_report["counts"].get(finding["category"], 0) + 1
                export_report["ready"] = False
            # Historical attribution must survive the public snapshot, not only current files.
            for commit in git(repo, "rev-list", "--all", "--reflog").splitlines():
                for entry in filter(None, git(repo, "ls-tree", "-r", "-z", commit.decode()).split(b"\0")):
                    metadata, raw_path = entry.split(b"\t", 1)
                    path = raw_path.decode("utf-8", "surrogateescape")
                    if protected(path) and not (target / path).is_file():
                        finding_scanner = Scanner(terms)
                        finding_scanner.add("export", "license", "historical-attribution-missing", path, value=metadata)
                        export_report["findings"].extend(finding_scanner.findings)
                        export_report["counts"]["license"] = export_report["counts"].get("license", 0) + 1
                        export_report["ready"] = False
                    elif protected(path) and any(x in Path(path).name.upper() for x in ("NOTICE", "UPSTREAM")):
                        oid = metadata.split()[2].decode()
                        old_raw = git(repo, "cat-file", "blob", oid)
                        old = re.sub(rb"\s+", b" ", old_raw).strip()
                        current = re.sub(rb"\s+", b" ", (target / path).read_bytes()).strip()
                        if any(re.sub(rb"\s+", b" ", line).strip() not in current for line in old_raw.splitlines() if line.strip()):
                            finding_scanner = Scanner(terms)
                            finding_scanner.add("export", "license", "historical-attribution-changed", path, value=old)
                            export_report["findings"].extend(finding_scanner.findings)
                            export_report["counts"]["license"] = export_report["counts"].get("license", 0) + 1
                            export_report["ready"] = False
            finding_scanner = Scanner(terms)
            apache_attribution_audit(repo, finding_scanner, target, "export")
            if finding_scanner.findings:
                export_report["findings"].extend(finding_scanner.findings)
                export_report["counts"]["license"] = export_report["counts"].get("license", 0) + len(finding_scanner.findings)
                export_report["ready"] = False
            export_report["commit"] = git(target, "rev-parse", "HEAD").strip().decode("ascii")
            for finding in export_report['findings']:
                finding['origin'] = 'export'
            export_report["audit_record"] = record_export_audit(target, export_report)
            if export_report["ready"]:
                if requested_target.exists() or requested_target.is_symlink():
                    raise export_destination_error(requested_target)
                target.rename(requested_target)
                target = requested_target
                owned_export = None
            else:
                quarantine_export(target)
                owned_export = None
            export_report["folder_suffix"] = "" if export_report["ready"] else ".BLOCKED"
            export_report["digest"] = export_digest(target)
            export_report["file_count"] = len(copied["files"])
            export_report["not_exported"] = {"count": len(copied["not_exported"]), "paths": [scanner.safe_path(p) for p in copied["not_exported"][:50]]}
            report["export"] = export_report
        classification = classify(report)
        report["verdict"] = classification["verdict"]
        report["summary"] = {key: len(classification[key]) for key in ("blocking", "warnings")}
        report["plan"] = build_plan(report, report["scrub_plan"])
        report["pre_publish_tests"] = test_list(report, manifest, scanner)
        report["report"] = name + "/" + stamp + "/report.json"
        write_reports(directory, report)
        summary = {"ready": report["ready"], "counts": report["counts"]}
        if "export" in report:
            summary["export_ready"] = report["export"]["ready"]
            summary["export_counts"] = report["export"]["counts"]
            if not report["export"]["ready"]:
                summary["export_warning"] = BLOCKED_EXPORT_WARNING
        # Only the relative report locator is printed (home names stay private).
        summary["report"] = name + "/" + stamp + "/report.json"
        if args.json:
            print(json.dumps(summary))
            if args.scrub_plan:
                print(json.dumps(report["scrub_plan"], indent=2))
        else:
            print(format_text(report), end="")
        return 0 if report.get("export", report)["ready"] else 1
    except (Exception, KeyboardInterrupt) as error:
        if owned_export is not None and owned_export.is_dir():
            quarantine_export(owned_export)
        # The CLI boundary must not expose paths or exception details in a traceback.
        code = error.args[0] if isinstance(error, AuditError) and len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0] in ERRORS else "audit-incomplete"
        try:
            if directory is not None and not (directory / "report.json").exists():
                write_reports(directory, {"version": VERSION, "verdict": "INCOMPLETE", "ready": False, "counts": {"coverage": 1}, "license": {"status": "unknown"}, "verification": {"status": "incomplete"}, "findings": [{"scope": "audit", "category": "coverage", "kind": "audit-incomplete", "path": "@audit", "line": 0, "fingerprint": fingerprint(b"audit-incomplete"), "reviewed": False}]})
        except Exception:
            # A failed report write must not bypass the private error response.
            pass
        print_error(code, args.json, error.detail if isinstance(error, AuditError) and code != "audit-incomplete" else None)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
