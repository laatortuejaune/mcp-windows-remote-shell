#!/usr/bin/env python3
"""Audit every public-source candidate without printing matched secret values."""

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
EXPORT_SPEC = importlib.util.spec_from_file_location("relay_export", SCRIPT_DIR / "export-source.py")
EXPORTER = importlib.util.module_from_spec(EXPORT_SPEC)
assert EXPORT_SPEC.loader is not None
EXPORT_SPEC.loader.exec_module(EXPORTER)

FORBIDDEN_NAMES = {
    ".git", ".relay-session", ".wrangler", "node_modules", "dist", "release",
    "operator.json", "rendezvous.json", "worker-secrets.json", "mcp-config.json",
    "worker-configuration.d.ts", "wrangler.local.jsonc",
}
LEGACY_NAMES = {
    "LISEZ" + "MOI.txt", "de" + "marrer-re" + "lais.cmd",
    "net" + "toyer.cmd", "pre" + "parer-re" + "lais.command",
}

LEGACY_TERMS = [
    b"de" + b"pannage", "d" + "épannage", b"re" + b"lais",
    b"pa" + b"quet", b"net" + b"toyage", b"re" + b"branche",
    b"de" + b"marrer", b"net" + b"toyer",
]

CHECKS = {
    "email address": re.compile(rb"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
    "macOS user path": re.compile(b"/" + rb"Users/(?!<|YOUR_|EXAMPLE_)[^/\s\"']+"),
    "Unix home path": re.compile(b"/" + rb"home/(?!<|YOUR_|EXAMPLE_)[^/\s\"']+"),
    "Windows user path": re.compile(rb"(?i)[A-Z]:\\Users\\(?!<|YOUR_|EXAMPLE_)[^\\\r\n\"']+"),
    "live-looking Worker URL": re.compile(rb"(?i)https://(?!YOUR-WORKER(?:\.|/))[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev"),
    "live-looking quick-tunnel URL": re.compile(rb"https://[a-z]+-[a-z]+-[a-z]+-[a-z]+\.trycloudflare\.com"),
    "private key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "cloud access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "legacy non-English project term": re.compile(
        rb"(?i)\b(?:" + b"|".join(re.escape(term.encode() if isinstance(term, str) else term) for term in LEGACY_TERMS) + rb")\b"
    ),
}


def source_files(root: Path) -> list[Path]:
    return EXPORTER.candidates(root)


def inspect_file(path: Path, root: Path) -> list[tuple[str, str]]:
    relative = path.relative_to(root).as_posix()
    findings: list[tuple[str, str]] = []
    if not relative.isascii():
        findings.append((relative, "non-ASCII filename"))
    if any(part in FORBIDDEN_NAMES for part in path.relative_to(root).parts):
        findings.append((relative, "private or generated filename"))
    if path.name in LEGACY_NAMES:
        findings.append((relative, "legacy non-English filename"))
    data = path.read_bytes()
    if b"\0" in data:
        findings.append((relative, "binary/NUL content"))
        return findings
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        findings.append((relative, "non-UTF-8 text"))
    for category, pattern in CHECKS.items():
        if pattern.search(data):
            findings.append((relative, category))
    if path.suffix.lower() in {".ps1", ".cmd"}:
        if any(byte >= 128 for byte in data):
            findings.append((relative, "non-ASCII Windows script"))
        if b"\n" in data.replace(b"\r\n", b""):
            findings.append((relative, "Windows script without CRLF-only newlines"))
    return findings


def historical_blobs(root: Path) -> tuple[int, list[tuple[str, str]]]:
    git = root / ".git"
    if not git.exists():
        return 0, []
    revisions = subprocess.run(
        ["git", "-C", str(root), "rev-list", "--all"], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    ).stdout.splitlines()
    seen: set[str] = set()
    findings: list[tuple[str, str]] = []
    for revision in revisions:
        tree = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-r", "-z", revision], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout.split(b"\0")
        for row in tree:
            if not row:
                continue
            metadata, raw_name = row.split(b"\t", 1)
            mode, kind, object_id = metadata.decode().split()
            del mode
            if kind != "blob" or object_id in seen:
                continue
            seen.add(object_id)
            data = subprocess.run(
                ["git", "-C", str(root), "cat-file", "blob", object_id], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            ).stdout
            name = raw_name.decode("utf-8", errors="replace")
            for category, pattern in CHECKS.items():
                if pattern.search(data):
                    findings.append((name, f"historical {category}"))
            if Path(name).name in LEGACY_NAMES:
                findings.append((name, "historical legacy filename"))
    # Author identities exist even when their values are not echoed here.
    if revisions:
        findings.append((".git", "commit author identity metadata"))
    return len(seen), sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=SCRIPT_DIR.parent)
    parser.add_argument("--history", action="store_true", help="also inspect all Git blobs and flag author metadata")
    args = parser.parse_args()
    root = args.root.resolve()
    files = source_files(root)
    findings = [finding for path in files for finding in inspect_file(path, root)]
    historical_count = 0
    if args.history:
        historical_count, history_findings = historical_blobs(root)
        findings.extend(history_findings)
    print(f"Reviewed {len(files)} source files and filenames.")
    if args.history:
        print(f"Reviewed {historical_count} unique historical Git blobs.")
    if findings:
        print("Privacy review failed. Matched values are intentionally not displayed:")
        for name, category in sorted(set(findings)):
            print(f"- {name}: {category}")
        return 1
    print("No direct personal-data or credential indicators matched the publication rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
