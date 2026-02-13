#!/usr/bin/env python3
"""Security audit script for scanning secrets in the repo and git history."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class Finding:
    source: str
    path: str
    line: int
    pattern: str
    match: str


PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("private_key_header", re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,20})?['\"]?[0-9a-zA-Z/+=]{40}['\"]?")),
    ("github_token", re.compile(r"ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{20,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("jwt", re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    ),
]

SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "docs/site_libs",
}

SKIP_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".pdf",
    ".zip",
    ".gz",
    ".rar",
    ".7z",
    ".kmz",
    ".qgz",
    ".mp4",
    ".mov",
    ".mp3",
    ".wav",
}


def run_git(args: List[str], repo_root: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", repo_root] + args,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def get_repo_root(start_path: str) -> Optional[str]:
    result = run_git(["rev-parse", "--show-toplevel"], start_path)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def is_binary(data: bytes) -> bool:
    return b"\x00" in data


def mask_value(value: str) -> str:
    if value.startswith("-----BEGIN"):
        return "PRIVATE_KEY_HEADER"
    cleaned = value.strip()
    if len(cleaned) <= 8:
        return "REDACTED"
    return f"{cleaned[:3]}...{cleaned[-2:]}"


def iter_text_lines(text: str) -> Iterable[Tuple[int, str]]:
    for index, line in enumerate(text.splitlines(), start=1):
        yield index, line


def scan_text(text: str, source: str, path: str) -> List[Finding]:
    findings: List[Finding] = []
    for pattern_name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    source=source,
                    path=path,
                    line=line,
                    pattern=pattern_name,
                    match=mask_value(match.group(0)),
                )
            )
    return findings


def should_skip(path: str, max_bytes: int) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in SKIP_EXTS:
        return True
    try:
        size = os.path.getsize(path)
    except OSError:
        return True
    return size > max_bytes


def scan_worktree(repo_root: str, max_bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    for root, dirs, files in os.walk(repo_root):
        rel_root = os.path.relpath(root, repo_root)
        dirs[:] = [
            d
            for d in dirs
            if os.path.join(rel_root, d) not in SKIP_DIRS and d not in SKIP_DIRS
        ]
        for name in files:
            path = os.path.join(root, name)
            rel_path = os.path.relpath(path, repo_root)
            if should_skip(path, max_bytes):
                continue
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError:
                continue
            if is_binary(data):
                continue
            text = data.decode("utf-8", errors="replace")
            findings.extend(scan_text(text, "worktree", rel_path))
    return findings


def scan_staged(repo_root: str, max_bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    result = run_git(["diff", "--cached", "--name-only", "-z"], repo_root, text=False)
    if result.returncode != 0:
        return findings
    names = result.stdout.split(b"\x00")
    for raw_name in names:
        if not raw_name:
            continue
        rel_path = raw_name.decode("utf-8", errors="replace")
        ext = os.path.splitext(rel_path)[1].lower()
        if ext in SKIP_EXTS:
            continue
        show = run_git(["show", f":{rel_path}"], repo_root, text=False)
        if show.returncode != 0:
            continue
        data = show.stdout
        if len(data) > max_bytes:
            continue
        if is_binary(data):
            continue
        text = data.decode("utf-8", errors="replace")
        findings.extend(scan_text(text, "staged", rel_path))
    return findings


def scan_git_history(repo_root: str, max_bytes: int) -> List[Finding]:
    findings: List[Finding] = []
    rev_list = run_git(["rev-list", "--objects", "--all"], repo_root)
    if rev_list.returncode != 0:
        return findings
    blob_entries: List[Tuple[str, str]] = []
    for line in rev_list.stdout.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) == 2:
            blob_entries.append((parts[0], parts[1]))

    if not blob_entries:
        return findings

    proc = subprocess.Popen(
        ["git", "-C", repo_root, "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    for sha, _path in blob_entries:
        proc.stdin.write(f"{sha}\n".encode("utf-8"))
    proc.stdin.flush()
    proc.stdin.close()

    for sha, path in blob_entries:
        header = proc.stdout.readline()
        if not header:
            break
        header_parts = header.decode("utf-8", errors="replace").strip().split()
        if len(header_parts) < 3:
            continue
        obj_type = header_parts[1]
        try:
            size = int(header_parts[2])
        except ValueError:
            size = 0
        data = proc.stdout.read(size)
        proc.stdout.read(1)
        if obj_type != "blob":
            continue
        if size > max_bytes:
            continue
        if is_binary(data):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXTS:
            continue
        text = data.decode("utf-8", errors="replace")
        findings.extend(scan_text(text, "history", path))

    proc.wait()
    return findings


def write_report(findings: List[Finding], report_path: str) -> None:
    payload: Dict[str, object] = {
        "findings": [finding.__dict__ for finding in findings],
        "count": len(findings),
    }
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan repository for sensitive information.")
    parser.add_argument("--path", default=".", help="Path inside the repository")
    parser.add_argument("--max-bytes", type=int, default=2_000_000, help="Max file size to scan")
    parser.add_argument("--no-history", action="store_true", help="Skip scanning git history")
    parser.add_argument("--no-worktree", action="store_true", help="Skip scanning working tree")
    parser.add_argument("--staged", action="store_true", help="Scan only staged files")
    parser.add_argument("--report", default="security_audit_report.json", help="Path to JSON report")
    args = parser.parse_args()

    repo_root = get_repo_root(args.path)
    if repo_root is None:
        print("ERROR: Not a git repository.", file=sys.stderr)
        return 2

    findings: List[Finding] = []

    if args.staged:
        findings.extend(scan_staged(repo_root, args.max_bytes))
    elif not args.no_worktree:
        findings.extend(scan_worktree(repo_root, args.max_bytes))

    if not args.no_history:
        findings.extend(scan_git_history(repo_root, args.max_bytes))

    write_report(findings, os.path.join(repo_root, args.report))

    print(f"Scan complete. Findings: {len(findings)}")
    if findings:
        for finding in findings:
            print(
                f"- {finding.source} {finding.path}:{finding.line} [{finding.pattern}] {finding.match}"
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
