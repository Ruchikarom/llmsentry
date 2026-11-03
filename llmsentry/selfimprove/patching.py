"""Checks and git operations for candidate patches.

Only ALLOWED_PATHS may change. Example texts may not appear verbatim in
added lines. Every change is applied with git and reverted on rejection.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ALLOWED_PATHS = ("llmsentry/llmsentry/scanner.py",)  # relative to the git root
_DIFF_BLOCK = re.compile(r"```diff\n(.*?)```", re.DOTALL)
_BANNED = ("rename from", "rename to", "copy from", "copy to",
           "new file mode", "deleted file mode", "GIT binary patch", "Binary files")


def extract_diff(reply: str) -> str | None:
    match = _DIFF_BLOCK.search(reply)
    return match.group(1) if match else None


def _strip(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def check_paths(diff: str) -> list[str]:
    problems: list[str] = []
    headers = 0
    for line in diff.splitlines():
        if line.startswith(_BANNED):
            problems.append(f"disallowed change: {line}")
        elif line.startswith("diff --git "):
            for part in line.split()[2:4]:
                if _strip(part) not in ALLOWED_PATHS:
                    problems.append(f"path not allowed: {_strip(part)}")
        elif line.startswith(("--- ", "+++ ")):
            headers += 1
            path = line[4:].split("\t")[0].strip()
            if path == "/dev/null":
                problems.append("file creation or deletion is not allowed")
            elif _strip(path) not in ALLOWED_PATHS:
                problems.append(f"path not allowed: {_strip(path)}")
    if headers == 0:
        problems.append("diff has no file headers")
    return problems


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def verbatim_hits(diff: str, texts: dict[str, str], window: int = 60) -> list[str]:
    """Ids whose text (or a 60-character slice of it) appears in added lines."""
    added = " ".join(line[1:] for line in diff.splitlines()
                     if line.startswith("+") and not line.startswith("+++"))
    blob = _norm(added)
    hits = []
    for item_id, text in texts.items():
        body = _norm(text)
        if len(body) < 30:
            continue
        for start in range(0, max(1, len(body) - window + 1), 10):
            if body[start:start + window] in blob:
                hits.append(item_id)
                break
    return hits


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)


def git_root(project: Path) -> Path:
    proc = _git(project, "rev-parse", "--show-toplevel")
    if proc.returncode != 0:
        raise RuntimeError(f"{project} is not inside a git repository")
    return Path(proc.stdout.strip())


def current_branch(root: Path) -> str:
    return _git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


def tree_is_clean(root: Path) -> bool:
    return _git(root, "status", "--porcelain", "--untracked-files=no").stdout.strip() == ""


def apply_diff(root: Path, diff: str, scratch: Path) -> tuple[bool, str]:
    patch = scratch / "candidate.patch"
    patch.write_text(diff, encoding="utf-8")
    for args in (("apply", "--check", "-p1", str(patch)), ("apply", "-p1", str(patch))):
        proc = _git(root, *args)
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[:500]
    return True, ""


def revert(root: Path) -> None:
    _git(root, "checkout", "--", *ALLOWED_PATHS)


def commit(root: Path, message: str) -> str:
    _git(root, "add", "--", *ALLOWED_PATHS)
    proc = subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=selfimprove-harness",
         "-c", "user.email=selfimprove@localhost", "commit", "-q", "-m", message],
        capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"commit failed: {proc.stderr.strip()[:300]}")
    return _git(root, "rev-parse", "--short", "HEAD").stdout.strip()
