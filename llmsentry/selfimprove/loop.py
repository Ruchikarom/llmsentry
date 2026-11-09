"""Self-improvement loop for the llmsentry scanner.

Each round: score the dev set and the regression corpus, show the proposer
only the dev misses and dev false positives, apply one proposed change to
scanner.py, run the unit tests, re-score, and keep the change only if dev
improves with no regression on either set. The held-out set is scored at
baseline, and again at the end if anything was accepted. Its results are
logged as counts only, and it is never shown to the proposer.

Run from the project directory (the one containing llmsentry/):
    python3 -m selfimprove.loop --dev corpus/dev_2026-11-02
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import patching
from .corpus import load_set
from .prompt import SYSTEM, build_user_prompt
from .proposer import AnthropicProposer, GeminiProposer, StubProposer
from .scorer import evaluate

PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_MODELS = {"gemini": "gemini-3.8-flash", "anthropic": "claude-sonnet-5-5"}


@dataclass
class Config:
    project: Path
    orig: Path             # regression corpus: guards against any loss
    dev: Path              # learning signal: the proposer sees its misses
    heldout: Path | None   # counts only, at baseline and at the end
    out: Path
    threshold: float = 0.40
    rounds: int = 8
    max_rejects: int = 3
    max_misses: int = 8
    max_fps: int = 6
    dry_run: bool = False


def flagged(res: dict, threshold: float) -> bool:
    return res["error"] is None and res["score"] >= threshold


def score_set(cfg: Config, items: dict, evaluate_fn) -> dict:
    flat = items["malicious"] + items["benign"]
    return {r["id"]: r for r in evaluate_fn(cfg.project, flat)}


def summarize(items: dict, res: dict, threshold: float):
    mal, ben = items["malicious"], items["benign"]
    misses = [i for i in mal if not flagged(res[i["id"]], threshold)]
    fps = [i for i in ben if flagged(res[i["id"]], threshold)]
    counts = {"malicious": len(mal), "benign": len(ben), "misses": len(misses),
              "fps": len(fps), "errors": sum(1 for r in res.values() if r["error"])}
    return counts, misses, fps


def verdict(before: dict, after: dict) -> tuple[bool, str]:
    """before/after are {"orig": counts, "dev": counts}. Accept only strict dev gains."""
    for name in ("orig", "dev"):
        b, a = before[name], after[name]
        if a["errors"] > b["errors"]:
            return False, f"{name}: scanner errors rose {b['errors']} -> {a['errors']}"
        if a["misses"] > b["misses"]:
            return False, f"{name}: misses rose {b['misses']} -> {a['misses']}"
        if a["fps"] > b["fps"]:
            return False, f"{name}: false positives rose {b['fps']} -> {a['fps']}"
    b, a = before["dev"], after["dev"]
    if a["misses"] < b["misses"] or a["fps"] < b["fps"]:
        return True, f"dev misses {b['misses']} -> {a['misses']}, dev FPs {b['fps']} -> {a['fps']}"
    return False, "no improvement on dev"


def run_tests(project: Path) -> bool:
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests"], cwd=project,
                          capture_output=True, text=True, timeout=900)
    return proc.returncode == 0


def _fields(res: dict) -> dict:
    return {"score": res["score"], "signals": res["signals"], "error": res["error"]}


def _propose(proposer, user: str, texts: dict[str, str]) -> tuple[str | None, str | None]:
    try:
        reply = proposer.propose(SYSTEM, user)
    except Exception as exc:  # an API error ends this round only
        return None, f"proposer error: {exc}"
    diff = patching.extract_diff(reply)
    if diff is None:
        return None, "reply had no ```diff block"
    problems = patching.check_paths(diff)
    if problems:
        return None, "; ".join(problems)
    hits = patching.verbatim_hits(diff, texts)
    if hits:
        return None, f"diff contains example text verbatim: {', '.join(hits)}"
    return diff, None


def _commit_message(rnd: int, before: dict, after: dict, model: str) -> str:
    return (f"selfimprove round {rnd}: dev misses {before['dev']['misses']} -> "
            f"{after['dev']['misses']}, dev false positives {before['dev']['fps']} -> "
            f"{after['dev']['fps']}\n\nProposed-by: {model}\n")


class Recorder:
    def __init__(self, out: Path, log):
        self.path = out / "rounds.jsonl"
        self.log = log

    def write(self, kind: str, **fields) -> None:
        row = {"kind": kind, "time": dt.datetime.now().isoformat(timespec="seconds"), **fields}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
        self.log(f"[{kind}] " + " ".join(f"{k}={v}" for k, v in fields.items()
                                         if not isinstance(v, (dict, list))))


def run(cfg: Config, proposer, evaluate_fn=evaluate, tester=run_tests, log=print) -> dict:
    root = patching.git_root(cfg.project)
    branch = patching.current_branch(root)
    if not cfg.dry_run:
        if branch in ("main", "master"):
            raise RuntimeError(f"refusing to commit on '{branch}': check out a working branch first")
        if not patching.tree_is_clean(root):
            raise RuntimeError("tracked files have uncommitted changes: commit or stash them first")
    cfg.out.mkdir(parents=True, exist_ok=True)
    (cfg.out / "prompts").mkdir(exist_ok=True)
    rec = Recorder(cfg.out, log)
    scanner_path = cfg.project / "llmsentry" / "scanner.py"

    orig, dev = load_set(cfg.orig), load_set(cfg.dev)
    all_items = [i for s in (orig, dev) for lbl in s for i in s[lbl]]
    ids = [i["id"] for i in all_items]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate ids across the regression and dev sets")
    texts = {i["id"]: i["text"] for i in all_items}

    held = None
    if cfg.heldout and (cfg.heldout / "malicious.json").exists():
        held = load_set(cfg.heldout)
    else:
        log("held-out set not found; running without it")

    if not tester(cfg.project):
        raise RuntimeError("unit tests fail on the starting tree; fix them first")

    res_orig = score_set(cfg, orig, evaluate_fn)
    res_dev = score_set(cfg, dev, evaluate_fn)
    cur = {"orig": summarize(orig, res_orig, cfg.threshold)[0],
           "dev": summarize(dev, res_dev, cfg.threshold)[0]}
    rec.write("baseline", orig=cur["orig"], dev=cur["dev"])
    if held is not None:
        counts = summarize(held, score_set(cfg, held, evaluate_fn), cfg.threshold)[0]
        rec.write("heldout_baseline", **counts)

    history: list[str] = []
    rejects = accepted = 0
    stop = "baseline only" if cfg.rounds == 0 else "rounds exhausted"
    for rnd in range(1, cfg.rounds + 1):
        _, dev_misses, dev_fps = summarize(dev, res_dev, cfg.threshold)
        if not dev_misses and not dev_fps:
            stop = "nothing left to fix on dev"
            break
        scanner_src = scanner_path.read_text(encoding="utf-8")
        misses = [{**i, **_fields(res_dev[i["id"]])} for i in dev_misses[: cfg.max_misses]]
        fps = [{**i, **_fields(res_dev[i["id"]])} for i in dev_fps[: cfg.max_fps]]
        user = build_user_prompt(scanner_src, misses, fps, history)
        (cfg.out / "prompts" / f"round_{rnd:02d}.txt").write_text(user, encoding="utf-8")

        diff, reason = _propose(proposer, user, texts)
        passed, after = False, None
        if reason is None:
            ok, err = patching.apply_diff(root, diff, cfg.out)
            reason = None if ok else f"patch does not apply: {err}"
        if reason is None and not tester(cfg.project):
            reason = "unit tests fail"
        if reason is None:
            cand_orig = score_set(cfg, orig, evaluate_fn)
            cand_dev = score_set(cfg, dev, evaluate_fn)
            after = {"orig": summarize(orig, cand_orig, cfg.threshold)[0],
                     "dev": summarize(dev, cand_dev, cfg.threshold)[0]}
            passed, reason = verdict(cur, after)

        digest = hashlib.sha256((diff or "").encode("utf-8")).hexdigest()[:12]
        if passed and not cfg.dry_run:
            sha = patching.commit(root, _commit_message(rnd, cur, after, proposer.name))
            cur, res_orig, res_dev = after, cand_orig, cand_dev
            accepted += 1
            rejects = 0
            outcome = f"accepted as {sha}"
        else:
            patching.revert(root)
            outcome = "would_accept" if passed else "rejected"
            if not passed:
                rejects += 1
                history.append(reason)
        rec.write("round", round=rnd, outcome=outcome, reason=reason or "", diff_sha=digest,
                  dev_after=after["dev"] if after else None,
                  orig_after=after["orig"] if after else None)
        if rejects >= cfg.max_rejects:
            stop = "too many rejected proposals in a row"
            break

    if held is not None and accepted:
        counts = summarize(held, score_set(cfg, held, evaluate_fn), cfg.threshold)[0]
        rec.write("heldout_final", **counts)

    summary = {"accepted": accepted, "stop": stop, "branch": branch,
               "dry_run": cfg.dry_run, "out": str(cfg.out), "final_dev": cur["dev"]}
    (cfg.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    rec.write("done", accepted=accepted, stop=stop, branch=branch, dry_run=cfg.dry_run)
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Self-improvement loop for the llmsentry scanner.")
    ap.add_argument("--project", type=Path, default=PROJECT,
                    help="directory containing llmsentry/ (default: this checkout)")
    ap.add_argument("--orig", type=Path, default=None,
                    help="regression corpus dir (default: <project>/corpus)")
    ap.add_argument("--dev", type=Path, default=None,
                    help="dev corpus dir (default: <project>/corpus/dev_2026-11-02)")
    ap.add_argument("--heldout", type=Path, default=None,
                    help="held-out dir (default: <project>/corpus/heldout_2026-11-02; skipped if absent)")
    ap.add_argument("--out", type=Path, default=None,
                    help="output dir (default: <project>/selfimprove/runs/<timestamp>)")
    ap.add_argument("--threshold", type=float, default=0.40)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--max-rejects", type=int, default=3)
    ap.add_argument("--max-misses", type=int, default=8)
    ap.add_argument("--max-fps", type=int, default=6)
    ap.add_argument("--provider", choices=sorted(DEFAULT_MODELS), default="gemini",
                    help="which API proposes changes (default: gemini)")
    ap.add_argument("--model", default=None,
                    help="model name (default: gemini-3.8-flash or claude-sonnet-5-5, by provider)")
    ap.add_argument("--dry-run", action="store_true", help="propose and score, but never commit")
    ap.add_argument("--stub-replies", type=Path, default=None,
                    help="JSON list of canned replies (tests and dry runs only)")
    a = ap.parse_args(argv)

    project = a.project.resolve()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    cfg = Config(
        project=project,
        orig=(a.orig or project / "corpus").resolve(),
        dev=(a.dev or project / "corpus" / "dev_2026-11-02").resolve(),
        heldout=(a.heldout or project / "corpus" / "heldout_2026-11-02").resolve(),
        out=(a.out or project / "selfimprove" / "runs" / stamp).resolve(),
        threshold=a.threshold, rounds=a.rounds, max_rejects=a.max_rejects,
        max_misses=a.max_misses, max_fps=a.max_fps, dry_run=a.dry_run,
    )
    model = a.model or DEFAULT_MODELS[a.provider]
    if a.stub_replies:
        proposer = StubProposer(json.loads(a.stub_replies.read_text(encoding="utf-8")))
    elif a.rounds == 0:
        proposer = StubProposer([])  # baseline only: no model call, no API key needed
    elif a.provider == "gemini":
        proposer = GeminiProposer(model)
    else:
        proposer = AnthropicProposer(model)
    print(json.dumps(run(cfg, proposer), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
