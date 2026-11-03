# Self-improvement harness for llmsentry

A loop in which a language model proposes one change to `llmsentry/llmsentry/scanner.py` per round. A change is kept only if it reduces misses or false positives on the dev set without making anything worse on the regression set.

## The three sets

Each set is a directory holding `malicious.json` and `benign.json`. Each item has `id`, `text`, `source` and `category`.

| Set | Path | Role |
|---|---|---|
| Regression | `corpus/` | Must not lose catches or gain false positives. Never shown to the proposer. |
| Dev | `corpus/dev_2026-11-02/` | Learning signal. The proposer sees up to 8 misses and 6 false positives per round. |
| Held-out | `corpus/heldout_2026-11-02/` | Final check. Scored at baseline, and again at the end only if something was accepted. Logged as counts only. Never shown to the proposer. |

The held-out set is only useful while it stays unseen. Each scoring pass spends some of that, so do not re-run it while you are tuning.

## What the code enforces

- One change per round, to `llmsentry/llmsentry/scanner.py` only. No other file, no new or deleted files, no renames.
- Added lines may not contain example text. Any 60-character slice of a regression or dev example is rejected.
- The repo's unit tests (`tests/`) must pass.
- A change is accepted only if dev misses or false positives go down, and neither set's misses, false positives or scanner errors go up.
- Commits go to the current branch. The run refuses `main` and `master`, and refuses to start with tracked changes.
- `--dry-run` proposes and scores, but never commits.

## Run it

```bash
export ANTHROPIC_API_KEY=...        # your key; it is never written to the repo
cd llmsentry                        # the project dir, the one containing llmsentry/
python3 -m selfimprove.loop --dry-run   # see what it proposes first
python3 -m selfimprove.loop             # real run; commits accepted rounds
```

Options: `--model` (default `claude-sonnet-5-5`), `--rounds` (8), `--max-rejects` (3), `--threshold` (0.40), `--dev`, `--heldout`, `--orig`, `--out`.

Each run writes to `selfimprove/runs/<timestamp>/`, which is git-ignored:
- `rounds.jsonl`: one row per round, plus the baseline and held-out counts.
- `prompts/round_NN.txt`: exactly what the proposer saw.
- `summary.json`.

## Tests

```bash
python3 -m unittest selfimprove.test_loop -v
```

These use a fake scanner in a throwaway git repo. They make no model calls.

## Caveats

- Each round is one model call. With the defaults, a run makes at most 8.
- The dev set was written by a fresh writer session, so it reflects that writer's style. Review it before you trust it.
- Gains on dev may not carry over to held-out. Check the held-out counts once, at the end. If they stay low, the scanner is overfitting to the dev examples.
