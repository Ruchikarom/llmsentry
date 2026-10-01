# Headroom SmartCrusher: prompt injection survives compression

## Framing

This is not a vulnerability report against Headroom. Compression tools are
not responsible for input safety, and this writeup doesn't claim otherwise.
It is a gap analysis: a demonstration that a common defensive assumption —
"content that passed through processing is probably clean" — doesn't hold,
and that something needs to sit before or after the compression layer to
catch what compression can't.

- **Headroom**: open-source LLM compression layer
  (SmartCrusher) that reduces the token cost of LLM inputs.
- **llmsentry**: rule-based prompt-injection scanner.

## The experiment

Embedded a prompt-injection phrase inside a statistically anomalous message
and ran it through Headroom's SmartCrusher compression, then checked whether
the payload survived.

## Result

The injection phrase survived compression **intact** — it would reach
downstream LLM calls unchanged. Compression re-encoded the message but
preserved the payload exactly where it matters.

## Why it matters

Compression acts as a trust-laundering step in many pipelines: teams assume
content that has been processed, summarized, or compressed has been
"handled." This experiment shows the opposite — a payload can ride through
the compression layer untouched and arrive at the model with its malicious
instruction fully intact. Any pipeline shaped like
`user input -> compression -> LLM`, without a scanning step, is exposed.

## Responsible framing

Reported directly to the maintainer with explicit scoping: this isn't
Headroom's bug to fix — a compression layer can't be expected to detect
vulnerabilities in its open-source form. The point is architectural:
detection belongs adjacent to compression, before or after it.

## Maintainer response

The maintainer confirmed the analysis:

> "This is really powerful - thank you for the analysis. Although you are
> right in pointing that Headroom per-se being a compression layer is unable
> to have (in its OSS form) a vuln detector and remover - we do offer an
> aspect of this in our Enterprise offerings. So - it is really great that
> you have tested this out - would love to explore collaboration
> opportunities further."

## Takeaway for llmsentry

Scan at the boundary, not just at the front door. llmsentry is designed to
sit before or after pipeline stages like compression — wherever untrusted
content changes shape but keeps its meaning. The reproduction script and
full results live in the llmsentry repo.
