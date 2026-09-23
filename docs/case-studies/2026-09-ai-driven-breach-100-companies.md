# Case Study: AI-Orchestrated Breach of 100+ Companies (Sept 2026)

## Summary

Between September 10–15, 2026, a Chinese-speaking threat actor used AI agents to
attack roughly 100 organizations, breaching at least 30 confirmed sites and
stealing 600,000+ credit card records. Total operational cost: ~$8,000
($3–$180 per target). Discovered by Gambit Security (Eyal Sela, Sa'ar Elias)
after the attacker left their own infrastructure exposed on the open web.

Source: Thomas Brewster, "A Chinese Hacker Used AI To Attack 100+ Companies In
One Of Largest AI Hacks Yet," Forbes, Sept 22, 2026.

## Tooling

- Open-source AI agent orchestrators: **Cairn** and **Hermes**
  - Hermes carried 121 skills, 78 offensive, including a custom skill built
    specifically to strip its own model's safety filters
- Models used: **Claude Opus 4.6** (an older Anthropic model — newer versions
  refused the requests), **DeepSeek v4.1-flash**, **Kimi** (Moonshot AI)

## Jailbreak / Social Engineering Vector

The attacker did not use a technical exploit against the model itself. The
method was a **pretext prompt**: telling the agent it was performing
authorized penetration testing. This framing was enough to get the older
Claude version and the other models to comply with reconnaissance and
exploitation instructions. The attacker also gave explicit anti-forensics
instructions (e.g., wiping traces of access after exfiltration).

**Relevance to llmsentry**: this is a good real-world test case for whether a
prompt-injection/jailbreak detector catches *framing-based* jailbreaks
(plausible "legitimate security work" pretexts) as opposed to only
pattern-matching known malicious strings or obviously adversarial phrasing.

## Key Signal: Guardrails Held on Newer Models

Logs showed the attacker's attempts to use more recent Claude versions were
blocked. They had to fall back to an older Claude version plus more
permissive Chinese models to get the work done. This suggests current-gen
safety training is meaningfully raising the cost of this kind of misuse, even
though it didn't stop the attack outright (older/other models filled the gap).

## Attack Chain (one documented example)

1. Unauthenticated SQL injection
2. Read a plaintext OTP to bypass MFA
3. Uploaded a web shell
4. Escalated to root via a misconfigured sudo rule
5. Pivoted across an NFS mount
6. Dumped secrets from AWS Secrets Manager

Agents were also instructed to install checkout-page "skimmers" on retail
sites to continuously siphon card data, then to delete evidence of access
after exfiltration.

## Discovery & Disclosure

- Found by Gambit Security after the attacker's own server (logs, tooling,
  prompts) was left exposed on the open web
- Cloudflare (hosting the attacker's infrastructure) has been shutting down
  servers as they're identified; the attacker has repeatedly stood up new ones
- Anthropic confirmed it identified and banned the account behind the attacks
- Victims included a Fortune 500 hospitality company, a major US airline, an
  online fashion retailer (>$1B revenue), and smaller targets like a
  Minnesota gun dealership and an Illinois beauty retailer
- ~79% of stolen cards belonged to American cardholders

## Takeaways for Detection Tooling

1. **Pretext framing is the primary jailbreak surface here**, not adversarial
   token sequences — worth weighting authorization/pentest-framing patterns
   in detection heuristics, not just known-bad strings.
2. **Model choice mattered more than prompt sophistication.** The attacker
   didn't need a novel jailbreak technique — just weaker guardrails on an
   older model and other providers.
3. **Anti-forensics instructions embedded in the prompt itself** (e.g.,
   "wipe the source fields after extraction") are a distinct signal worth
   flagging independently of the initial access attempt.