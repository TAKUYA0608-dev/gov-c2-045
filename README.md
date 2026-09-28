# GOV-C2-045 — Municipal Public-Records Disclosure Redaction Review Packet Agent

> **Category**: Cat 2 (domain workflow (a job to be done))
> **Industry**: Government

## Overview

Preparation of a redaction packet for a municipal public-records disclosure request. Given a JSON request (the request and the records to be disclosed, each with content and an authorisation flag), the agent discards any record the caller is not authorised to submit, routes each authorised record to the applicable non-disclosure exemption rulesets, flags sensitive fields (personal data, corporate information, deliberation and public-safety material) as redaction candidates with category, rationale and confidence, and composes a traceable packet of candidates with exemption citations. The flagging is deterministic — an exemption taxonomy plus personal-data patterns, no LLM —. The agent never alters or publishes a record: every candidate is marked for human confirmation and the packet carries a draft disclaimer; a request with no records or with unauthorised, oversized or injection-like content gets an explicit out-of-scope notice and a named error code. The exemption taxonomy shipped here is a small seed — replace it with your municipality's ordinance and guidance.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | 3.11 or later (`requires-python = ">=3.11"`) |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent raises
`PlatformRequired` during graph compile / start-up preflight rather than starting in a partially
working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Known limitations

**Some personal data is masked by the platform before the records are scanned.** AGENTIC STAR's
personal-data protection runs before this template's code and replaces My Number digits, e-mail addresses,
phone numbers, labelled names (`氏名 山田太郎` — the label included) and runs of two or more Title-Case words
with `[MASKED]`; the template cannot switch it off. Addresses are not masked. Each masked span is listed as a
personal-information candidate with confidence 0.65 — below the 0.7 line, so it goes to the reviewer's
low-confidence exceptions — because its type can no longer be seen. Measured on AgentCore 1.0.3:

| Record | Personal-information candidates without masking | On the platform |
|---|---|---|
| resident application (name, address, My Number, e-mail) | 7 (My Number 0.95, e-mail 0.9, address 0.8, 4 labels) | 7 — 3 of them masked spans at 0.65, `PERSONAL_DATA_MASKED` |
| labelled name + address | 3 (address 0.8, 2 labels) | 3 — the name is a masked span at 0.65, `PERSONAL_DATA_MASKED` |
| complaint record (Latin name, phone, labelled staff name) | 2 | 4 — 3 masked spans, `PERSONAL_DATA_MASKED` |
| contract memo (no personal data) | 0 | 0, `limitations: []` |

`limitations` holds the code only; `message` says how many spans were masked. Always check a masked candidate
against the original record before deciding on the redaction. Evidence snippets are redacted over whole
values, so a value that crosses the snippet edge is not shown in part.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/02_design.md` for the design and `docs/03_test_spec.md` for the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
