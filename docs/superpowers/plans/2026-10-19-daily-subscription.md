# Daily Subscription Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement these tasks inline. Steps use checkboxes for tracking.

**Goal:** Deliver a deployable GitHub Actions project that tests daily proxy subscriptions and publishes stable files.

**Architecture:** Parse and normalize subscription entries without disclosing credentials to conversion services. Test each unique node with an isolated Xray instance and curl HTTPS probes, then commit only successful outputs.

**Tech Stack:** Python 3.12, standard library, PyYAML 6.0.3, official Xray v26.3.27, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-19-daily-subscription-design.md`

## Global Constraints

- Use Asia/Shanghai for source dates; default schedule 09:20.
- Keep working subscriptions if fetch or all probes fail.
- No direct fallback or third-party subscription conversion.
- Every parsed connection and unsupported row receives a report result; equivalent renamed entries may be deduplicated.
- No secrets in reports or uploaded artifacts.

## Review Focus

- Differently escaped or named URIs must retain connection semantics while deduplicating.
- Unsupported transport parameters must never be silently discarded.
- HTTPS success without using the candidate must never pass a node.
- Zero successful nodes must leave prior subscriptions byte-identical.
- Xray pass does not establish Mihomo conversion correctness; record incompatible exports.

### Task 1: Subscription parser and exporters

**Files:** `nodes.py`, `tests/test_nodes.py`.

**Interfaces:** `decode_subscription(text) -> list[str]`; `parse_node(uri) -> Node`; `Node.xray_outbound() -> dict`; `Node.clash_proxy() -> dict`; `unique_nodes(uris) -> tuple[list[Node], list[dict]]`.

- [x] Write failing tests for Base64/plain input, encoded SS credentials, IPv6 VLESS TLS, XHTTP, REALITY, VMess/Trojan, duplicates and unsupported parameters.
- [x] Run `python -m unittest discover -s tests -p test_nodes.py -v` and observe missing implementation.
- [x] Implement parser and loss-aware export, then run the same suite until green.

### Task 2: Real proxy testing and guarded publication

**Files:** `check_nodes.py`, `download_xray.py`, `tests/test_checker.py`.

**Interfaces:** consumes Task 1's Node; produces `check_node(node, xray, settings) -> dict`, `source_url(now) -> str`, `publish(output, nodes, results, report) -> bool`.

- [x] Write failing tests for Shanghai date rollover, forced SOCKS curl command, private-address rejection, all-failed retention and successful Base64/YAML output.
- [x] Run `python -m unittest discover -s tests -p test_checker.py -v` and observe failures.
- [x] Implement engine lifecycle, timeouts, bounded concurrency, secret-free reports and staging outputs.
- [x] Download the pinned official Xray archive and verify SHA256 before execution.
- [x] Run the full unittest suite and real local VLESS/HTTPS integration, including failed credentials.

### Task 3: Scheduled workflow, deployment guide and delivery

**Files:** `.github/workflows/update.yml`, `settings.json`, `README.md`, `requirements.txt`, `.gitignore`.

- [x] Write the schedule, manual trigger, test, download, probe, artifact and guarded commit steps.
- [x] Parse YAML, run the full suite, run today's source where the environment permits, and inspect reports.
- [x] Review code for lost transport fields, secrets, direct fallback and partial publication.
- [x] Package the complete project, including the hidden `.github` workflow, and save the deliverable.
- [x] Deploy only to a user-owned repository with verified write access; otherwise state the remaining repo requirement and avoid claiming a live URL.
