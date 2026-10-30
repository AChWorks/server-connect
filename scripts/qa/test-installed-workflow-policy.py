#!/usr/bin/env python3
"""Fail-closed, dependency-free regression checks for privileged CI admission.

These checks inspect the actual checked-out workflow source. They complement,
but do not replace, GitHub's trusted-default-branch event handling.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/installed-host-qa.yml"
source = WORKFLOW.read_text(encoding="utf-8")


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise SystemExit(f"INSTALLED_HOST_WORKFLOW_POLICY=FAIL: {explanation}")


# Match the exact effective event stanza. In particular, a fork-modifiable
# pull_request trigger must not be able to select this privileged job.
require(source.count("\non:\n") == 1, "missing/ambiguous event section")
events = source.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
require("  pull_request:\n" not in events, "PR-modifiable workflow trigger")
require("  pull_request_target:\n    paths:\n" in events, "trusted-base trigger missing")
require("  workflow_dispatch:\n" in events, "trusted manual candidate path missing")
paths_section = events.split("  pull_request_target:\n    paths:\n", 1)[1].split(
    "  workflow_dispatch:\n", 1
)[0]
path_lines = [line for line in paths_section.splitlines() if line.strip()]
require(all(re.fullmatch(r"      - '[^']+'", line) for line in path_lines),
        "unrecognized path-filter syntax")
patterns = [line[9:-1] for line in path_lines]
require("bundle/server-connect.service" in patterns, "service-unit-only change ignored")
require("bundle/server-connect-activation-recover.service" in patterns, "independent guard service-only change ignored")
require("bundle/server-connect-activation-recover.timer" in patterns, "independent guard timer-only change ignored")
require("bundle/server-connect-smart-tun.service" in patterns, "separate TUN unit-only change ignored")
require(".github/workflows/installed-host-qa.yml" in patterns, "policy changes ignored")

for candidate, expected in (
    ("bundle/server-connect.service", True),
    ("bundle/server-connect-activation-recover.service", True),
    ("bundle/server-connect-activation-recover.timer", True),
    ("bundle/server-connect-smart-tun.service", True),
    ("scripts/qa/host-proxy-only.sh", True),
    (".github/workflows/installed-host-qa.yml", True),
    ("docs/general-overview.md", False),
    ("README.md", False),
):
    selected = any(fnmatchcase(candidate, path) for path in patterns)
    require(selected is expected, f"incorrect selection for {candidate}")


# Require exact fail-closed base-owned admission expression; a changed
# expression must be reviewed together with an updated security test.
admission_part = source.split("    if: >-\n", 1)
require(len(admission_part) == 2, "missing/duplicate trusted job admission")
admission = " ".join(admission_part[1].split("    runs-on:", 1)[0].split())
expected_admission = (
    "github.event_name == 'workflow_dispatch' || "
    "(github.event_name == 'pull_request_target' && "
    "github.event.pull_request.head.repo.id == github.event.repository.id && "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)
require(admission == expected_admission, "unreviewed job admission semantics")

# Exercise the policy's two intended branches (with exact expression above):
# workflow_dispatch is allowed only after GitHub authenticates an Actions
# write-capable dispatcher for an internal repository ref.
def admitted(event: str, head_id: int, base_id: int,
             head_repo: str, base_repo: str) -> bool:
    return event == "workflow_dispatch" or (
        event == "pull_request_target"
        and head_id == base_id and head_repo == base_repo
    )


own = "AChWorks/server-connect"
cases = (
    ("pull_request_target", 100, 100, own, own, True),
    ("pull_request_target", 200, 100, "attacker/server-connect", own, False),
    ("pull_request_target", 200, 100, own, own, False),
    ("pull_request_target", 100, 100, "attacker/server-connect", own, False),
    ("pull_request", 100, 100, own, own, False),
    ("workflow_dispatch", 100, 100, own, own, True),
    ("schedule", 100, 100, own, own, False),
)
for event, head_id, base_id, head_repo, base_repo, expected in cases:
    require(admitted(event, head_id, base_id, head_repo, base_repo) is expected,
            f"admission expectation failed: {event!r}, {head_repo!r}")


# In a pull_request_target event the default checkout points to main, not
# the candidate. The explicit checked-out merge must include BOTH event
# parent SHAs, and the source of the PR itself must be same-repository.
require("          persist-credentials: false\n" in source, "checkout retains token")
require("          fetch-depth: 2\n" in source, "merge parents unavailable")
require(
    "ref: ${{ github.event_name == 'pull_request_target' && "
    "format('refs/pull/{0}/merge', github.event.pull_request.number) || github.sha }}"
    in source,
    "PR merge-tree exact-candidate checkout missing",
)
require('[[ $(git rev-parse HEAD^1) == "$EXPECTED_BASE_SHA" ]]' in source,
        "merge base not verified")
require('[[ $(git rev-parse HEAD^2) == "$EXPECTED_HEAD_SHA" ]]' in source,
        "merge head not verified")
require('[[ $(git rev-parse HEAD) == "$CHECKOUT_EVENT_SHA" ]]' in source,
        "manual dispatch identity not verified")
require("permissions:\n  contents: read\n" in source, "token not explicitly read-only")
require("runs-on: ubuntu-24.04\n" in source, "ephemeral hosted runner required")
require("secrets." not in source and "environment:" not in source,
        "privileged workflow unexpectedly references secrets/environment")

print("INSTALLED_HOST_WORKFLOW_POLICY=PASS")
print("TRUSTED_BASE_ADMISSION_CASES=PASS")
print("SERVICE_UNIT_ONLY_TRIGGER_SELECTION=PASS")
print("UNRELATED_DOCS_ONLY_TRIGGER_EXCLUDED=PASS")
print("EXACT_CANDIDATE_IDENTITY_POLICY=PASS")
