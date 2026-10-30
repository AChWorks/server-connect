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
require("bundle/server-connect-smart-health.service" in patterns, "health execution service-only change ignored")
require("bundle/server-connect-smart-health.timer" in patterns, "health scheduler timer-only change ignored")
require(".github/workflows/installed-host-qa.yml" in patterns, "policy changes ignored")

for candidate, expected in (
    ("bundle/server-connect.service", True),
    ("bundle/server-connect-activation-recover.service", True),
    ("bundle/server-connect-activation-recover.timer", True),
    ("bundle/server-connect-smart-tun.service", True),
    ("bundle/server-connect-smart-health.service", True),
    ("bundle/server-connect-smart-health.timer", True),
    ("scripts/qa/host-proxy-only.sh", True),
    (".github/workflows/installed-host-qa.yml", True),
    ("docs/general-overview.md", False),
    ("README.md", False),
):
    selected = any(fnmatchcase(candidate, path) for path in patterns)
    require(selected is expected, f"incorrect selection for {candidate}")


# Require exact fail-closed base-owned admission expression; a changed
# expression must be reviewed together with an updated security test.
jobs = source.split("\njobs:\n", 1)
require(len(jobs) == 2, "missing/ambiguous job section")
job_names = re.findall(r"^  ([a-zA-Z0-9_-]+):$", jobs[1], re.MULTILINE)
require(job_names == ["debian-systemd-lifecycle"],
        "an additional privileged job needs its own reviewed admission")
require(source.count("    if: >-\n") == 1,
        "missing/duplicate trusted job admission")
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
require("        debian: ['13', '12']\n" in source,
        "supported installed targets changed without reviewed coverage")
require("      fail-fast: false\n" in source,
        "one target failure must not cancel the other target's evidence")
require("      SC_QA_DEBIAN_VERSION: ${{ matrix.debian }}\n" in source,
        "matrix target is not bound to the shared installed harness")
require('"debian-${SC_QA_DEBIAN_VERSION}-amd64"' in source,
        "target-specific bundle construction missing")

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

# Metadata-only evidence may follow a successful, explicitly dispatched
# Debian12 lifecycle. The sole upload is the identity/checksum JSON; no
# installable archive, binary, log, profile or directory is permitted.
handoff_gate = (
    "        if: ${{ success() && github.event_name == 'workflow_dispatch' "
    "&& matrix.debian == '12' }}\n"
)
steps = re.split(r"(?m)^      - name: ", source)[1:]
upload_steps = [step for step in steps if "uses: actions/upload-artifact@" in step]
require(len(upload_steps) == 1, "missing/additional artifact upload step")
upload = upload_steps[0]
require(upload == steps[-1], "artifact upload must follow all lifecycle checks")
require(handoff_gate in upload, "artifact upload admits unsuccessful/non-dispatch/non-Debian12 runs")
require("        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2\n" in upload,
        "artifact action is not the reviewed immutable version")
require("          name: server-connect-debian12-qa-evidence-${{ github.sha }}-attempt-${{ github.run_attempt }}\n" in upload,
        "artifact identity is not explicit QA evidence candidate/run-attempt scope")
for setting in ("retention-days: 1", "compression-level: 0", "if-no-files-found: error", "overwrite: false"):
    require(f"          {setting}\n" in upload, f"artifact setting changed: {setting}")
inputs = re.findall(r"^          ([a-z-]+):", upload, re.MULTILINE)
require(len(inputs) == 6 and set(inputs) == {
    "name", "retention-days", "compression-level", "if-no-files-found", "overwrite", "path",
}, "unreviewed/duplicate artifact input")
path_parts = upload.split("          path: |\n")
require(len(path_parts) == 2, "missing/ambiguous artifact path allowlist")
require(path_parts[1].splitlines() == [
    "            build/installed-qa/debian12-qa-handoff.json",
], "artifact upload must contain only the JSON evidence, never installable bytes")
identity_steps = [step for step in steps if step.startswith("Record successful Debian 12 QA build evidence\n")]
require(len(identity_steps) == 1 and identity_steps[0] == steps[-2],
        "exact-build identity must be recorded immediately before upload")
require(handoff_gate in identity_steps[0], "identity step bypasses the artifact gate")
require('[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]]' in identity_steps[0],
        "handoff candidate identity is not rechecked")
archive_parts = identity_steps[0].split("          archive_paths = (\n")
require(len(archive_parts) == 2, "missing/ambiguous archive evidence inputs")
archive_inputs = archive_parts[1].split("          )\n", 1)
require(len(archive_inputs) == 2 and archive_inputs[0].splitlines() == [
    "              'dist/server-connect-0.1.0-dev-debian12-amd64-local-qa.tar.gz',",
    "              'build/installed-qa/server-connect-hostqa-update-valid.tar.gz',",
    "              'build/installed-qa/server-connect-hostqa-update-invalid-unit.tar.gz',",
], "metadata must identify exactly the three tested QA archives")

print("INSTALLED_HOST_WORKFLOW_POLICY=PASS")
print("TRUSTED_BASE_ADMISSION_CASES=PASS")
print("SERVICE_UNIT_ONLY_TRIGGER_SELECTION=PASS")
print("UNRELATED_DOCS_ONLY_TRIGGER_EXCLUDED=PASS")
print("EXACT_CANDIDATE_IDENTITY_POLICY=PASS")
print("EXPLICIT_DEBIAN12_DEBIAN13_INSTALLED_MATRIX=PASS")
print("DEBIAN12_QA_METADATA_ONLY_ARTIFACT_POLICY=PASS")
