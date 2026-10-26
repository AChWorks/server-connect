#!/usr/bin/env bash
# Hermetic task-owned Docker cleanup regressions. PATH intercepts ALL Docker
# calls; no real Docker daemon, privileged container or network is touched.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
source "$root/scripts/qa/docker-owned-cleanup.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/runner" "$scratch/state"
state=$scratch/state
cat > "$scratch/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail
state=$SC_QA_FAKE_DOCKER_STATE
printf '%s\n' "$*" >> "$state/calls"
case "$1 $2" in
  'build --pull')
    : > "$state/image"
    [[ $SC_QA_FAKE_BUILD_FAIL == 0 ]] || exit 61
    ;;
  'run -d')
    : > "$state/container"
    # Docker run created its named container, then START failed.
    exit 62
    ;;
  'container ls')
    [[ $SC_QA_FAKE_LIST_FAIL == 0 ]] || exit 63
    [[ "$*" == *'--filter name=^/sc-online-minimal-'* ]] || exit 68
    if [[ -f $state/container ]]; then echo exact-container-id; fi
    ;;
  'image ls')
    [[ $SC_QA_FAKE_IMAGE_LIST_FAIL == 0 ]] || exit 64
    [[ "$*" == *'sc-online-minimal:'* ]] || exit 69
    if [[ -f $state/image ]]; then echo exact-image-id; fi
    ;;
  'rm -f')
    [[ $3 == sc-online-minimal-* ]] || exit 65
    [[ $SC_QA_FAKE_RM_FAIL == 0 ]] || exit 70
    rm -f "$state/container"
    ;;
  'image rm')
    [[ $3 == sc-online-minimal:* ]] || exit 66
    [[ ! -f $state/container ]] || exit 71
    rm -f "$state/image"
    ;;
  'logs --tail') ;;
  *)
    echo "Unexpected fake Docker command: $*" >&2
    exit 67
    ;;
esac
DOCKER
chmod 0700 "$scratch/bin/docker"
export SC_QA_FAKE_DOCKER_STATE="$state"
export SC_QA_FAKE_BUILD_FAIL=0 SC_QA_FAKE_LIST_FAIL=0
export SC_QA_FAKE_IMAGE_LIST_FAIL=0 SC_QA_FAKE_RM_FAIL=0
export PATH="$scratch/bin:/usr/bin:/bin"
printf 'QA-ONLY' > "$scratch/bundle.tar.gz"
printf '# bootstrap QA fixture\n' > "$scratch/bootstrap.sh"
# The actual connected-host script has an early CI gate. The invocation is
# hermetic: the fake Docker intercepts build/run and fails before any guest
# is started; CI flags below are not production authorization.
run_connected() {
  GITHUB_ACTIONS=true CI=true RUNNER_TEMP="$scratch/runner" \
    /bin/bash "$root/scripts/qa/test-online-minimal-host.sh" \
    "$scratch/bundle.tar.gz" "$scratch/bootstrap.sh" \
    > "$scratch/out" 2> "$scratch/err"
}
assert_cleaned() {
  local label=$1
  [[ ! -e $state/container && ! -e $state/image ]] ||
    { echo "QA cleanup left task-owned fake resources: $label" >&2; exit 1; }
  [[ -z $(find "$scratch/runner" -mindepth 1 -maxdepth 1 -print -quit) ]] ||
    { echo "QA cleanup left task scratch: $label" >&2; exit 1; }
  [[ -f $state/unrelated-container && -f $state/unrelated-image ]] ||
    { echo "QA cleanup touched unrelated resources: $label" >&2; exit 1; }
}
: > "$state/unrelated-container"
: > "$state/unrelated-image"

# Case 1: run creates its task-named privileged guest, then START fails.
# The process must keep its original failed status and delete exact resources.
set +e
run_connected
rc=$?
set -e
[[ $rc -eq 62 ]] || { echo "Startup failure RC changed: $rc" >&2; exit 1; }
grep -F 'run -d --name sc-online-minimal-' "$state/calls" >/dev/null
grep -F 'container ls --all --quiet --no-trunc' "$state/calls" >/dev/null
grep -F 'rm -f sc-online-minimal-' "$state/calls" >/dev/null
grep -F 'image rm sc-online-minimal:' "$state/calls" >/dev/null
assert_cleaned created-start-failed
echo 'DOCKER_CREATED_START_FAILED_CLEANUP=PASS'

# Case 2: build tags an image but fails before docker run. The image and
# scratch must still be removed, even though no success flag could be set.
: > "$state/calls"
set +e
SC_QA_FAKE_BUILD_FAIL=1 run_connected
rc=$?
set -e
[[ $rc -eq 61 ]] || { echo "Build failure RC changed: $rc" >&2; exit 1; }
if grep -F 'run -d' "$state/calls"; then
  echo 'Docker run invoked after failed build' >&2
  exit 1
fi
assert_cleaned partial-build
echo 'DOCKER_PARTIAL_BUILD_CLEANUP=PASS'

# Case 3: Docker cannot inspect the container. This must not be interpreted
# as "absent" or reported as successful cleanup.
mkdir -p "$scratch/probe"
: > "$state/container"
: > "$state/image"
if SC_QA_FAKE_LIST_FAIL=1 sc_qa_cleanup_owned_docker \
    sc-online-minimal-probe sc-online-minimal:probe "$scratch/probe" \
    > "$scratch/out" 2> "$scratch/err"; then
  echo 'Docker listing failure normalized to cleanup success' >&2
  exit 1
fi
grep -F 'could not inspect Docker container' "$scratch/err" >/dev/null
[[ -f $state/container ]] || { echo 'Probe unexpectedly removed container' >&2; exit 1; }
[[ ! -d $scratch/probe ]] || { echo 'Scratch was not removed after inspect failure' >&2; exit 1; }
rm -f "$state/container" "$state/image"
echo 'DOCKER_INSPECTION_ERROR_FAIL_CLOSED=PASS'

# Case 4: Docker can list, but removal fails. Preserve caller's error state,
# report exact failed resources and attempt remaining safe cleanup.
mkdir -p "$scratch/failed-removal"
: > "$state/container"
: > "$state/image"
if SC_QA_FAKE_RM_FAIL=1 sc_qa_cleanup_owned_docker \
    sc-online-minimal-probe sc-online-minimal:probe "$scratch/failed-removal" \
    > "$scratch/out" 2> "$scratch/err"; then
  echo 'Docker removal failure normalized to cleanup success' >&2
  exit 1
fi
grep -F 'cleanup failed: Docker container' "$scratch/err" >/dev/null
grep -F 'cleanup failed: Docker image' "$scratch/err" >/dev/null
[[ ! -d $scratch/failed-removal ]] || { echo 'Scratch retained after removal error' >&2; exit 1; }
rm -f "$state/container" "$state/image"
echo 'DOCKER_REMOVAL_FAILURE_REPORTED=PASS'

# Both actual guest scripts must use the same tested exact-name cleanup.
for harness in test-online-minimal-host.sh test-installed-host.sh; do
  grep -F 'sc_qa_cleanup_owned_docker "$container" "$image" "$scratch"' \
    "$root/scripts/qa/$harness" >/dev/null ||
    { echo "Shared cleanup absent from $harness" >&2; exit 1; }
done
echo 'DOCKER_SHARED_QA_RESOURCE_CLEANUP=PASS'
