#!/usr/bin/env bash
# Task-scoped Docker resource cleanup for ephemeral GitHub-hosted QA scripts.
# Source into both installed-host QA harnesses. Never prune the Docker host;
# only inspect and remove task-owned exact random names.
sc_qa_cleanup_owned_docker() {
  local container_name=$1 image_ref=$2 scratch_dir=$3
  local found remaining failed=0
  # docker run can CREATE a named container and then fail to START it. A flag
  # set only after the command returned zero is not proof of absence.
  if found=$(docker container ls --all --quiet --no-trunc \
      --filter "name=^/$container_name$"); then
    if [[ -n $found ]]; then
      if ! docker rm -f "$container_name" >/dev/null; then
        echo "QA cleanup failed: Docker container $container_name" >&2
        failed=1
      elif ! remaining=$(docker container ls --all --quiet --no-trunc \
          --filter "name=^/$container_name$"); then
        echo "QA cleanup could not verify removed container $container_name" >&2
        failed=1
      elif [[ -n $remaining ]]; then
        echo "QA cleanup left Docker container $container_name" >&2
        failed=1
      fi
    fi
  else
    echo "QA cleanup could not inspect Docker container $container_name" >&2
    failed=1
  fi
  # An image tag can exist after a failed build; check regardless of build RC.
  if found=$(docker image ls --quiet --no-trunc "$image_ref"); then
    if [[ -n $found ]]; then
      if ! docker image rm "$image_ref" >/dev/null; then
        echo "QA cleanup failed: Docker image $image_ref" >&2
        failed=1
      elif ! remaining=$(docker image ls --quiet --no-trunc "$image_ref"); then
        echo "QA cleanup could not verify removed image $image_ref" >&2
        failed=1
      elif [[ -n $remaining ]]; then
        echo "QA cleanup left Docker image $image_ref" >&2
        failed=1
      fi
    fi
  else
    echo "QA cleanup could not inspect Docker image $image_ref" >&2
    failed=1
  fi
  if [[ -z $scratch_dir || ! -d $scratch_dir ]]; then
    echo 'QA cleanup scratch directory is missing or invalid' >&2
    failed=1
  elif ! rm -rf -- "$scratch_dir"; then
    echo "QA cleanup failed: task scratch $scratch_dir" >&2
    failed=1
  fi
  return "$failed"
}
