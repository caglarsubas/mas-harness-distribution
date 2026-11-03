#!/usr/bin/env bash
# Shared by the trusted offline launchers. This file must be sourced, not executed.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "warm-source isolation helper must be sourced by a trusted launcher" >&2
  exit 2
fi

HARNESS_WARM_SOURCE_SENTINEL="__HARNESS_NO_WARM_SOURCE_ROOT__"
warm_source_roots=("$HARNESS_WARM_SOURCE_SENTINEL")

harness_warm_source_refuse() {
  echo "offline verification refused: $1" >&2
  return 2
}

harness_append_warm_source_root() {
  local requested_root="$1"
  local canonical_root existing_root

  if [[ -z "$requested_root" || "$requested_root" != /* ]]; then
    harness_warm_source_refuse "HARNESS_WARM_SOURCE_ROOTS entries must be absolute paths"
    return 2
  fi
  if [[ ! -d "$requested_root" || -L "$requested_root" ]]; then
    harness_warm_source_refuse "warm-source root is absent, inaccessible, or a symlink: $requested_root"
    return 2
  fi
  canonical_root="$(CDPATH='' cd -- "$requested_root" 2>/dev/null && pwd -P)" || {
    harness_warm_source_refuse "warm-source root cannot be canonicalized: $requested_root"
    return 2
  }
  if [[ "$requested_root" != "$canonical_root" ]]; then
    harness_warm_source_refuse "warm-source root must already be canonical: $requested_root"
    return 2
  fi
  case "$canonical_root" in
    /|/private|/private/tmp|/tmp|/Users|/home)
      harness_warm_source_refuse "warm-source root is dangerously broad: $canonical_root"
      return 2
      ;;
  esac
  if [[ -n "${harness_isolation_repository_root:-}" ]]; then
    if [[ "$canonical_root" == "$harness_isolation_repository_root" \
      || "$canonical_root" == "$harness_isolation_repository_root"/* \
      || "$harness_isolation_repository_root" == "$canonical_root"/* ]]; then
      harness_warm_source_refuse "warm-source root overlaps the implementation repository: $canonical_root"
      return 2
    fi
  fi
  for existing_root in "${warm_source_roots[@]}"; do
    [[ "$existing_root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] && continue
    if [[ "$canonical_root" == "$existing_root" ]]; then
      harness_warm_source_refuse "duplicate warm-source root: $canonical_root"
      return 2
    fi
    if [[ "$canonical_root" == "$existing_root"/* \
      || "$existing_root" == "$canonical_root"/* ]]; then
      harness_warm_source_refuse "warm-source roots must not overlap: $canonical_root and $existing_root"
      return 2
    fi
  done
  warm_source_roots+=("$canonical_root")
}

harness_root_is_declared() {
  local candidate="$1"
  local declared_root
  for declared_root in "${warm_source_roots[@]}"; do
    [[ "$declared_root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] && continue
    if [[ "$candidate" == "$declared_root" || "$candidate" == "$declared_root"/* ]]; then
      return 0
    fi
  done
  return 1
}

harness_require_known_warm_sources_declared() {
  local base container candidate config
  local bases=(/private/tmp /tmp)
  if [[ -n "${TMPDIR:-}" && "${TMPDIR%/}" != "/private/tmp" && "${TMPDIR%/}" != "/tmp" ]]; then
    bases+=("${TMPDIR%/}")
  fi
  for base in "${bases[@]}"; do
    for container in "$base"/codex-harness-warmstarts.*; do
      [[ -d "$container" ]] || continue
      for candidate in "$container"/*; do
        config="$candidate/.git/config"
        [[ -f "$config" ]] || continue
        if grep -Fqs 'no-fetch://immutable-warm-source' "$config" \
          && grep -Fqs 'no-push://immutable-warm-source' "$config" \
          && ! harness_root_is_declared "$(CDPATH='' cd -- "$candidate" && pwd -P)"; then
          harness_warm_source_refuse \
            "locked warm snapshot exists but is absent from HARNESS_WARM_SOURCE_ROOTS: $candidate"
          return 2
        fi
      done
    done
  done
}

harness_load_warm_source_roots() {
  if [[ "${HARNESS_WARM_SOURCE_ROOTS+x}" != "x" ]]; then
    harness_warm_source_refuse \
      "HARNESS_WARM_SOURCE_ROOTS must be set by the trusted launcher to canonical roots or NONE"
    return 2
  fi
  local roots_value="${HARNESS_WARM_SOURCE_ROOTS-}"
  local requested_root
  warm_source_roots=("$HARNESS_WARM_SOURCE_SENTINEL")

  if [[ -z "$roots_value" ]]; then
    harness_warm_source_refuse \
      "HARNESS_WARM_SOURCE_ROOTS must be NONE or a newline-delimited canonical root list"
    return 2
  fi
  if [[ "$roots_value" == "NONE" ]]; then
    roots_value=""
  fi
  if [[ -n "$roots_value" ]]; then
    while IFS= read -r requested_root || [[ -n "$requested_root" ]]; do
      harness_append_warm_source_root "$requested_root" || return 2
    done <<< "$roots_value"
  fi
  harness_require_known_warm_sources_declared || return 2
}

harness_scrub_warm_source_environment() {
  unset HARNESS_WARM_SOURCE_ROOTS
}
