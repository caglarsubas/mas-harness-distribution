#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "offline verification accepts no shell command arguments" >&2
  exit 2
fi
if [[ -z "${HARNESS_TASK_PACKET:-}" || ! -f "${HARNESS_TASK_PACKET}" ]]; then
  echo "HARNESS_TASK_PACKET must name a readable packet YAML file" >&2
  exit 2
fi

ci_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "${ci_dir}/.." && pwd -P)"
runner="${ci_dir}/run_packet_argv.py"
session_id="offline-$PPID-$$"
packet_dir="$(CDPATH='' cd -- "$(dirname -- "$HARNESS_TASK_PACKET")" && pwd -P)"
packet_path="${packet_dir}/$(basename -- "$HARNESS_TASK_PACKET")"

if [[ "${HARNESS_OFFLINE_ENFORCED:-0}" == "1" ]]; then
  if [[ -z "${HARNESS_OFFLINE_BACKEND:-}" || -z "${HARNESS_OFFLINE_SESSION_ID:-}" ]]; then
    echo "trusted outer isolation must name its backend and session" >&2
    exit 2
  fi
  for offline_setting in UV_OFFLINE UV_FROZEN UV_NO_SYNC; do
    if [[ "${!offline_setting:-}" != "1" ]]; then
      echo "trusted outer isolation requires ${offline_setting}=1" >&2
      exit 2
    fi
  done
  cd "$repo_root"
  exec python3 -I "$runner"
fi

# shellcheck disable=SC2034 # Consumed by the sourced isolation contract.
harness_isolation_repository_root="$repo_root"
# shellcheck source=warm-source-isolation.sh
# shellcheck disable=SC1091 # The canonical repository path is resolved at runtime.
source "${ci_dir}/warm-source-isolation.sh"
harness_load_warm_source_roots

case "$(uname -s)" in
  Darwin)
    if [[ ! -x /usr/bin/sandbox-exec ]]; then
      echo "offline verification refused: sandbox-exec is unavailable" >&2
      exit 2
    fi
    sandbox_profile='(version 1) (allow default) (deny network*) (deny file-write* (literal (param "PACKET_PATH")))'
    sandbox_parameters=("-D" "PACKET_PATH=${packet_path}")
    warm_root_index=0
    # shellcheck disable=SC2154 # Populated by harness_load_warm_source_roots.
    for warm_root in "${warm_source_roots[@]}"; do
      [[ "$warm_root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] && continue
      parameter_name="WARM_ROOT_${warm_root_index}"
      sandbox_parameters+=("-D" "${parameter_name}=${warm_root}")
      sandbox_profile+=" (deny file-read* (subpath (param \"${parameter_name}\")))"
      sandbox_profile+=" (deny file-write* (subpath (param \"${parameter_name}\")))"
      warm_root_index=$((warm_root_index + 1))
    done
    harness_scrub_warm_source_environment
    exec /usr/bin/sandbox-exec \
      "${sandbox_parameters[@]}" \
      -p "$sandbox_profile" \
      env \
        HARNESS_TASK_PACKET="$packet_path" \
        HARNESS_OFFLINE_ENFORCED=1 \
        HARNESS_OFFLINE_BACKEND=darwin-sandbox \
        HARNESS_OFFLINE_SESSION_ID="$session_id" \
        UV_OFFLINE=1 \
        UV_FROZEN=1 \
        UV_NO_SYNC=1 \
        python3 -I "$runner"
    ;;
  Linux)
    if command -v firejail >/dev/null 2>&1; then
      firejail_arguments=(--quiet --net=none "--read-only=${packet_path}")
      # shellcheck disable=SC2154 # Populated by harness_load_warm_source_roots.
      for warm_root in "${warm_source_roots[@]}"; do
        [[ "$warm_root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] && continue
        firejail_arguments+=("--blacklist=${warm_root}" "--read-only=${warm_root}")
      done
      harness_scrub_warm_source_environment
      exec firejail "${firejail_arguments[@]}" \
        env \
          HARNESS_TASK_PACKET="$packet_path" \
          HARNESS_OFFLINE_ENFORCED=1 \
          HARNESS_OFFLINE_BACKEND=linux-firejail \
          HARNESS_OFFLINE_SESSION_ID="$session_id" \
          UV_OFFLINE=1 \
          UV_FROZEN=1 \
          UV_NO_SYNC=1 \
          python3 -I "$runner"
    fi
    echo "offline verification refused: firejail is required for network, packet-write, and warm-source isolation" >&2
    exit 2
    ;;
  *)
    echo "offline verification refused: unsupported isolation platform $(uname -s)" >&2
    exit 2
    ;;
esac
