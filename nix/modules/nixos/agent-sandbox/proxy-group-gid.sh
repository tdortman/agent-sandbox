#!/usr/bin/env bash
set -euo pipefail

group_name="${1:?group name is required}"
group_lines="$(getent group "$group_name" || true)"
[[ -n "$group_lines" ]] || {
  echo "agent-sandbox policy: proxy group is missing" >&2
  exit 1
}
[[ "$(printf '%s\n' "$group_lines" | wc -l)" == 1 ]] || {
  echo "agent-sandbox policy: proxy group lookup is ambiguous" >&2
  exit 1
}

IFS=: read -r _group_name _group_password group_id _group_members <<< "$group_lines"
[[ "$group_id" =~ ^[1-9][0-9]*$ ]] || {
  echo "agent-sandbox policy: proxy group ID is invalid" >&2
  exit 1
}
printf '%s\n' "$group_id"
