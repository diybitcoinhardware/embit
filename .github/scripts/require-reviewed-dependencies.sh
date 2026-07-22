#!/usr/bin/env bash
set -euo pipefail

changes=${DEPENDENCY_CHANGES:-[]}
reviewed=${REVIEWED_DEPENDENCY_PURLS:-}
reviewed_file=""

if [ -n "${REVIEWED_DEPENDENCY_PURLS_FILE:-}" ]; then
  reviewed_file=$(cat "$REVIEWED_DEPENDENCY_PURLS_FILE")
fi

pending=$(
  jq -r --arg reviewed "$reviewed" --arg reviewed_file "$reviewed_file" '
    (($reviewed + "\n" + $reviewed_file)
      | split("\n")
      | [.[] | split(",")[] | split("#")[0] | gsub("^\\s+|\\s+$"; "") | select(length > 0)]
    ) as $allowlist
    | [
        .[]
        | select(.change_type == "added")
        | select((.package_url | split("@")[0]) as $purl | ($allowlist | index($purl) | not))
        | "\(.manifest): \(.package_url)"
      ]
    | .[]
  ' <<< "$changes"
)

if [ -n "$pending" ]; then
  {
    echo "New dependencies require maintainer review."
    echo "Add reviewed package URLs without versions to REVIEWED_DEPENDENCY_PURLS or REVIEWED_DEPENDENCY_PURLS_FILE."
    echo "$pending"
  } >&2
  exit 1
fi
