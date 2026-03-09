#!/usr/bin/env bash
# Convert a .env file to YAML format
# Usage: ./env2yaml.sh [.env file] > output.yaml

input="${1:-.env}"

if [[ ! -f "$input" ]]; then
  echo "Error: $input not found" >&2
  exit 1
fi

while IFS= read -r line || [[ -n "$line" ]]; do
  # Skip blank lines
  [[ -z "$line" ]] && continue
  # Convert comments
  if [[ "$line" =~ ^#(.*)$ ]]; then
    echo "#${BASH_REMATCH[1]}"
    continue
  fi
  # Parse KEY=VALUE
  key="${line%%=*}"
  value="${line#*=}"
  # Strip surrounding quotes
  value="${value#\"}" ; value="${value%\"}"
  value="${value#\'}" ; value="${value%\'}"
  # Quote the value for YAML safety
  echo "${key}: \"${value}\""
done < "$input"
