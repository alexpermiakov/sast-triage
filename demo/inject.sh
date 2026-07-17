#!/usr/bin/env bash
# Materialize today's vulnerability into its own package under the demo app, so
# findings accumulate as committed code (one package per class) instead of
# overwriting a single file. That keeps the committed cache coherent: every
# verdict maps to code that is actually present and reviewable in the diff.
#
# Selection is deterministic per day. Over five consecutive days the whole set
# lands; after that each run is a no-op (the package already exists) and the
# cache carries the run — nothing new to triage.
set -euo pipefail
shopt -s nullglob

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
vulns=("$dir"/vulnerable-app/vulns/*.go.txt)
count=${#vulns[@]}
if (( count == 0 )); then
	echo "no vuln templates found under $dir/vulnerable-app/vulns" >&2
	exit 1
fi

# Day-of-year (1-366; base-10 so a leading zero isn't read as octal) picks one.
doy=$(date -u +%j)
idx=$(( (10#$doy - 1) % count ))
selected="${vulns[$idx]}"

base=$(basename "$selected" .go.txt) # e.g. 01-sql-injection
pkg=${base#*-}                       # strip the NN- ordering prefix
pkg=${pkg//-/_}                      # sql_injection — a valid package dir
dest="$dir/vulnerable-app/$pkg"

mkdir -p "$dest"
cp "$selected" "$dest/main.go"
echo "materialized $base -> demo/vulnerable-app/$pkg/main.go"
