#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Runs sip-golden and compares its normalised output with the recorded one.
set -eu
bin=$1 ref=$2 norm=$3
out=$(mktemp)
trap 'rm -f "$out"' EXIT
"$bin" 2>/dev/null | "$norm" > "$out"
diff -u "$ref" "$out"
echo "sip-golden: identical to $(basename "$ref")"
