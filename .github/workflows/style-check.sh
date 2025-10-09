#!/bin/bash
#;**********************************************************************;
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2025, Siemens AG
#
#;**********************************************************************;

#########################################################################
# Configuration
#########################################################################
# Include directories
include_directories="platform src test util"
exclude_directories=""
include_files="meson.build meson_options.txt"
#########################################################################

# Find all *.c and *.h files in specified directories
files=$(find $include_directories -type f \( -iname "*.c" -or -iname "*.h" -or -iname "meson.build" \) ! -path "${exclude_directories}/*")

# Add include_files
files="$files $include_files"

# Initialize counters
total_files=0
files_with_tabs=0
files_with_trailing_ws=0
problem_found=false

echo "=== Checking files for tabs and trailing whitespace ==="
echo

for file in $files; do
  ((total_files++))
  echo "Checking file: $file"

  tab_lines=$(grep -nP '\t' "$file")
  trailing_ws_lines=$(grep -nP '[ \t]+$' "$file")

  if [ -n "$tab_lines" ]; then
    ((files_with_tabs++))
    problem_found=true
    echo "  → Lines with tabs:"
    echo "$tab_lines"
  else
    echo "  → No tabs found"
  fi

  if [ -n "$trailing_ws_lines" ]; then
    ((files_with_trailing_ws++))
    problem_found=true
    echo "  → Lines with trailing whitespace:"
    echo "$trailing_ws_lines"
  else
    echo "  → No trailing whitespace found"
  fi

  echo
done

# Summary
echo "=== Summary ==="
echo "Total files scanned: $total_files"
echo "Files with tabs: $files_with_tabs"
echo "Files with trailing whitespace: $files_with_trailing_ws"

# Exit with error code if any problems found
if $problem_found; then
  echo "❌ Issues found. Exiting with error code 1."
  exit 1
else
  echo "✅ No issues found. Exiting with code 0."
  exit 0
fi
