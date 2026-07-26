#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-only
#
# Run meson unit tests with the `make test-*` conventions:
#   $1 - meson build directory
#   $2 - test name glob (TEST make variable, same pattern as test/run.py -p)
#   $3 - fail fast: 1 stops at the first failing test (FAILFAST make variable)

builddir=$1
pattern=${2:-*}
failfast=${3:-0}

matched=""
for t in $(meson test -C "$builddir" --list); do
	case $t in
	$pattern)
		matched="$matched $t"
		;;
	esac
done

if [ -z "$matched" ]; then
	echo "unit tests: no tests match '$pattern', skipping"
	exit 0
fi

maxfail=""
if [ "$failfast" != 0 ]; then
	maxfail="--maxfail 1"
fi

exec meson test -C "$builddir" --print-errorlogs $maxfail $matched
