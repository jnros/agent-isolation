#!/usr/bin/env bash
# run probe under each profile — progressive isolation demo.
set -eu
cd "$(dirname "$0")"

for prof in none ns_only landlock full; do
	echo "=== profile: $prof ==="
	case "$prof" in
	none)	path=agent/probe.py ;;	# no mnt ns; host path
	*)	path=/agent/probe.py ;;	# bind-mounted by sandbox
	esac
	harness/sandbox --profile "$prof" /usr/bin/python3 "$path" || true
	echo
done
