#!/usr/bin/env bash
# demo: probe under each profile
set -eu
cd "$(dirname "$0")"

for prof in none ns_only landlock full; do
	echo "=== profile: $prof ==="
	case "$prof" in
	none)	path=agent/probe.py ;;	# no mnt ns; host path
	*)	path=/agent/probe.py ;;	# bind-mounted by sandbox
	esac
	SANDBOX_PROFILE="$prof" harness/sandbox --profile "$prof" \
		/usr/bin/python3 "$path" || true
	echo
done
