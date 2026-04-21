#!/usr/bin/env bash
# bench.sh [iters] [runs]	startup + syscall cost per profile -> perf.txt
set -eu
cd "$(dirname "$0")"

iters="${1:-10000000}"
runs="${2:-1000}"
hf=$(mktemp)
summary=$(mktemp)
trap 'rm -f "$hf" "$summary"' EXIT

printf "%-10s %14s %16s\n" profile startup_ms ns_per_syscall >"$summary"

{
for prof in none ns_only landlock full; do
	echo "=== profile: $prof ==="
	hyperfine -N --warmup 50 --runs "$runs" \
		--export-json "$hf" \
		"harness/sandbox --profile $prof /bin/true" 2>&1
	start_ms=$(jq '.results[0].mean * 1000' "$hf")

	case "$prof" in
	none)	path=agent/syscall_loop ;;
	*)	path=/agent/syscall_loop ;;
	esac
	sys=$(harness/sandbox --profile "$prof" "$path" "$iters")
	echo "$sys"
	ns=$(echo "$sys" | awk '{print $(NF-1)}')

	printf "%-10s %14.3f %16s\n" "$prof" "$start_ms" "$ns" >>"$summary"
	echo
done
echo "=== summary ==="
cat "$summary"
} | tee perf.txt
