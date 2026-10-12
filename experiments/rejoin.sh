#!/bin/sh
# session-matrix.sh shows the two rules refuse kern.procargs2 only across
# process groups. Can code inside the sandbox undo that by moving itself back
# into the target's process group? Starts the sandbox in a new process group
# or a new session; inside it, the probe optionally calls setpgid() to join
# this script's group before reading. Prints one markdown table.
#
# Exits non-zero only if the harness broke.
set -u

here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/seatbelt-rejoin.XXXXXX") || exit 1
probe="$work/probe"
conditions="control deny deny-regex"
target=""

cleanup() {
	if [ -n "$target" ]; then
		pkill -P "$target" 2>/dev/null
		kill "$target" 2>/dev/null
	fi
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

fail() {
	echo "harness error: $*" >&2
	exit 1
}

cc -O0 -Wall -o "$probe" "$here/probe.c" || fail "probe did not build"

pgid=$(ps -o pgid= -p $$ | tr -d ' ')
/bin/sh -c '/bin/sleep 600; :' &
target=$!
[ "$(ps -o pgid= -p "$target" | tr -d ' ')" = "$pgid" ] ||
	fail "target is not in this script's process group $pgid"

# cell <output>: an optional join line, then the read's result line.
cell() {
	joined="" result=""
	while IFS= read -r line; do
		case $line in
		"join ok"*) joined="joined" ;;
		"join refused "*) joined="join $(echo "$line" | sed -n 's/.* name=\([^ ]*\).*/\1/p')" ;;
		"read "*) result="read" ;;
		"refused "*) result=$(echo "$line" | sed -n 's/.* name=\([^ ]*\) stage=\(.*\)/\1 @\2/p') ;;
		esac
	done <<EOF
$1
EOF
	[ -n "$result" ] || return 1
	echo "${joined:+$joined, }$result"
}

{
	printf '| target | sandbox started in | rejoins target group |'
	for cond in $conditions; do printf ' %s.sb |' "$cond"; done
	printf '\n|---|---|---|'
	for cond in $conditions; do printf -- '---|'; done
	echo
	for t in same-group ancestor; do
		if [ $t = same-group ]; then pid=$target; else pid=$$; fi
		for d in pgrp session; do
			case $d in
			pgrp) where="new process group" ;;
			session) where="new session" ;;
			esac
			for attempt in no yes; do
				if [ $attempt = yes ]; then join="$probe join $pgid"; else join=""; fi
				row="| $t | $where | $attempt"
				for cond in $conditions; do
					kill -0 "$pid" 2>/dev/null || fail "$t (pid $pid) not alive"
					# $join is unquoted on purpose: empty, or three words.
					out=$("$probe" detach "$d" /usr/bin/sandbox-exec \
						-f "$here/profiles/$cond.sb" $join \
						"$probe" read "$pid" no-marker no-marker 2>"$work/err")
					c=$(cell "$out") ||
						fail "$t / $d / $attempt / $cond: no result line (stdout: '$out'; stderr: $(cat "$work/err"))"
					row="$row | $c"
				done
				echo "$row |"
			done
		done
	done
} >"$work/table" || exit 1
cat "$work/table"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "## rejoin: $(sw_vers -productVersion) ($(sw_vers -buildVersion), $(uname -m))"
		echo
		cat "$work/table"
	} >>"$GITHUB_STEP_SUMMARY"
fi
