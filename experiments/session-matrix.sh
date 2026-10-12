#!/bin/sh
# Does the session a sandboxed reader runs in decide whether kern.procargs2 is
# refused? agent-sandbox.nix's test harness starts its sandbox with setsid(),
# and its reads were refused only for targets outside that new session.
#
# Starts the sandboxed reader in this script's session, in a new process
# group, and in a new session, under each profile, against a target in this
# session, this script itself (an ancestor), and a target in a session of its
# own. Prints one markdown table.
#
# Exits non-zero only if the harness broke.
set -u

here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/seatbelt-session-matrix.XXXXXX") || exit 1
probe="$work/probe"
conditions="unsandboxed control deny-info deny-sysctl deny deny-regex"
pids=""

cleanup() {
	for p in $pids; do
		pkill -P "$p" 2>/dev/null
		kill "$p" 2>/dev/null
	done
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

fail() {
	echo "harness error: $*" >&2
	exit 1
}

cc -O0 -Wall -o "$probe" "$here/probe.c" || fail "probe did not build"

# Same enforcement check as run.sh, for the two profiles it does not use.
for cond in $conditions; do
	[ "$cond" = unsandboxed ] && continue
	canary="$work/canary-$cond"
	/usr/bin/sandbox-exec -f "$here/profiles/$cond.sb" \
		/bin/sh -c ': >"$1"' sh "$canary" 2>/dev/null
	[ -e "$canary" ] && fail "$cond.sb did not block a file write"
done

# start_target <detach>: a /bin/sh that sleeps, in this session or its own.
start_target() {
	"$probe" detach "$1" /bin/sh -c '/bin/sleep 600; :' >/dev/null 2>&1 &
	target=$!
	pids="$pids $target"
	tries=0
	until ps -o comm= -p "$target" 2>/dev/null | grep -q 'sh$'; do
		tries=$((tries + 1))
		[ "$tries" -le 50 ] || fail "target never became sh"
		sleep 0.1
	done
}

start_target none
same_session=$target
start_target session
own_session=$target

# Checks the detach worked: setsid() also makes the caller a group leader,
# while a plain background job stays in this script's process group.
[ "$(ps -o pgid= -p "$own_session" | tr -d ' ')" = "$own_session" ] ||
	fail "own-session target did not get a session of its own"
[ "$(ps -o pgid= -p "$same_session" | tr -d ' ')" != "$same_session" ] ||
	fail "same-session target unexpectedly leads its own process group"

cell() {
	case $1 in
	"read "*) echo "read" ;;
	"refused "*) echo "$1" | sed -n 's/.* name=\([^ ]*\) stage=\(.*\)/\1 @\2/p' ;;
	*) return 1 ;;
	esac
}

# read_as <detach> <condition> <pid>
read_as() {
	if [ "$2" = unsandboxed ]; then
		"$probe" detach "$1" "$probe" read "$3" no-marker no-marker
	else
		"$probe" detach "$1" /usr/bin/sandbox-exec -f "$here/profiles/$2.sb" \
			"$probe" read "$3" no-marker no-marker
	fi
}

{
	printf '| target | reader started in |'
	for cond in $conditions; do
		case $cond in unsandboxed) printf ' %s |' "$cond" ;; *) printf ' %s.sb |' "$cond" ;; esac
	done
	printf '\n|---|---|'
	for cond in $conditions; do printf -- '---|'; done
	echo
	for t in same-session ancestor own-session; do
		case $t in
		same-session) pid=$same_session ;;
		ancestor) pid=$$ ;;
		own-session) pid=$own_session ;;
		esac
		for d in none pgrp session; do
			case $d in
			none) where="this session" ;;
			pgrp) where="new process group" ;;
			session) where="new session" ;;
			esac
			row="| $t | $where"
			for cond in $conditions; do
				kill -0 "$pid" 2>/dev/null || fail "$t (pid $pid) not alive"
				out=$(read_as "$d" "$cond" "$pid" 2>"$work/err")
				c=$(cell "$out") ||
					fail "$t / $d / $cond: no result line (stdout: '$out'; stderr: $(cat "$work/err"))"
				row="$row | $c"
			done
			echo "$row |"
		done
	done
} >"$work/table" || exit 1
cat "$work/table"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "## session matrix: $(sw_vers -productVersion) ($(sw_vers -buildVersion), $(uname -m))"
		echo
		cat "$work/table"
	} >>"$GITHUB_STEP_SUMMARY"
fi
