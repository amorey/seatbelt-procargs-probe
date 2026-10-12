#!/bin/sh
# Can a Seatbelt-sandboxed process read kern.procargs2 of each target, under
# each profile? Prints the environment, then one markdown table.
#
# The exit status says only whether the harness worked, never what the table
# shows: non-zero means the probe did not build, a profile was not enforced, a
# target was not alive when measured, or the probe printed no result line.
#
# Optional, for measuring someone else's profile as one more column:
#   EXTRA_PROFILE  path to a profile, reported as upstream.sb
#   PROBE_DIR      where to build the probe, for a profile that allows exec
#                  only in certain directories
set -u

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/seatbelt-procargs-probe.XXXXXX") || exit 1
probe="${PROBE_DIR:-$work}/probe"
conditions="unsandboxed control deny deny-regex"
[ -n "${EXTRA_PROFILE:-}" ] && conditions="$conditions upstream"
pids=""

profile() {
	if [ "$1" = upstream ]; then
		echo "$EXTRA_PROFILE"
	else
		echo "$here/profiles/$1.sb"
	fi
}

stop_target() {
	# The /bin/sh targets have a `sleep` child that would outlive them.
	pkill -P "$1" 2>/dev/null
	kill "$1" 2>/dev/null
	wait "$1" 2>/dev/null
}

cleanup() {
	for p in $pids; do stop_target "$p"; done
	[ -n "${PROBE_DIR:-}" ] && rm -f "$probe"
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

fail() {
	echo "harness error: $*" >&2
	exit 1
}

marker() {
	printf 'procargs-%s-%s' "$1" "$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
}

# --- build -------------------------------------------------------------------

cc -O0 -Wall -o "$probe" "$here/probe.c" || fail "probe did not build"

# --- enforcement check -------------------------------------------------------

# A read under a profile means nothing unless the profile is enforced. Each
# one is (deny default) and allows no writes under $TMPDIR, so a file write
# there must fail. The unsandboxed write shows the check can see a write.
try_write() {
	"$@" /bin/sh -c ': >"$1"' sh "$canary" 2>/dev/null
	[ -e "$canary" ]
}

canary="$work/canary-unsandboxed"
try_write || fail "unsandboxed file write failed, so the enforcement check cannot work"
for cond in $conditions; do
	[ "$cond" = unsandboxed ] && continue
	canary="$work/canary-$cond"
	if try_write /usr/bin/sandbox-exec -f "$(profile "$cond")"; then
		fail "$cond.sb did not block a file write, so it is not being enforced"
	fi
done

# --- environment -------------------------------------------------------------

signing() {
	codesign -dvvv "$1" 2>&1 |
		grep -E '^(Identifier|Authority|Platform identifier)=|flags=|not signed' |
		sed 's/^/  /'
}

{
	sw_vers
	echo "uname -m: $(uname -m)"
	echo "csrutil: $(csrutil status 2>&1)"
	echo "codesign /bin/sh:"
	signing /bin/sh
	echo "codesign probe (built by this run):"
	signing "$probe"
	echo "enforcement: every profile blocked a file write"
} >"$work/env"
cat "$work/env"
echo

# --- measurement -------------------------------------------------------------

# Turns the probe's result line into a table cell; fails on anything else.
cell() {
	case $1 in
	"read args=yes env=yes") echo "read (args, env)" ;;
	"read args=yes env=no") echo "read (args)" ;;
	"read args=no env=yes") echo "read (env)" ;;
	"read args=no env=no") echo "read (neither)" ;;
	"refused "*)
		name=$(echo "$1" | sed -n 's/.* name=\([^ ]*\).*/\1/p')
		stage=$(echo "$1" | sed -n 's/.* stage=\([^ ]*\)$/\1/p')
		echo "refused $name @$stage"
		;;
	*) return 1 ;;
	esac
}

# record <target> <condition> <probe output>: appends a cell to $row.
record() {
	c=$(cell "$3") ||
		fail "$1 under $2: no result line (stdout: '$3'; stderr: $(cat "$work/err"))"
	row="$row | $c"
	case $2 in
	unsandboxed)
		case $c in
		"read (args"*) ;;
		*) echo "warning: $1 unsandboxed gave '$c'; every target should read at least its args, so suspect the harness" >&2 ;;
		esac
		;;
	esac
}

# Starts an unrelated target in the background. `env -i` puts the env marker in
# env's own argv until it execs, so wait until the pid is the real program.
start_target() {
	want=$1
	shift
	"$@" >/dev/null 2>&1 &
	target=$!
	pids="$pids $target"
	tries=0
	until ps -o comm= -p "$target" 2>/dev/null | grep -q "$want\$"; do
		tries=$((tries + 1))
		[ "$tries" -le 50 ] || fail "target $* never became $want"
		sleep 0.1
	done
}

# measure_unrelated <name> <apple> <program-name> <command...>: the command is
# run with the markers in $arg and $env already in place.
measure_unrelated() {
	name=$1 apple=$2 want=$3
	shift 3
	start_target "$want" "$@"
	row="| $name | $apple | unrelated"
	for cond in $conditions; do
		kill -0 "$target" 2>/dev/null || fail "$name (pid $target) not alive before $cond"
		if [ "$cond" = unsandboxed ]; then
			out=$("$probe" read "$target" "$arg" "$env" 2>"$work/err")
		else
			out=$(/usr/bin/sandbox-exec -f "$(profile "$cond")" \
				"$probe" read "$target" "$arg" "$env" 2>"$work/err")
		fi
		record "$name" "$cond" "$out"
	done
	stop_target "$target"
	echo "$row |" >>"$work/rows"
}

: >"$work/rows"

arg=$(marker arg) env=$(marker env)
measure_unrelated sh-unrelated yes sh \
	env -i PROCARGS_TEST_SECRET="$env" /bin/sh -c '/bin/sleep 60; :' "$arg"

arg=$(marker arg) env=$(marker env)
measure_unrelated probe-unrelated no probe \
	env -i PROCARGS_TEST_SECRET="$env" "$probe" sleep 60 "$arg"

# The ancestor targets are alive by construction: they are waiting on the
# sandboxed probe. Their markers are never spelled out in their argv except as
# themselves: sh gets the arg marker as $0 and reads the env marker from its
# environment, and `probe launch` takes the env marker from its environment.
arg=$(marker arg) env=$(marker env)
row="| sh-ancestor | yes | ancestor"
for cond in $conditions; do
	if [ "$cond" = unsandboxed ]; then
		pre=""
	else
		pre="/usr/bin/sandbox-exec -f '$(profile "$cond")' "
	fi
	# `; :` stops sh from exec'ing its last command, which would replace the
	# target with the probe. $$ is this shell, the sandboxed probe's parent.
	out=$(env -i PROCARGS_TEST_SECRET="$env" /bin/sh -c \
		"$pre'$probe' read \$\$ \"\$0\" \"\$PROCARGS_TEST_SECRET\"; :" "$arg" \
		2>"$work/err")
	record sh-ancestor "$cond" "$out"
done
echo "$row |" >>"$work/rows"

arg=$(marker arg) env=$(marker env)
row="| probe-ancestor | no | ancestor"
for cond in $conditions; do
	if [ "$cond" = unsandboxed ]; then p=none; else p=$(profile "$cond"); fi
	out=$(env -i PROCARGS_TEST_SECRET="$env" "$probe" launch "$p" "$arg" 2>"$work/err")
	record probe-ancestor "$cond" "$out"
done
echo "$row |" >>"$work/rows"

# --- report ------------------------------------------------------------------

{
	printf '| target | apple binary | relation |'
	for cond in $conditions; do
		case $cond in unsandboxed) printf ' %s |' "$cond" ;; *) printf ' %s.sb |' "$cond" ;; esac
	done
	printf '\n|---|---|---|'
	for cond in $conditions; do printf -- '---|'; done
	echo
	cat "$work/rows"
} >"$work/table"
cat "$work/table"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "## $(sw_vers -productVersion) ($(sw_vers -buildVersion), $(uname -m))"
		echo
		echo '```'
		cat "$work/env"
		echo '```'
		echo
		cat "$work/table"
	} >>"$GITHUB_STEP_SUMMARY"
fi
