#!/bin/sh
# Which part of agent-sandbox.nix's setup gets kern.procargs2 refused, when its
# own profile alone does not? Runs two readers, our C probe and their
# probe.lua under LuaJIT, through each way of entering the sandbox, against
# an unrelated target and an ancestor. Prints one markdown table.
#
# Needs, all from the upstream workflow:
#   PROFILE         the seatbelt.sb their test generated
#   WORKSPACE       that test's workspace: their profile allows exec in it,
#                   and it still holds the probe.lua the test wrote
#   LUAJIT          the luajit binary from their fixture's closure
#   SANDBOXED_BASH  their launcher, built from the same fixture
#
# Exits non-zero only if a reader printed nothing, which is a harness fault.
set -u
: "${PROFILE:?}" "${WORKSPACE:?}" "${LUAJIT:?}" "${SANDBOXED_BASH:?}"

here=$(cd "$(dirname "$0")/.." && pwd)
probe="$WORKSPACE/probe"
lua="$WORKSPACE/probe.lua"
: "${RUNNER_TEMP:=${TMPDIR:-/tmp}}"

[ -f "$lua" ] || { echo "no probe.lua in $WORKSPACE" >&2; exit 1; }
cc -O0 -Wall -o "$probe" "$here/probe.c" || exit 1

/bin/sh -c '/bin/sleep 600; :' unrelated-target &
unrelated=$!
trap 'pkill -P "$unrelated"; kill "$unrelated"; rm -f "$probe"' EXIT

# reader_cmd <reader> <pid>: the reader's argv, one word per line. The C
# probe's markers are placeholders; only read vs refused matters here.
reader_cmd() {
	case $1 in
	c) printf '%s\n' "$probe" read "$2" no-marker no-marker ;;
	lua) printf '%s\n' "$LUAJIT" "$lua" "$2" ;;
	esac
}

# run_via <how> <reader> <pid>: prints the reader's stdout.
run_via() {
	how=$1
	set -- $(reader_cmd "$2" "$3")
	case $how in
	unsandboxed)
		"$@" ;;
	deny-regex)
		/usr/bin/sandbox-exec -f "$here/profiles/deny-regex.sb" "$@" ;;
	plain)
		/usr/bin/sandbox-exec -f "$PROFILE" "$@" ;;
	child)
		# A child of a shell inside the sandbox, as their bash -c makes it;
		# `; :` keeps sh from exec'ing the reader in its own place.
		/usr/bin/sandbox-exec -f "$PROFILE" /bin/sh -c '"$@"; :' sh "$@" ;;
	launcher)
		# Their launcher, exactly as their test harness calls it. It writes
		# a fresh profile for this workspace; the launch log keeps the path.
		(cd "$WORKSPACE" && AGENT_SANDBOX_SESSIONS_ROOT="$RUNNER_TEMP/sessions" \
			"$SANDBOXED_BASH" --norc --noprofile -c "$*" </dev/null) ;;
	esac
}

# Normalises both readers' output to read / EPERM, keeping the raw line.
cell() {
	case $1 in
	"read "*) echo "read" ;;
	"refused "*) echo "$1" | sed -n 's/.* name=\([^ ]*\) stage=\(.*\)/\1 @\2/p' ;;
	"") echo "no output"; return 1 ;;
	*)
		# probe.lua prints errnos for kern.proc.all, kern.procargs and
		# kern.procargs2; 0 means the read worked.
		set -- $1
		case ${3:-} in 0) r=read ;; 1) r=EPERM ;; *) r="errno ${3:-?}" ;; esac
		echo "$r (all: $*)"
		;;
	esac
}

hows="unsandboxed deny-regex plain child launcher"
echo "| reader | target | unsandboxed | deny-regex.sb | their profile, direct | their profile, child of sh | their launcher |"
echo "|---|---|---|---|---|---|---|"
for reader in c lua; do
	for t in unrelated ancestor; do
		if [ $t = unrelated ]; then pid=$unrelated; else pid=$$; fi
		kill -0 "$pid" 2>/dev/null || { echo "target $t ($pid) not alive" >&2; exit 1; }
		row="| $reader | $t"
		for how in $hows; do
			out=$(run_via "$how" "$reader" "$pid" 2>"$RUNNER_TEMP/err")
			if ! c=$(cell "$out"); then
				echo "no output: $reader / $t / $how: $(cat "$RUNNER_TEMP/err")" >&2
			fi
			row="$row | $c"
		done
		echo "$row |"
	done
done | tee "$RUNNER_TEMP/matrix.md"

[ -n "${GITHUB_STEP_SUMMARY:-}" ] && {
	echo "## launch matrix: $(sw_vers -productVersion) ($(uname -m))"
	echo
	cat "$RUNNER_TEMP/matrix.md"
} >>"$GITHUB_STEP_SUMMARY"

grep -q '| no output' "$RUNNER_TEMP/matrix.md" && exit 1
exit 0
