/*
 * probe: read another process's kern.procargs2 and report what came back.
 *
 *   probe read   <pid> <arg-marker> <env-marker>
 *   probe sleep  <seconds> <arg-marker>
 *   probe launch <profile-path|none> <arg-marker>
 *   probe detach <none|pgrp|session> <absolute-path> [args...]
 *
 * read, sleep and launch print exactly one result line to stdout. A refused
 * read is a result, not an error: the exit status is non-zero only on a usage
 * error or when the harness itself breaks (no result line is printed then).
 * detach prints nothing itself; it becomes the command it runs.
 */
#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <mach-o/dyld.h>

extern char **environ;

#define ENV_NAME "PROCARGS_TEST_SECRET"

static int usage(void)
{
	fprintf(stderr,
	    "usage: probe read <pid> <arg-marker> <env-marker>\n"
	    "       probe sleep <seconds> <arg-marker>\n"
	    "       probe launch <profile-path|none> <arg-marker>\n"
	    "       probe detach <none|pgrp|session> <absolute-path> [args...]\n"
	    "         (launch takes the env marker from $" ENV_NAME ")\n");
	return 2;
}

static const char *errno_name(int e)
{
	switch (e) {
	case EPERM:  return "EPERM";
	case EACCES: return "EACCES";
	case EINVAL: return "EINVAL";
	case ESRCH:  return "ESRCH";
	case ENOMEM: return "ENOMEM";
	case EFAULT: return "EFAULT";
	default:     return "OTHER";
	}
}

static int parse_long(const char *s, long *out)
{
	char *end;

	errno = 0;
	*out = strtol(s, &end, 10);
	return errno == 0 && *s != '\0' && *end == '\0' && *out >= 0;
}

static int refused(int e, const char *stage)
{
	printf("refused errno=%d name=%s stage=%s\n", e, errno_name(e), stage);
	return 0;
}

static int do_read(pid_t pid, const char *arg, const char *env)
{
	int mib[3] = { CTL_KERN, KERN_PROCARGS2, (int)pid };
	size_t size = 0;
	char *buf;

	/*
	 * Size query first, then the real read, so the table shows which of the
	 * two calls a profile refuses. Seatbelt can treat them differently.
	 */
	if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0)
		return refused(errno, "size");

	/* Headroom in case the target's arguments change between the calls. */
	size = size * 2 + 1;
	if ((buf = malloc(size)) == NULL) {
		perror("malloc");
		return 1;
	}
	if (sysctl(mib, 3, buf, &size, NULL, 0) != 0) {
		int e = errno;
		free(buf);
		return refused(e, "data");
	}

	/* argc, then NUL-separated strings: search bytes, not C strings. */
	printf("read args=%s env=%s\n",
	    memmem(buf, size, arg, strlen(arg)) ? "yes" : "no",
	    memmem(buf, size, env, strlen(env)) ? "yes" : "no");
	free(buf);
	return 0;
}

static int do_sleep(long seconds)
{
	/* The arg marker needs no handling: being in argv is its whole job. */
	sleep((unsigned)seconds);
	printf("slept %ld\n", seconds);
	return 0;
}

static int do_launch(const char *profile, const char *arg)
{
	char raw[PATH_MAX], self[PATH_MAX], pidstr[32];
	uint32_t rawlen = sizeof(raw);
	const char *env = getenv(ENV_NAME);
	char *argv[9];
	int i = 0, status;
	pid_t child;

	/*
	 * The env marker comes from our environment, not argv: if it were in
	 * argv too, the child could not tell which of the two it found.
	 */
	if (env == NULL || *env == '\0')
		return usage();

	/* sandbox-exec needs an absolute path to the program it runs. */
	if (_NSGetExecutablePath(raw, &rawlen) != 0 || realpath(raw, self) == NULL) {
		perror("cannot resolve own path");
		return 1;
	}
	snprintf(pidstr, sizeof(pidstr), "%d", (int)getpid());

	if (strcmp(profile, "none") != 0) {
		argv[i++] = "/usr/bin/sandbox-exec";
		argv[i++] = "-f";
		argv[i++] = (char *)profile;
	}
	argv[i++] = self;
	argv[i++] = "read";
	argv[i++] = pidstr;
	argv[i++] = (char *)arg;
	argv[i++] = (char *)env;
	argv[i] = NULL;

	/* The child inherits stdout, so its result line passes through as is. */
	fflush(stdout);
	if ((errno = posix_spawn(&child, argv[0], NULL, NULL, argv, environ)) != 0) {
		perror("posix_spawn");
		return 1;
	}
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR) {
			perror("waitpid");
			return 1;
		}
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static int do_detach(const char *how, char **cmd)
{
	/*
	 * agent-sandbox.nix's test harness starts its sandbox with setsid(). This
	 * reproduces that, or only a new process group, then runs the command in
	 * this same process, so a background target keeps the pid it was given.
	 */
	if (strcmp(how, "session") == 0) {
		if (setsid() < 0) {
			perror("setsid");
			return 1;
		}
	} else if (strcmp(how, "pgrp") == 0) {
		if (setpgid(0, 0) != 0) {
			perror("setpgid");
			return 1;
		}
	} else if (strcmp(how, "none") != 0) {
		return usage();
	}
	execv(cmd[0], cmd);
	perror("execv");
	return 1;
}

int main(int argc, char **argv)
{
	long n;

	if (argc == 5 && strcmp(argv[1], "read") == 0 && parse_long(argv[2], &n) && n > 0)
		return do_read((pid_t)n, argv[3], argv[4]);
	if (argc == 4 && strcmp(argv[1], "sleep") == 0 && parse_long(argv[2], &n))
		return do_sleep(n);
	if (argc == 4 && strcmp(argv[1], "launch") == 0)
		return do_launch(argv[2], argv[3]);
	if (argc >= 4 && strcmp(argv[1], "detach") == 0)
		return do_detach(argv[2], argv + 3);
	return usage();
}
