/*
 * sandbox: unprivileged agent isolation via namespaces + landlock + seccomp.
 *
 * pivot_root (not chroot): swaps mount's root and detaches the old root so
 * child can't escape via ../.. or lingering fds. chroot is bypassable by
 * a proc with CAP_SYS_CHROOT or an open fd to old root.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>

#define STACK_SZ	(1 << 20)
#define NEW_ROOT	"/tmp/agent_root"

/*
 * Progressive isolation profiles. Each level adds on top of the previous,
 * so the demo probe shows strictly more BLOCKED rows as the profile rises.
 *	none		no isolation; baseline.
 *	ns_only		+ user/mnt/pid/net/ipc ns + pivot_root
 *	landlock	+ landlock fs restrictions
 *	full		+ drop caps + seccomp
 */
enum profile {
	PROF_NONE,
	PROF_NS,
	PROF_LANDLOCK,
	PROF_FULL,
};

static enum profile profile = PROF_FULL;
static const char *agent_dir;	/* host path bind-mounted at /agent */

/* glibc doesn't wrap the landlock syscalls — call them directly. */

#define LL_RX	(LANDLOCK_ACCESS_FS_EXECUTE   | \
		 LANDLOCK_ACCESS_FS_READ_FILE | \
		 LANDLOCK_ACCESS_FS_READ_DIR)

#define LL_RWX	(LL_RX				| \
		 LANDLOCK_ACCESS_FS_WRITE_FILE	| \
		 LANDLOCK_ACCESS_FS_MAKE_DIR	| \
		 LANDLOCK_ACCESS_FS_MAKE_REG	| \
		 LANDLOCK_ACCESS_FS_REMOVE_DIR	| \
		 LANDLOCK_ACCESS_FS_REMOVE_FILE)

static int
ll_allow(int rs, const char *path, __u64 access)
{
	struct landlock_path_beneath_attr pb = { .allowed_access = access };
	int fd, rc;

	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return 0;	/* path absent in sandbox root — skip */
	pb.parent_fd = fd;
	rc = syscall(__NR_landlock_add_rule, rs,
		     LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	close(fd);
	return rc;
}

struct args {
	char	**argv;
	int	 sync_fd;
};

static int
write_file(const char *path, const char *data)
{
	int fd, n;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	n = write(fd, data, strlen(data));
	close(fd);
	return n < 0 ? -1 : 0;
}

static int
setup_root(void)
{
	static const struct bind {
		const char	*src;
		int		 optional;
	} binds[] = {
		{ "/usr",   0 },
		{ "/lib",   0 },
		{ "/lib64", 1 },
		{ "/bin",   0 },
	};
	char dst[PATH_MAX];
	size_t i;

	/* make host mount propagation private so our mounts don't leak */
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
		perror("mount / private");
		return -1;
	}
	if (mount("tmpfs", NEW_ROOT, "tmpfs", 0, "size=64m")) {
		perror("mount tmpfs");
		return -1;
	}

	mkdir(NEW_ROOT "/proc",	   0755);
	mkdir(NEW_ROOT "/tmp",	   01777);
	mkdir(NEW_ROOT "/agent",   0755);
	mkdir(NEW_ROOT "/oldroot", 0755);

	for (i = 0; i < sizeof(binds) / sizeof(binds[0]); i++) {
		snprintf(dst, sizeof(dst), "%s%s", NEW_ROOT, binds[i].src);
		mkdir(dst, 0755);
		if (mount(binds[i].src, dst, NULL,
			  MS_BIND | MS_REC | MS_RDONLY, NULL) &&
		    !binds[i].optional)
			return -1;
	}

	if (mount(agent_dir, NEW_ROOT "/agent", NULL,
		  MS_BIND | MS_REC | MS_RDONLY, NULL)) {
		perror("mount agent");
		return -1;
	}

	/*
	 * Mount proc before pivot_root: kernel's mount_too_revealing check
	 * (non-init userns) requires an already-visible procfs in the mnt
	 * ns; after pivot_root+detach the host /proc is gone.
	 */
	if (mount("proc", NEW_ROOT "/proc", "proc", 0, NULL)) {
		perror("mount proc");
		return -1;
	}

	if (syscall(SYS_pivot_root, NEW_ROOT, NEW_ROOT "/oldroot")) {
		perror("pivot_root");
		return -1;
	}
	if (chdir("/"))
		return -1;
	if (umount2("/oldroot", MNT_DETACH))
		return -1;
	rmdir("/oldroot");

	return 0;
}

static int
apply_landlock(void)
{
	struct landlock_ruleset_attr attr = {
		.handled_access_fs =
			LANDLOCK_ACCESS_FS_EXECUTE	|
			LANDLOCK_ACCESS_FS_READ_FILE	|
			LANDLOCK_ACCESS_FS_READ_DIR	|
			LANDLOCK_ACCESS_FS_WRITE_FILE	|
			LANDLOCK_ACCESS_FS_REMOVE_DIR	|
			LANDLOCK_ACCESS_FS_REMOVE_FILE	|
			LANDLOCK_ACCESS_FS_MAKE_DIR	|
			LANDLOCK_ACCESS_FS_MAKE_REG,
	};
	int fd;

	fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (fd < 0)
		return -1;

	if (ll_allow(fd, "/usr",   LL_RX)  ||
	    ll_allow(fd, "/lib",   LL_RX)  ||
	    ll_allow(fd, "/lib64", LL_RX)  ||
	    ll_allow(fd, "/bin",   LL_RX)  ||
	    ll_allow(fd, "/agent", LL_RX)  ||
	    ll_allow(fd, "/proc",  LL_RX)  ||
	    ll_allow(fd, "/tmp",   LL_RWX)) {
		close(fd);
		return -1;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	if (syscall(__NR_landlock_restrict_self, fd, 0))
		return -1;
	close(fd);
	return 0;
}

/*
 * Drop all capabilities. Mounts + pivot_root already done, so nothing
 * after this needs caps. Kills CAP_NET_RAW → SOCK_RAW socket() → EPERM.
 */
static int
drop_caps(void)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid	 = 0,
	};
	struct __user_cap_data_struct data[2] = { { 0 } };

	return syscall(SYS_capset, &hdr, data);
}

static int
apply_seccomp(void)
{
	/*
	 * RET_ERRNO (not KILL): agent gets EPERM and can continue — demo
	 * probe reports the block. Use KILL only for syscalls we never
	 * want observed at all.
	 */
	#define DENY	(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount,	 0, 1),
		BPF_STMT(BPF_RET | BPF_K, DENY),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_umount2, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, DENY),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, DENY),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pivot_root, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, DENY),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_reboot, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, DENY),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len	= sizeof(f) / sizeof(f[0]),
		.filter	= f,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

static int
child(void *arg)
{
	struct args *a = arg;
	char buf;

	/* wait for parent to write uid_map/gid_map */
	if (read(a->sync_fd, &buf, 1) != 1)
		_exit(1);
	close(a->sync_fd);

	if (profile >= PROF_NS && setup_root()) {
		perror("setup_root");
		_exit(1);
	}
	if (profile >= PROF_LANDLOCK && apply_landlock()) {
		perror("landlock");
		_exit(1);
	}
	if (profile >= PROF_FULL) {
		if (drop_caps()) {
			perror("drop_caps");
			_exit(1);
		}
		if (apply_seccomp()) {
			perror("seccomp");
			_exit(1);
		}
	}

	execvp(a->argv[0], a->argv);
	perror("execvp");
	_exit(127);
}

static void
usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--profile none|ns_only|landlock|full] "
		"cmd [args...]\n", prog);
}

static int
parse_profile(const char *s, enum profile *p)
{
	if (!strcmp(s, "none"))		*p = PROF_NONE;
	else if (!strcmp(s, "ns_only"))	*p = PROF_NS;
	else if (!strcmp(s, "landlock"))	*p = PROF_LANDLOCK;
	else if (!strcmp(s, "full"))	*p = PROF_FULL;
	else				return -1;
	return 0;
}

int
main(int argc, char **argv)
{
	struct args a;
	int pipefd[2], status, argi = 1, flags = SIGCHLD;
	char path[64], map[64];
	char agent_buf[PATH_MAX];
	const char *env_agent;
	pid_t pid;
	void *stack;

	if (argi < argc && !strcmp(argv[argi], "--profile")) {
		if (argi + 1 >= argc || parse_profile(argv[argi + 1],
						      &profile)) {
			usage(argv[0]);
			return 1;
		}
		argi += 2;
	}

	if (argi >= argc) {
		usage(argv[0]);
		return 1;
	}

	if (profile >= PROF_NS) {
		env_agent = getenv("AGENT_DIR");
		if (env_agent) {
			agent_dir = env_agent;
		} else {
			if (!realpath("./agent", agent_buf)) {
				perror("realpath ./agent (set AGENT_DIR?)");
				return 1;
			}
			agent_dir = agent_buf;
		}
		mkdir(NEW_ROOT, 0755);
		flags |= CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
			 CLONE_NEWNET  | CLONE_NEWIPC;
	}

	if (pipe(pipefd))
		return 1;
	a.argv	  = argv + argi;
	a.sync_fd = pipefd[0];

	stack = malloc(STACK_SZ);
	if (!stack)
		return 1;

	pid = clone(child, (char *)stack + STACK_SZ, flags, &a);
	if (pid < 0) {
		perror("clone");
		return 1;
	}
	close(pipefd[0]);

	if (profile >= PROF_NS) {
		/* setgroups=deny must precede gid_map for unpriv userns */
		snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
		if (write_file(path, "deny"))
			perror("setgroups");

		snprintf(map,  sizeof(map),  "0 %d 1", getuid());
		snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
		if (write_file(path, map))
			perror("uid_map");

		snprintf(map,  sizeof(map),  "0 %d 1", getgid());
		snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
		if (write_file(path, map))
			perror("gid_map");
	}

	/* release child */
	if (write(pipefd[1], "x", 1) != 1)
		perror("sync");
	close(pipefd[1]);

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}
	free(stack);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
