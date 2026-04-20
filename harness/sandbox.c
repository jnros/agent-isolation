/*
 * sandbox: unprivileged agent isolation via namespaces + landlock + seccomp.
 *
 * pivot_root vs chroot: pivot_root swaps the mount's root and requires new
 * root to be a mountpoint; old root is detached so the child cannot escape
 * via ../.. or open fds. chroot only changes the path resolution root and
 * a process with CAP_SYS_CHROOT (or open fd to old root) can break out.
 * We use pivot_root; fallback to chroot only if pivot_root fails.
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
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>

#define STACK_SZ	(1 << 20)
#define NEW_ROOT	"/tmp/agent_root"

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *a,
			size_t sz, __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, a, sz, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int
landlock_restrict_self(int fd, __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, fd, flags);
}
#endif

#ifndef landlock_add_rule
static inline int
landlock_add_rule(int fd, enum landlock_rule_type t,
		  const void *attr, __u32 flags)
{
	return syscall(__NR_landlock_add_rule, fd, t, attr, flags);
}
#endif

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
	rc = landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
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
do_pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

static int
setup_root(void)
{
	/* make host mount propagation private so our mounts don't leak */
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
		perror("mount / private");
		return -1;
	}

	if (mount("tmpfs", NEW_ROOT, "tmpfs", 0, "size=64m")) {
		perror("mount tmpfs");
		return -1;
	}

	mkdir(NEW_ROOT "/usr",	  0755);
	mkdir(NEW_ROOT "/lib",	  0755);
	mkdir(NEW_ROOT "/lib64",  0755);
	mkdir(NEW_ROOT "/bin",	  0755);
	mkdir(NEW_ROOT "/proc",	  0755);
	mkdir(NEW_ROOT "/tmp",	  01777);
	mkdir(NEW_ROOT "/oldroot", 0755);

	if (mount("/usr", NEW_ROOT "/usr", NULL,
		  MS_BIND | MS_REC | MS_RDONLY, NULL))
		return -1;

	if (mount("/lib", NEW_ROOT "/lib", NULL,
		  MS_BIND | MS_REC | MS_RDONLY, NULL))
		return -1;

	mount("/lib64", NEW_ROOT "/lib64", NULL,
	      MS_BIND | MS_REC | MS_RDONLY, NULL);

	if (mount("/bin", NEW_ROOT "/bin", NULL,
		  MS_BIND | MS_REC | MS_RDONLY, NULL))
		return -1;

	/*
	 * Mount proc before pivot_root: kernel's mount_too_revealing check
	 * (non-init userns) requires an already-visible procfs in the mnt
	 * ns; after pivot_root+detach the host /proc is gone.
	 */
	if (mount("proc", NEW_ROOT "/proc", "proc", 0, NULL)) {
		perror("mount proc");
		return -1;
	}

	if (do_pivot_root(NEW_ROOT, NEW_ROOT "/oldroot")) {
		/* fallback: chroot is weaker, see file header */
		if (chroot(NEW_ROOT))
			return -1;
		if (chdir("/"))
			return -1;
	} else {
		if (chdir("/"))
			return -1;
		if (umount2("/oldroot", MNT_DETACH))
			return -1;
		rmdir("/oldroot");
	}

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

	fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	if (fd < 0)
		return -1;

	if (ll_allow(fd, "/usr",   LL_RX)  ||
	    ll_allow(fd, "/lib",   LL_RX)  ||
	    ll_allow(fd, "/lib64", LL_RX)  ||
	    ll_allow(fd, "/bin",   LL_RX)  ||
	    ll_allow(fd, "/tmp",   LL_RWX)) {
		close(fd);
		return -1;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	if (landlock_restrict_self(fd, 0))
		return -1;
	close(fd);
	return 0;
}

static int
apply_seccomp(void)
{
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount,	 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_umount2, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pivot_root, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_reboot, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
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

	if (setup_root()) {
		perror("setup_root");
		_exit(1);
	}
	if (apply_landlock()) {
		perror("landlock");
		_exit(1);
	}
	if (apply_seccomp()) {
		perror("seccomp");
		_exit(1);
	}

	execvp(a->argv[0], a->argv);
	perror("execvp");
	_exit(127);
}

int
main(int argc, char **argv)
{
	struct args a;
	int pipefd[2], status;
	char path[64], map[64];
	pid_t pid;
	void *stack;

	if (argc < 2) {
		fprintf(stderr, "usage: %s cmd [args...]\n", argv[0]);
		return 1;
	}

	mkdir(NEW_ROOT, 0755);

	if (pipe(pipefd))
		return 1;
	a.argv	  = argv + 1;
	a.sync_fd = pipefd[0];

	stack = malloc(STACK_SZ);
	if (!stack)
		return 1;

	pid = clone(child, (char *)stack + STACK_SZ,
		    CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
		    CLONE_NEWNET  | CLONE_NEWIPC | SIGCHLD, &a);
	if (pid < 0) {
		perror("clone");
		return 1;
	}
	close(pipefd[0]);

	/* setgroups=deny must precede gid_map for unprivileged user ns */
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
