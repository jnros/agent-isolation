#!/usr/bin/env python3
# sandbox probe: try forbidden ops, report outcome.

import ctypes
import ctypes.util
import errno
import os
import signal
import socket
import sys

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

PTRACE_TRACEME	= 0

PROFILE		= os.environ.get("SANDBOX_PROFILE", "full")
HAS_LANDLOCK	= PROFILE in ("landlock", "full")
HAS_SECCOMP	= PROFILE == "full"


def errtup(e):
	code = e.errno
	if code is None:
		return ("?", str(e))
	return (errno.errorcode.get(code, str(code)), os.strerror(code))


def blocker_for(key, err):
	if err is None:
		return "-"
	code = err[0]
	if code == "EPERM":
		if key == "mount_tmpfs":
			return ("seccomp" if HAS_SECCOMP
				else "landlock" if HAS_LANDLOCK
				else "caps")
		if key == "ptrace_traceme":
			return "seccomp" if HAS_SECCOMP else "caps/lsm"
		return {
			"kill_all":	"pidns/caps",
			"socket_raw":	"caps",
			"open_mem":	"caps",
		}.get(key, "caps/lsm")
	if code == "EACCES":
		return "landlock" if HAS_LANDLOCK else "DAC"
	if code == "ENOENT":
		if key == "read_proc2":
			return "pid ns"
		return "mnt ns (not present)"
	if code in ("EAFNOSUPPORT", "ENETUNREACH"):
		return "net ns"
	if code == "ENOSYS":
		return "seccomp"
	if code == "ESRCH" and key == "kill_all":
		return "pid ns (no other procs)"
	return code


def libc_call(fn, *args):
	ctypes.set_errno(0)
	if fn(*args) != 0:
		e = ctypes.get_errno()
		raise OSError(e, os.strerror(e))


def op_read(p):
	with open(p, "rb") as f:
		f.read(64)


def op_write(p):
	with open(p, "wb") as f:
		f.write(b"x")


def op_open(p):
	os.close(os.open(p, os.O_RDONLY))


def op_sock_raw():
	socket.socket(socket.AF_INET, socket.SOCK_RAW,
		      socket.IPPROTO_ICMP).close()


def op_connect():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	s.settimeout(2)
	try:
		s.connect(("8.8.8.8", 53))
	finally:
		s.close()


def op_ptrace():
	libc_call(libc.ptrace, PTRACE_TRACEME, 0, 0, 0)


def op_mount():
	libc_call(libc.mount, b"tmpfs", b"/tmp", b"tmpfs", 0, None)


def op_kill_all():
	os.kill(-1, signal.SIGKILL)


def in_host_pidns():
	# /proc/self/status NSpid lists pid in each nested pid ns, outer to
	# inner. One field = host ns only. /proc/1/ns/pid readlink would
	# need ptrace cap, so use this instead.
	try:
		with open("/proc/self/status") as f:
			for line in f:
				if line.startswith("NSpid:"):
					return len(line.split()) <= 2
	except OSError:
		pass
	return True


PROBES = [
	("read /etc/passwd",	lambda: op_read("/etc/passwd"),		"read_passwd"),
	("read /etc/shadow",	lambda: op_read("/etc/shadow"),		"read_shadow"),
	# /proc/2/status — in pidns only PID 1 (self) exists
	("read /proc/2/status",	lambda: op_read("/proc/2/status"),	"read_proc2"),
	# write outside landlock-writable dirs
	("write /evil",		lambda: op_write("/evil"),		"write_evil"),
	# /dev/mem — CAP_SYS_RAWIO + DAC (root:kmem 0640) both gate
	("open /dev/mem",	lambda: op_open("/dev/mem"),		"open_mem"),
	("socket RAW ICMP",	op_sock_raw,				"socket_raw"),
	("connect 8.8.8.8:53",	op_connect,				"connect"),
	("ptrace TRACEME",	op_ptrace,				"ptrace_traceme"),
	("mount tmpfs /tmp",	op_mount,				"mount_tmpfs"),
]

results = []

for name, fn, key in PROBES:
	try:
		fn()
		results.append((name, True, None, "-"))
	except OSError as e:
		err = errtup(e)
		results.append((name, False, err, blocker_for(key, err)))

# kill(-1, SIGKILL) — signal every proc we can see.
# Self-guard: in host pidns, this nukes the user's whole session.
# full profile guarantees nested pidns; skip self-guard there.
if PROFILE != "full" and in_host_pidns():
	results.append(("kill(-1, SIGKILL)", False,
			("SKIP", "host pidns — self-guard"), "self-guard"))
else:
	try:
		op_kill_all()
		results.append(("kill(-1, SIGKILL)", True, None, "-"))
	except OSError as e:
		err = errtup(e)
		results.append(("kill(-1, SIGKILL)", False, err,
				blocker_for("kill_all", err)))

# print table: each probe tries a forbidden op; BLOCKED is the goal.
w1 = max(len(r[0]) for r in results)
print(f"{'op'.ljust(w1)}  {'result':<8}  {'errno':<16}  blocker")
print("-" * (w1 + 2 + 8 + 2 + 16 + 2 + 20))
for name, ok, err, blk in results:
	status = "ALLOWED" if ok else "BLOCKED"
	cell = f"{err[0]} ({err[1]})" if err else "-"
	print(f"{name.ljust(w1)}  {status:<8}  {cell:<16}  {blk}")

sys.exit(0)
