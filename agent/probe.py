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

results = []


def record(name, ok, err, blocker):
	results.append((name, ok, err, blocker))


def get_errno():
	e = ctypes.get_errno()
	return errno.errorcode.get(e, str(e)), os.strerror(e)


def try_read(path):
	try:
		with open(path, "rb") as f:
			f.read(64)
		return True, None
	except OSError as e:
		return False, (errno.errorcode.get(e.errno, str(e.errno)),
			       os.strerror(e.errno))


def try_write(path):
	try:
		with open(path, "wb") as f:
			f.write(b"x")
		return True, None
	except OSError as e:
		return False, (errno.errorcode.get(e.errno, str(e.errno)),
			       os.strerror(e.errno))


def blocker_for(name, err):
	if err is None:
		return "-"
	code = err[0]
	if code == "EPERM":
		return {
			"ptrace_traceme":	"seccomp",
			"unshare_newuser":	"userns/caps",
			"mount_tmpfs":		"caps/landlock",
			"kill_all":		"pidns/caps",
			"socket_raw":		"caps",
		}.get(name, "caps/lsm")
	if code == "EACCES":
		return "landlock/DAC"
	if code == "ENOENT":
		if name == "read_proc2":
			return "pid ns"
		return "mnt ns (not present)"
	if code == "EROFS":
		return "ro mount"
	if code == "EAFNOSUPPORT" or code == "ENETUNREACH":
		return "net ns"
	if code == "ENOSYS":
		return "seccomp"
	return code


# 1. read /etc/passwd
ok, err = try_read("/etc/passwd")
record("read /etc/passwd", ok, err, blocker_for("read_passwd", err))

# 2. read /etc/shadow
ok, err = try_read("/etc/shadow")
record("read /etc/shadow", ok, err, blocker_for("read_shadow", err))

# 3. read /proc/2/status — in pidns only PID 1 (self) exists
ok, err = try_read("/proc/2/status")
record("read /proc/2/status", ok, err, blocker_for("read_proc2", err))

# 4. write /evil (outside landlock-writable dirs)
ok, err = try_write("/evil")
record("write /evil", ok, err, blocker_for("write_evil", err))

# 5. open /dev/sda raw
try:
	fd = os.open("/dev/sda", os.O_RDONLY)
	os.close(fd)
	record("open /dev/sda", True, None, "-")
except OSError as e:
	err = (errno.errorcode.get(e.errno, str(e.errno)),
	       os.strerror(e.errno))
	record("open /dev/sda", False, err, blocker_for("open_sda", err))

# 6. raw ICMP socket
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
			  socket.IPPROTO_ICMP)
	s.close()
	record("socket RAW ICMP", True, None, "-")
except OSError as e:
	err = (errno.errorcode.get(e.errno, str(e.errno)),
	       os.strerror(e.errno))
	record("socket RAW ICMP", False, err, blocker_for("socket_raw", err))

# 7. TCP connect 8.8.8.8:53
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	s.settimeout(2)
	s.connect(("8.8.8.8", 53))
	s.close()
	record("connect 8.8.8.8:53", True, None, "-")
except OSError as e:
	code = errno.errorcode.get(e.errno, str(e.errno)) if e.errno \
		else "ETIMEDOUT?"
	msg = os.strerror(e.errno) if e.errno else str(e)
	err = (code, msg)
	record("connect 8.8.8.8:53", False, err,
	       blocker_for("connect", err))

# 8. ptrace(PTRACE_TRACEME)
ctypes.set_errno(0)
r = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
if r == 0:
	record("ptrace TRACEME", True, None, "-")
else:
	err = get_errno()
	record("ptrace TRACEME", False, err,
	       blocker_for("ptrace_traceme", err))

# 9. mount tmpfs on /tmp
ctypes.set_errno(0)
r = libc.mount(b"tmpfs", b"/tmp", b"tmpfs", 0, None)
if r == 0:
	record("mount tmpfs /tmp", True, None, "-")
else:
	err = get_errno()
	record("mount tmpfs /tmp", False, err,
	       blocker_for("mount_tmpfs", err))

# 10. kill(-1, SIGKILL) — signal every proc we can see.
# Self-guard: in host pid ns, this nukes the user's whole session.
# Skip the real call; still record a row so the demo column lines up.
def in_host_pidns():
	# /proc/self/status NSpid lists pid in each nested pid ns, outer
	# to inner. One field = host ns only. /proc/1/ns/pid readlink
	# would need ptrace cap, so use this instead.
	try:
		with open("/proc/self/status") as f:
			for line in f:
				if line.startswith("NSpid:"):
					return len(line.split()) <= 2
	except OSError:
		pass
	return True

in_host = in_host_pidns()
if in_host:
	record("kill(-1, SIGKILL)", False,
	       ("SKIP", "host pidns — self-guard"),
	       "self-guard")
else:
	try:
		os.kill(-1, signal.SIGKILL)
		record("kill(-1, SIGKILL)", True, None, "-")
	except OSError as e:
		err = (errno.errorcode.get(e.errno, str(e.errno)),
		       os.strerror(e.errno))
		record("kill(-1, SIGKILL)", False, err,
		       blocker_for("kill_all", err))

# print table: each probe tries a forbidden op; BLOCKED is the goal.
w1 = max(len(r[0]) for r in results)
print(f"{'op'.ljust(w1)}  {'result':<8}  {'errno':<16}  blocker")
print("-" * (w1 + 2 + 8 + 2 + 16 + 2 + 20))
for name, ok, err, blk in results:
	status = "ALLOWED" if ok else "BLOCKED"
	ecode = err[0] if err else "-"
	emsg = err[1] if err else ""
	cell = f"{ecode} ({emsg})" if err else "-"
	print(f"{name.ljust(w1)}  {status:<8}  {cell:<16}  {blk}")

sys.exit(0)
