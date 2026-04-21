# Agent Isolation Sandbox

Sandbox harness and probe that isolate an untrusted agent. Four progressive profiles: none, namespaces, +landlock, +caps/seccomp. Script runs the probe across all four and records which primitive blocks which operation. Results show what each primitive contributes, and why namespaces alone are not a sandbox.

## Profiles
- **none** - baseline - no isolation
- **ns_only** - namespaces + pivot_root into composed tmpfs
- **landlock** - + unprivileged filesystem allow-list
- **full** - + capability drop + seccomp-bpf syscall filter

## Run
./run.sh

## Results: Isolation Matrix

```
=== profile: none ===
op                   result    errno             blocker
---------------------------------------------------------------------
read /etc/passwd     ALLOWED   -                 -
read /etc/shadow     BLOCKED   EACCES (Permission denied)  DAC
read /proc/2/status  ALLOWED   -                 -
write /evil          BLOCKED   EACCES (Permission denied)  DAC
open /dev/mem        BLOCKED   EACCES (Permission denied)  DAC
socket RAW ICMP      BLOCKED   EPERM (Operation not permitted)  caps
connect 8.8.8.8:53   ALLOWED   -                 -
ptrace TRACEME       ALLOWED   -                 -
mount tmpfs /tmp     BLOCKED   EPERM (Operation not permitted)  caps
kill(-1, SIGKILL)    BLOCKED   SKIP (host pidns — self-guard)  self-guard

=== profile: ns_only ===
op                   result    errno             blocker
---------------------------------------------------------------------
read /etc/passwd     BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
read /etc/shadow     BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
read /proc/2/status  BLOCKED   ENOENT (No such file or directory)  pid ns
write /evil          ALLOWED   -                 -
open /dev/mem        BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
socket RAW ICMP      ALLOWED   -                 -
connect 8.8.8.8:53   BLOCKED   ENETUNREACH (Network is unreachable)  net ns
ptrace TRACEME       ALLOWED   -                 -
mount tmpfs /tmp     ALLOWED   -                 -
kill(-1, SIGKILL)    BLOCKED   SKIP (host pidns — self-guard)  self-guard

=== profile: landlock ===
op                   result    errno             blocker
---------------------------------------------------------------------
read /etc/passwd     BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
read /etc/shadow     BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
read /proc/2/status  BLOCKED   ENOENT (No such file or directory)  pid ns
write /evil          BLOCKED   EACCES (Permission denied)  landlock
open /dev/mem        BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
socket RAW ICMP      ALLOWED   -                 -
connect 8.8.8.8:53   BLOCKED   ENETUNREACH (Network is unreachable)  net ns
ptrace TRACEME       ALLOWED   -                 -
mount tmpfs /tmp     BLOCKED   EPERM (Operation not permitted)  landlock
kill(-1, SIGKILL)    BLOCKED   SKIP (host pidns — self-guard)  self-guard

=== profile: full ===
op                   result    errno             blocker
---------------------------------------------------------------------
read /etc/passwd     BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
read /etc/shadow     BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
read /proc/2/status  BLOCKED   ENOENT (No such file or directory)  pid ns
write /evil          BLOCKED   EACCES (Permission denied)  landlock
open /dev/mem        BLOCKED   ENOENT (No such file or directory)  mnt ns (not present)
socket RAW ICMP      BLOCKED   EPERM (Operation not permitted)  caps
connect 8.8.8.8:53   BLOCKED   ENETUNREACH (Network is unreachable)  net ns
ptrace TRACEME       BLOCKED   EPERM (Operation not permitted)  seccomp
mount tmpfs /tmp     BLOCKED   EPERM (Operation not permitted)  seccomp
kill(-1, SIGKILL)    BLOCKED   ESRCH (No such process)  pid ns (no other procs)
```

## Overhead
```
profile        startup_ms   ns_per_syscall   delta
---------------------------------------------------
none                0.585             81.5      —
ns_only             1.101             81.5      +0
landlock            1.119             80.2      +0
full                1.151             97.4     +16   (seccomp BPF)
```

## Limitations
Linux kernel remains in the trust boundary. Workloads with more strict requirements need user-space syscall interception (gVisor), per-agent VMs (Firecracker), or a microkernel (seL4). 
