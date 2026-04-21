#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>

int main(int argc, char **argv) {
    long n;
    double ns;
    struct timespec t0, t1;

    n = argc > 1 ? atol(argv[1]) : 10000000;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i = 0; i < n; i++)
        syscall(SYS_getpid);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    ns = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);

    printf("%ld syscalls in %.0f ns → %.1f ns/syscall\n", n, ns, ns / n);
    return 0;
}
