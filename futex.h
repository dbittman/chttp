#pragma once
#include <linux/futex.h>
#include <sys/syscall.h>

/* we have to use syscall directly, there's no wrapper */
static int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

