/* Executor state-commit tests: only fatal setup failures may stop executor
 * apply from recording the desired state as applied. */
#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "internal.h"

static int fail(const char *what)
{
    printf("executor_test: FAIL (%s)\n", what);
    return 1;
}

int main(void)
{
    if (executor_action_is_fatal(-ENOENT, false))
        return fail("nonfatal action failure");
    if (executor_action_is_fatal(0, true))
        return fail("successful action");
    if (!executor_action_is_fatal(-ENOENT, true))
        return fail("fatal action failure");

    printf("executor_test: OK\n");
    return 0;
}
