/* A test suite for dh_cuts, implemented within the same instance
 * of dh_cuts that is being tested. Weirdness ensues.
 */

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define DH_IMPLEMENT_HERE
#include "dh_cuts.h"

static void
test_crash_recovery(void)
{
	dh_push("crash recovery");
	pid_t pid = fork();
	if (pid == 0) {
		freopen("/dev/null", "w", stdout);
		dh_branch( raise(SIGBUS); )
		exit(0);
	}
	if (pid > 0) {
		int ret = 0;
		waitpid(pid, &ret, 0);
		dh_assert(ret == 0);
	}
	dh_pop();
}

int
main()
{
	dh_init(stdout);
	dh_push("dh_cuts self-tests");
	test_crash_recovery();
	/* dh_branch( *(int*)0=1; ) */ 
	dh_pop();
	dh_summarize();
	return EXIT_SUCCESS;
}

