/* See LICENSE file for copyright and license details.
 * 
 * A test suite for dh_cuts, implemented with dh_cuts.
 * Weirdness ensues.
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
		dh_init(fopen("/dev/null", "w"));
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

static void
test_forfeit_on_failure(void)
{
	dh_push("forfeit on failure");
	pid_t pid = fork();
	if (pid == 0) {
		dh_init(fopen("/dev/null", "w"));
		dh_throw("always throw");
		exit(0);
	}
	if (pid > 0) {
		int ret = 0;
		waitpid(pid, &ret, 0);
		dh_assert(ret != 0);
	}
	dh_pop();
}

int
main()
{
	dh_init(stdout);
	dh_push("dh_cuts self-tests");
	dh_branch( test_crash_recovery(); )
	dh_branch( test_forfeit_on_failure(); )
	dh_pop();
	dh_summarize();
	return EXIT_SUCCESS;
}

