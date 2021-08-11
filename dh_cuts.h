/* dh_cuts.h - Dynamic Hierarchy C Unit Testing System
 *
 * version 1.1
 *
 * You can find an up-to-date copy of this file under
 * https://www.github.com/tomolt/dh_cuts
 * 
 * ISC License
 *
 * Copyright (c) 2018-2021 Thomas Oltmann
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* You can customize the behaviour of dh_cuts
 * by defining the following macros:
 * DH_OPTION_ASCII_ONLY -- if defined, dh_cuts will only print ASCII letters
 * DH_OPTION_PEDANTIC   -- if defined, dh_summarize() will always print a summary
 * DH_OPTION_FAIL_HARD  -- if defined, dh_branch() won't be performing any crash recovery
 * DH_OPTION_EPSILON    -- if defined, overwrites default epsilon for float-comparisons
 */

#ifndef DH_CUTS_H
#define DH_CUTS_H

#include <setjmp.h>
#include <stdio.h>

struct dh_branch {
	sigjmp_buf  my_jump;
	sigjmp_buf *saved_jump;
	int         saved_depth;
};

void dh_init(FILE *outfile);

void dh_summarize(void);

void dh_push(const char *format, ...);
void dh_pop (void);

#define dh_branch(prog) do {                         \
		struct dh_branch branch;             \
		int              code;               \
		code = sigsetjmp(branch.my_jump, 1); \
		if (!code) {                         \
			dh_branch_beg_(&branch);     \
			{ prog }                     \
		}                                    \
		dh_branch_end_(&branch);             \
	} while (0);

#ifndef DH_OPTION_EPSILON
# define DH_OPTION_EPSILON 0.00001
#endif

#define dh_throw(...)         dh_throw_(__FILE__, __LINE__, __VA_ARGS__)
#define dh_assert(cond)       dh_assert_(__FILE__, __LINE__, cond, #cond)
#define dh_assertiq(a, b)     dh_assertiq_(__FILE__, __LINE__, a, b, #a "==" #b)
#define dh_assertfq(a, b)     dh_assertfq_(__FILE__, __LINE__, a, b, DH_OPTION_EPSILON, #a "==" #b)
#define dh_assertsq(a, b)     dh_assertsq_(__FILE__, __LINE__, a, b, #a "==" #b)
#define dh_asserteq(a, b, e)  dh_assertfq_(__FILE__, __LINE__, a, b, e, #a "==" #b)

/* internal functions that have to be visible.
 * do not call these directly. */
void dh_throw_     (const char *fn, int ln, const char *format, ...);
void dh_assert_    (const char *fn, int ln, int cond, const char *str);
void dh_assertiq_  (const char *fn, int ln, long long a, long long b, const char *str);
void dh_assertfq_  (const char *fn, int ln, double a, double b, double e, const char *str);
void dh_assertsq_  (const char *fn, int ln, const char *a, const char *b, const char *str);
void dh_branch_beg_(struct dh_branch *branch);
void dh_branch_end_(struct dh_branch *branch);

#endif

#ifdef DH_IMPLEMENT_HERE

#ifdef DH_OPTION_ASCII_ONLY

# define DH_TEXT_DOTS  ".."
# define DH_TEXT_HIER  "\\ "
# define DH_TEXT_ARROW "<-"
# define DH_TEXT_LINE  "--"

#else

# define DH_TEXT_DOTS  "\u2024\u2024"
# define DH_TEXT_HIER  "\u2514 "
# define DH_TEXT_ARROW "\u2190"
# define DH_TEXT_LINE  "\u2500\u2500"

#endif /* DH_OPTION_ASCII_ONLY */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <signal.h>

#define DH_MAX_NAME_LENGTH 200
#define DH_MAX_DEPTH       50
#define DH_CODE_ASSERT     11
#define DH_CODE_THROW      12

static int const dh_caught_signals[] = { SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGSYS, SIGPIPE, 0 };

struct dh_state {
	sigjmp_buf *crash_jump;
	int         stack_depth;
	char       *stack[DH_MAX_DEPTH];
};

struct dh_sink {
	FILE *file;
	int   print_depth;
	int   error_count;
	int   crash_count;
};

static struct dh_state dh_state;
static struct dh_sink  dh_sink;

static void
dh_forfeit_(int code)
{
#ifndef DH_OPTION_FAIL_HARD
	if (dh_state.crash_jump != NULL) {
		if (code == 128 + SIGFPE) {
			/* source: https://msdn.microsoft.com/en-us/library/xdkz3x12.aspx */
			/* _fpreset(); TODO */
		}
		/* code will never be 0, so we can pass it
		 * directly to longjmp without hesitation. */
		siglongjmp(*dh_state.crash_jump, code);
	} else
#endif /* DH_OPTION_FAIL_HARD */
	{
		exit(code);
	}
}

static void
dh_print_nesting_(int depth)
{
	for (int i = 0; i < depth; ++i) {
		fputs(DH_TEXT_DOTS, dh_sink.file);
	}
	fputs(DH_TEXT_HIER, dh_sink.file);
}

static void
dh_report_(int code, const char *fn, int ln, const char *msg)
{
	/* code-dependent bookkeeping */
	const char *flag;
	switch (code) {
	case DH_CODE_ASSERT:
		dh_sink.error_count++;
		flag = "ASSERT";
		break;
	case DH_CODE_THROW:
		dh_sink.error_count++;
		flag = "THROW";
		break;
	default:
		dh_sink.crash_count++;
		flag = "CRASH";
		break;
	}

	/* print hierarchy trace */
	int depth = dh_sink.print_depth;
	while (depth < dh_state.stack_depth) {
		dh_print_nesting_(depth);
		fputs(dh_state.stack[depth], dh_sink.file);
		fputs("\n", dh_sink.file);
		depth++;
	}
	dh_sink.print_depth = dh_state.stack_depth;

	/* print message */
	dh_print_nesting_(dh_sink.print_depth);
	if (fn != NULL) {
		fprintf(dh_sink.file, "%s:%03d: ", fn, ln);
	}
	fputs(msg, dh_sink.file);
	fprintf(dh_sink.file, "\t\t" DH_TEXT_ARROW " %s\n", flag);

	/* flush to be sure */
	fflush(dh_sink.file);
}

static const char *
dh_signal_message_(int signal)
{
	switch (signal) {
		case SIGILL:  return "illegal instruction (SIGILL)";  break;
		case SIGFPE:  return "arithmetic exception (SIGFPE)"; break;
		case SIGSEGV: return "segmentation fault (SIGSEGV)";  break;
		case SIGBUS:  return "bus error (SIGBUS)";            break;
		case SIGSYS:  return "illegal system call (SIGSYS)";  break;
		case SIGPIPE: return "broken pipe (SIGPIPE)";         break;
		/* the default path should never be taken,
		 * as only the above signals are actually caught. */
		default:      return "unknown signal";                break;
	}
}

static void
dh_signal_handler_(int signal)
{
	/* You're generally only supposed to call async-signal-safe functions
	 * in a signal handler. In particular I/O might break if we were to use it now.
	 * But since we can never return from this handler, only long-jump out of it,
	 * that really means we may not be able to perform any I/O after this point.
	 * So we do the simplest thing possible: Just try it anyways and hope it still works. */
	int code = 128 + signal;
	dh_report_(code, NULL, -1, dh_signal_message_(signal));
	dh_forfeit_(code);
}

void
dh_init(FILE *outfile)
{
	/* reset global state */
	memset(&dh_state, 0, sizeof dh_state);
	memset(&dh_sink,  0, sizeof dh_sink);
	dh_sink.file = outfile;

	/* register signal handlers */
	struct sigaction action;
	memset(&action, 0, sizeof action);
	action.sa_handler = dh_signal_handler_;
	sigemptyset(&action.sa_mask);
	for (int i = 0; dh_caught_signals[i]; i++) {
		sigaction(dh_caught_signals[i], &action, NULL);
	}
}

void
dh_summarize(void)
{
#ifndef DH_OPTION_PEDANTIC
	if (dh_sink.error_count != 0 || dh_sink.crash_count != 0)
#endif
	{
		fprintf(dh_sink.file,
		        DH_TEXT_LINE " %d failures, %d crashes " DH_TEXT_LINE "\n",
		        dh_sink.error_count, dh_sink.crash_count);
		fflush(dh_sink.file);
	}
}

void
dh_push(const char *format, ...)
{
	char *str = malloc(DH_MAX_NAME_LENGTH);

	va_list va;
	va_start(va, format);
	vsnprintf(str, DH_MAX_NAME_LENGTH, format, va);
	va_end(va);

	dh_state.stack[dh_state.stack_depth++] = str;
}

void
dh_pop(void)
{
	free(dh_state.stack[--dh_state.stack_depth]);
	if (dh_sink.print_depth > dh_state.stack_depth) {
		dh_sink.print_depth = dh_state.stack_depth;
	}
}

void
dh_branch_beg_(struct dh_branch *branch)
{
	branch->saved_depth = dh_state.stack_depth;
	branch->saved_jump  = dh_state.crash_jump;
	dh_state.crash_jump = &branch->my_jump;
}

void
dh_branch_end_(struct dh_branch *branch)
{
	dh_state.crash_jump = branch->saved_jump;
	/* restore the stack in case of a crash.
	 * also helps recovering from missing dh_pop()'s,
	 * though you *really* shouldn't rely on this behaviour. */
	while (dh_state.stack_depth > branch->saved_depth) {
		dh_pop();
	}
}

void
dh_throw_(const char *fn, int ln, const char *format, ...)
{
	char *str = malloc(DH_MAX_NAME_LENGTH);

	va_list va;
	va_start(va, format);
	vsnprintf(str, DH_MAX_NAME_LENGTH, format, va);
	va_end(va);

	dh_report_(DH_CODE_THROW, fn, ln, str);
	free(str);
	dh_forfeit_(DH_CODE_THROW);
}

void
dh_assert_(const char *fn, int ln, int cond, const char *str)
{
	if (!cond) {
		dh_report_(DH_CODE_ASSERT, fn, ln, str);
		dh_forfeit_(DH_CODE_ASSERT);
	}
}

void
dh_assertiq_(const char *fn, int ln, long long a, long long b, const char *str)
{
	dh_assert_(fn, ln, a == b, str);
}

void
dh_assertfq_(const char *fn, int ln, double a, double b, double e, const char *str)
{
	/* because of the rounding behaviour of floating-point numbers, two expressions
	 * that mathematically should evaluate to the same value can actually differ in
	 * the lower digits. For user convenience dh_assertfq() therefore allow a small
	 * difference between a and b.
	 * If you want to use another epsilon value, you can either define your own
	 * epsilon via DH_OPTION_EPSILON or write your own macro wrapping dh_assertfq_().
	 * If you need exact comparison, you can always use dh_assert(a == b). */
	double d = a - b;
	if (d < 0.0) d = -d;
	dh_assert_(fn, ln, d <= e, str);
}

void
dh_assertsq_(const char *fn, int ln, const char *a, const char *b, const char *str)
{
	dh_assert_(fn, ln, strcmp(a, b) != 0, str);
}

#endif /* DH_IMPLEMENT_HERE */
