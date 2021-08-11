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
 * DH_OPTION_ASCII_ONLY
 * DH_OPTION_PEDANTIC
 * DH_OPTION_EPSILON
 */

#ifndef DH_CUTS_H
#define DH_CUTS_H

#include <setjmp.h>
#include <stdio.h>

struct dh_branch {
	int   saved_depth;
	void *saved_jump;
};

void dh_init(FILE *outfile);

void dh_summarize(void);

void dh_push(char const *format, ...);
void dh_pop (void);

#define dh_branch(code) {                                  \
		struct dh_branch branch;                   \
		sigjmp_buf       my_jump;                  \
		int              signal;                   \
		signal = sigsetjmp(my_jump, 1);            \
		dh_branch_beg_(signal, &my_jump, &branch); \
		if (!signal) {                             \
			code                               \
		}                                          \
		dh_branch_end_(&branch);                   \
	}

#ifndef DH_OPTION_EPSILON
# define DH_OPTION_EPSILON 0.00001
#endif

#define dh_throw(format, ...) dh_throw_(__LINE__, format, __VA_ARGS__)
#define dh_assert(cond)       dh_assert_(__LINE__, cond, #cond)
#define dh_assertiq(a, b)     dh_assertiq_(__LINE__, a, b, #a "==" #b)
#define dh_assertfq(a, b)     dh_assertfq_(__LINE__, a, b, DH_OPTION_EPSILON, #a "==" #b)
#define dh_assertsq(a, b)     dh_assertsq_(__LINE__, a, b, #a "==" #b)
#define dh_asserteq(a, b, e)  dh_assertfq_(__LINE__, a, b, e, #a "==" #b)

/* internal functions that have to be visible.
 * do not call these directly. */
void dh_throw_     (int ln, char const *format, ...);
void dh_assert_    (int ln, int cond, char const *str);
void dh_assertiq_  (int ln, long long a, long long b, char const *str);
void dh_assertfq_  (int ln, double a, double b, double e, char const *str);
void dh_assertsq_  (int ln, char const *a, char const *b, char const *str);
void dh_branch_beg_(int signal, sigjmp_buf *my_jump, struct dh_branch *branch);
void dh_branch_end_(struct dh_branch *branch);

#endif

#ifdef DH_IMPLEMENT_HERE

#if DH_OPTION_ASCII_ONLY

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
#define DH_NO_LINENO       -1

enum { DH_FAIL,  DH_CRASH  };
enum { DH_THROW, DH_ASSERT };

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

static const char *
dh_name_of_signal_(int signal)
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
	if (dh_state.crash_jump != NULL) {
		if (signal == SIGFPE) {
			/* source: https://msdn.microsoft.com/en-us/library/xdkz3x12.aspx */
			/* _fpreset(); TODO */
		}
		/* signal will never be 0, so we can pass it
		 * directly to longjmp without hesitation.
		 * source: /usr/include/bits/signum-generic.h */
		siglongjmp(*dh_state.crash_jump, signal);
	} else {
		/* if there is no recovery point, we can't do anything about the signal.
		 * this situation should not arise during normal operation. */
	}
}

void
dh_init(FILE *outfile)
{
	dh_sink.file = outfile;

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
#if !DH_OPTION_PEDANTIC
	if (dh_sink.error_count != 0 || dh_sink.crash_count != 0)
#endif
	{
		fprintf(dh_sink.file,
		        DH_TEXT_LINE " %d failures, %d crashes " DH_TEXT_LINE "\n",
		        dh_sink.error_count, dh_sink.crash_count);
	}
}

void
dh_push(char const *format, ...)
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

static void
dh_print_nesting_(int depth)
{
	for (int i = 0; i < depth; ++i) {
		fputs(DH_TEXT_DOTS, dh_sink.file);
	}
	fputs(DH_TEXT_HIER, dh_sink.file);
}

static void
dh_report_(int kind, int signal, int ln, const char *msg)
{
	const char *kind_name, *signal_name;
	switch (kind) {
	case DH_FAIL:
		dh_sink.error_count++;
		kind_name = "FAIL";
		switch (signal) {
			case DH_THROW:  signal_name = "throw";  break;
			case DH_ASSERT: signal_name = "assert"; break;
		}
		break;
	case DH_CRASH:
		dh_sink.crash_count++;
		kind_name   = "CRASH";
		signal_name = dh_name_of_signal_(signal);
		break;
	}

	int depth = dh_sink.print_depth;
	while (depth < dh_state.stack_depth) {
		dh_print_nesting_(depth);
		fputs(dh_state.stack[depth], dh_sink.file);
		fputs("\n", dh_sink.file);
		depth++;
	}
	dh_sink.print_depth = dh_state.stack_depth;
	dh_print_nesting_(dh_sink.print_depth);
	fprintf(dh_sink.file, "triggered %s", signal_name);
	if (ln != DH_NO_LINENO) {
		fprintf(dh_sink.file, " in line %03d", ln);
	}
	if (msg != NULL) {
		fprintf(dh_sink.file, ": %s", msg);
	}
	fprintf(dh_sink.file, "\t\t" DH_TEXT_ARROW " %s\n", kind_name);
}

void
dh_branch_beg_(int signal, sigjmp_buf *my_jump, struct dh_branch *branch)
{
	if (signal) {
		dh_report_(DH_CRASH, signal, DH_NO_LINENO, NULL);
	} else {
		branch->saved_depth = dh_state.stack_depth;
		branch->saved_jump  = dh_state.crash_jump;
		dh_state.crash_jump = my_jump;
	}
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
dh_throw_(int ln, char const *format, ...)
{
	char *str = malloc(DH_MAX_NAME_LENGTH);

	va_list va;
	va_start(va, format);
	vsnprintf(str, DH_MAX_NAME_LENGTH, format, va);
	va_end(va);

	dh_report_(DH_FAIL, DH_THROW, ln, str);

	free(str);
}

void
dh_assert_(int ln, int cond, char const *str)
{
	if (!cond) dh_report_(DH_FAIL, DH_ASSERT, ln, str);
}

void
dh_assertiq_(int ln, long long a, long long b, char const *str)
{
	dh_assert_(ln, a == b, str);
}

void
dh_assertfq_(int ln, double a, double b, double e, char const *str)
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
	dh_assert_(ln, d <= e, str);
}

void
dh_assertsq_(int ln, char const *a, char const *b, char const *str)
{
	dh_assert_(ln, strcmp(a, b) != 0, str);
}

#endif /* DH_IMPLEMENT_HERE */
