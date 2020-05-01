/* dh_cuts.h - Dynamic Hierarchy C Unit Testing System
 * 
 * ISC License
 *
 * Copyright (c) 2018, 2019, 2020 Thomas Oltmann
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
 *
 * You can find an up-to-date copy of this file under
 * https://www.github.com/tomolt/dh_cuts
 */

/*
 * DH_OPTION_ASCII_ONLY
 * DH_OPTION_PEDANTIC
 * DH_OPTION_EPSILON
 */

#ifndef DH_CUTS_H
#define DH_CUTS_H

#include <setjmp.h>
#include <stdio.h>

struct dh_branch_saves_ {
	int saved_depth;
	void *saved_jump;
};

void dh_init(FILE *pipe);

void dh_summarize(void);

void dh_push(char const *format, ...);
void dh_pop(void);

#define dh_branch(code) { \
		struct dh_branch_saves_ s; \
		sigjmp_buf my_jmp; \
		int signal = sigsetjmp(my_jmp, 1); \
		dh_branch_beg_(signal, &my_jmp, &s); \
		if (!signal) { \
			code \
		} \
		dh_branch_end_(&s); \
	}

#ifndef DH_OPTION_EPSILON
# define DH_OPTION_EPSILON 0.00001
#endif

#define dh_throw(format, ...) dh_throw_(__LINE__, format, __VA_ARGS__)
#define dh_assert(cond) dh_assert_(__LINE__, cond, #cond)
#define dh_assertiq(a, b) dh_assertiq_(__LINE__, a, b, #a "==" #b)
#define dh_assertfq(a, b) dh_assertfq_(__LINE__, a, b, DH_OPTION_EPSILON, #a "==" #b)
#define dh_assertsq(a, b) dh_assertsq_(__LINE__, a, b, #a "==" #b)
#define dh_asserteq(a, b, e) dh_assertfq_(__LINE__, a, b, e, #a "==" #b)

/* internal functions that have to be visible. */
/* do not call these directly. */
void dh_throw_(int ln, char const *format, ...);
void dh_assert_(int ln, int cond, char const *str);
void dh_assertiq_(int ln, long long a, long long b, char const *str);
void dh_assertfq_(int ln, double a, double b, double e, char const *str);
void dh_assertsq_(int ln, char const *a, char const *b, char const *str);
void dh_branch_beg_(int signal, sigjmp_buf *my_jmp, struct dh_branch_saves_ *s);
void dh_branch_end_(struct dh_branch_saves_ *s);

#endif

#ifdef DH_IMPLEMENT_HERE

#if DH_OPTION_ASCII_ONLY

# define TEXT_DOTS  ".."
# define TEXT_HIER  "\\ "
# define TEXT_ARROW "<-"
# define TEXT_LINE  "--"

#else

# define TEXT_DOTS  "\u2024\u2024"
# define TEXT_HIER  "\u2514 "
# define TEXT_ARROW "\u2190"
# define TEXT_LINE  "\u2500\u2500"

#endif

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <signal.h>

#define MAX_NAME_LENGTH 200
#define MAX_DEPTH 50

enum { FAIL, CRASH };
enum { THROW, ASSERT };

#define NO_LINENO -1

static int const dh_caught_signals[] = { SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGSYS, SIGPIPE, 0 };

struct dh_this {
	sigjmp_buf *crash_jump;
	int stack_depth;
	char const *stack[MAX_DEPTH];
};

struct dh_sink {
	FILE *pipe;
	int print_depth;
	int error_count;
	int crash_count;
};

static struct dh_this dh_this;
static struct dh_sink dh_sink;

static char const *dh_name_of_signal_(int signal)
{
	switch (signal) {
		case SIGILL:  return "illegal instruction (SIGILL)";  break;
		case SIGFPE:  return "arithmetic exception (SIGFPE)";  break;
		case SIGSEGV: return "segmentation fault (SIGSEGV)"; break;
		case SIGBUS:  return "bus error (SIGBUS)";  break;
		case SIGSYS:  return "illegal system call (SIGSYS)";  break;
		case SIGPIPE: return "broken pipe (SIGPIPE)"; break;
		/* the default path should never be taken, */
		/* as only the above signals are actually caught. */
		default: return "unknown signal"; break;
	}
}

static void dh_signal_handler_(int signal)
{
	if (dh_this.crash_jump != NULL) {
		if (signal == SIGFPE) {
			/* source: https://msdn.microsoft.com/en-us/library/xdkz3x12.aspx */
			/* _fpreset(); TODO */
		}
		/* signal will never be 0, so we can pass it */
		/* directly to longjmp without hesitation. */
		/* source: /usr/include/bits/signum-generic.h */
		siglongjmp(*dh_this.crash_jump, signal);
	} else {
		/* if there is no recovery point, we can't do anything about the signal. */
		/* this situation should not arise during normal operation. */
	}
}

void dh_init(FILE *pipe)
{
	dh_sink.pipe = pipe;
	struct sigaction action;
	memset(&action, 0, sizeof(struct sigaction));
	action.sa_handler = dh_signal_handler_;
	sigemptyset(&action.sa_mask);
	/* TODO error checking */
	int i;
	for (i = 0; dh_caught_signals[i] != 0; ++i) {
		sigaction(dh_caught_signals[i], &action, NULL);
	}
}

void dh_summarize(void)
{
#if !DH_OPTION_PEDANTIC
	if (dh_sink.error_count != 0 || dh_sink.crash_count != 0)
#endif
	{
		fprintf(dh_sink.pipe,
			TEXT_LINE " %d failures, %d crashes " TEXT_LINE "\n",
			dh_sink.error_count, dh_sink.crash_count);
	}
}

void dh_push(char const *format, ...)
{
	char *str = malloc(MAX_NAME_LENGTH);

	va_list va;
	va_start(va, format);
	vsnprintf(str, MAX_NAME_LENGTH, format, va);
	va_end(va);

	dh_this.stack[dh_this.stack_depth++] = str;
}

void dh_pop(void)
{
	free((char *)dh_this.stack[--dh_this.stack_depth]);
	if (dh_sink.print_depth > dh_this.stack_depth)
		dh_sink.print_depth = dh_this.stack_depth;
}

static void dh_print_nesting_(int depth)
{
	int i;
	for (i = 0; i < depth; ++i)
		fputs(TEXT_DOTS, dh_sink.pipe);
	fputs(TEXT_HIER, dh_sink.pipe);
}

static void dh_report_(int kind, int signal, int ln, char const *msg)
{
	char const *kind_name, *signal_name;
	switch (kind) {
		case FAIL:
			++dh_sink.error_count;
			kind_name = "FAIL";
			switch (signal) {
				case THROW: signal_name = "throw"; break;
				case ASSERT: signal_name = "assert"; break;
			}
			break;
		case CRASH:
			++dh_sink.crash_count;
			kind_name = "CRASH";
			signal_name = dh_name_of_signal_(signal);
			break;
	}

	int depth = dh_sink.print_depth;
	while (depth < dh_this.stack_depth) {
		dh_print_nesting_(depth);
		fputs(dh_this.stack[depth], dh_sink.pipe);
		fputs("\n", dh_sink.pipe);
		++depth;
	}
	dh_sink.print_depth = dh_this.stack_depth;
	dh_print_nesting_(dh_sink.print_depth);
	fprintf(dh_sink.pipe, "triggered %s", signal_name);
	if (ln != NO_LINENO) {
		fprintf(dh_sink.pipe, " in line %03d", ln);
	}
	if (msg != NULL) {
		fprintf(dh_sink.pipe, ": %s", msg);
	}
	fprintf(dh_sink.pipe, "\t\t" TEXT_ARROW " %s\n", kind_name);
}

void dh_branch_beg_(int signal, sigjmp_buf *my_jmp, struct dh_branch_saves_ *s)
{
	if (signal) {
		dh_report_(CRASH, signal, NO_LINENO, NULL);
	} else {
		*s = (struct dh_branch_saves_){dh_this.stack_depth, (void *)dh_this.crash_jump};
		dh_this.crash_jump = my_jmp;
	}
}

void dh_branch_end_(struct dh_branch_saves_ *s)
{
	dh_this.crash_jump = s->saved_jump;
	/* restore the stack in case of a crash. */
	/* also helps recovering from missing dh_pop()'s, */
	/* though you *really* shouldn't rely on this behaviour. */
	while (dh_this.stack_depth > s->saved_depth)
		dh_pop();
}

void dh_throw_(int ln, char const *format, ...)
{
	char *str = malloc(MAX_NAME_LENGTH);

	va_list va;
	va_start(va, format);
	vsnprintf(str, MAX_NAME_LENGTH, format, va);
	va_end(va);

	dh_report_(FAIL, THROW, ln, str);

	free(str);
}

void dh_assert_(int ln, int cond, char const *str)
{
	if (!cond) dh_report_(FAIL, ASSERT, ln, str);
}

void dh_assertiq_(int ln, long long a, long long b, char const *str)
{
	dh_assert_(ln, a == b, str);
}

void dh_assertfq_(int ln, double a, double b, double e, char const *str)
{
	/* because of the rounding behaviour of floating-point numbers, two expressions */
	/* that mathematically should evaluate to the same value can actually differ in */
	/* the lower digits. For user convenience dh_assertfq() therefore allow a small */
	/* difference between a and b. */
	/* If the user wants to use another epsilon value, he can either define his own */
	/* epsilon via DH_OPTION_EPSILON or write his own macro wrapping dh_assertfq_(). */
	/* If exact comparison is wanted, one can always use dh_assert(a == b). */
	double d = a - b;
	if (d < 0.0) d = -d; /* same as: d = fabsf(d); */
	dh_assert_(ln, d <= e, str);
}

void dh_assertsq_(int ln, char const *a, char const *b, char const *str)
{
	dh_assert_(ln, strcmp(a, b) != 0, str);
}

#endif
