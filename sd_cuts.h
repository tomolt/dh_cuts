/* sd_cuts.h - Somewhat Different C Unit Testing System
 * 
 * MIT License
 *
 * Copyright (c) 2018, 2019 Thomas Oltmann
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * This file was originally distributed as part of Thomas Oltmann's personal
 * tiny library collection. (https://www.github.com/tomolt/tiny-library-collection)
 */

/*
 * SD_OPTION_ASCII_ONLY
 * SD_OPTION_PEDANTIC
 * SD_OPTION_EPSILON
 */

#ifndef SD_CUTS_H
#define SD_CUTS_H

#include <setjmp.h>
#include <stdio.h>

struct sd_branch_saves_ {
	int saved_depth;
	void *saved_jump;
};

void sd_init(FILE *pipe);
int  sd_ismtsafe(void);

void sd_summarize(void);

void sd_push(char const *format, ...);
void sd_pop(void);

#define sd_branch(code) { \
		struct sd_branch_saves_ s; \
		sigjmp_buf my_jmp; \
		int signal = sigsetjmp(my_jmp, 1); \
		sd_branch_beg_(signal, &my_jmp, &s); \
		if (!signal) { \
			code \
		} \
		sd_branch_end_(&s); \
	}

#ifndef SD_OPTION_EPSILON
# define SD_OPTION_EPSILON 0.00001
#endif

#define sd_throw(format, ...) sd_throw_(__LINE__, format, __VA_ARGS__)
#define sd_assert(cond) sd_assert_(__LINE__, cond, #cond)
#define sd_assertiq(a, b) sd_assertiq_(__LINE__, a, b, #a "==" #b)
#define sd_assertfq(a, b) sd_assertfq_(__LINE__, a, b, SD_OPTION_EPSILON, #a "==" #b)
#define sd_assertsq(a, b) sd_assertsq_(__LINE__, a, b, #a "==" #b)
#define sd_asserteq(a, b, e) sd_assertfq_(__LINE__, a, b, e, #a "==" #b)

/* internal functions that have to be visible. */
/* do not call these directly. */
void sd_throw_(int ln, char const *format, ...);
void sd_assert_(int ln, int cond, char const *str);
void sd_assertiq_(int ln, long long a, long long b, char const *str);
void sd_assertfq_(int ln, double a, double b, double e, char const *str);
void sd_assertsq_(int ln, char const *a, char const *b, char const *str);
void sd_branch_beg_(int signal, sigjmp_buf *my_jmp, struct sd_branch_saves_ *s);
void sd_branch_end_(struct sd_branch_saves_ *s);

#endif

#ifdef SD_IMPLEMENT_HERE

#if SD_OPTION_ASCII_ONLY

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

#if (__STDC_VERSION__ >= 201112L) && (!defined __STDC_NO_THREADS__)
# define HAVE_THREADS 1
#else
# define HAVE_THREADS 0
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <signal.h>
#include <float.h>

#if HAVE_THREADS
# include <threads.h>
#endif

#define MAX_NAME_LENGTH 200
#define MAX_DEPTH 50

enum { FAIL, CRASH };
enum { THROW, ASSERT };

#define NO_LINENO -1

static int const caught_signals[] = { SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGSYS, SIGPIPE, 0 };

struct sd_this {
	sigjmp_buf *crash_jump;
	int stack_depth;
	char const *stack[MAX_DEPTH];
};

struct sd_sink {
	FILE *pipe;
	int print_depth;
	int error_count;
	int crash_count;
#if HAVE_THREADS
	mtx_t mutex;
#endif
};

static struct sd_this sd_this;
static struct sd_sink sd_sink;

static char const *name_of_signal(int signal)
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

static void signal_handler(int signal)
{
	/* TODO make thread-safe */
	if (sd_this.crash_jump != NULL) {
		if (signal == SIGFPE) {
			/* source: https://msdn.microsoft.com/en-us/library/xdkz3x12.aspx */
			/* _fpreset(); TODO */
		}
		/* signal will never be 0, so we can pass it */
		/* directly to longjmp without hesitation. */
		/* source: /usr/include/bits/signum-generic.h */
		siglongjmp(*sd_this.crash_jump, signal);
	} else {
		/* if there is no recovery point, we can't do anything about the signal. */
		/* this situation should not arise during normal operation. */
	}
}

void sd_init(FILE *pipe)
{
#if HAVE_THREADS
	mtx_init(&sd_sink.mutex, mtx_plain);
#endif
	sd_sink.pipe = pipe;
	struct sigaction action;
	memset(&action, 0, sizeof(struct sigaction));
	action.sa_handler = signal_handler;
	sigemptyset(&action.sa_mask);
	/* TODO error checking */
	int i;
	for (i = 0; caught_signals[i] != 0; ++i) {
		sigaction(caught_signals[i], &action, NULL);
	}
}

int sd_ismtsafe(void)
{
	return HAVE_THREADS;
}

void sd_summarize(void)
{
#if HAVE_THREADS
	mtx_lock(&sd_sink.mutex);
#endif

#if !SD_OPTION_PEDANTIC
	if (sd_sink.error_count != 0 || sd_sink.crash_count != 0)
#endif
	{
		fprintf(sd_sink.pipe,
			TEXT_LINE " %d failures, %d crashes " TEXT_LINE "\n",
			sd_sink.error_count, sd_sink.crash_count);
	}

#if HAVE_THREADS
	mtx_unlock(&sd_sink.mutex);
#endif
}

void sd_push(char const *format, ...)
{
	char *str = malloc(MAX_NAME_LENGTH);

	va_list va;
	va_start(va, format);
	vsnprintf(str, MAX_NAME_LENGTH, format, va);
	va_end(va);

	sd_this.stack[sd_this.stack_depth++] = str;
}

void sd_pop(void)
{
	free((char *)sd_this.stack[--sd_this.stack_depth]);
	if (sd_sink.print_depth > sd_this.stack_depth)
		sd_sink.print_depth = sd_this.stack_depth;
}

static void print_nesting(int depth)
{
	int i;
	for (i = 0; i < depth; ++i)
		fputs(TEXT_DOTS, sd_sink.pipe);
	fputs(TEXT_HIER, sd_sink.pipe);
}

static void report(int kind, int signal, int ln, char const *msg)
{
#if HAVE_THREADS
	mtx_lock(&sd_sink.mutex);
#endif

	char const *kind_name, *signal_name;
	switch (kind) {
		case FAIL:
			++sd_sink.error_count;
			kind_name = "FAIL";
			switch (signal) {
				case THROW: signal_name = "throw"; break;
				case ASSERT: signal_name = "assert"; break;
			}
			break;
		case CRASH:
			++sd_sink.crash_count;
			kind_name = "CRASH";
			signal_name = name_of_signal(signal);
			break;
	}

	int depth = sd_sink.print_depth;
	while (depth < sd_this.stack_depth) {
		print_nesting(depth);
		fputs(sd_this.stack[depth], sd_sink.pipe);
		fputs("\n", sd_sink.pipe);
		++depth;
	}
	sd_sink.print_depth = sd_this.stack_depth;
	print_nesting(sd_sink.print_depth);
	fprintf(sd_sink.pipe, "triggered %s", signal_name);
	if (ln != NO_LINENO) {
		fprintf(sd_sink.pipe, " in line %03d", ln);
	}
	if (msg != NULL) {
		fprintf(sd_sink.pipe, ": %s", msg);
	}
	fprintf(sd_sink.pipe, "\t\t" TEXT_ARROW " %s\n", kind_name);

#if HAVE_THREADS
	mtx_unlock(&sd_sink.mutex);
#endif
}

void sd_branch_beg_(int signal, sigjmp_buf *my_jmp, struct sd_branch_saves_ *s)
{
	if (signal) {
		report(CRASH, signal, NO_LINENO, NULL);
	} else {
		*s = (struct sd_branch_saves_){sd_this.stack_depth, (void *)sd_this.crash_jump};
		sd_this.crash_jump = my_jmp;
	}
}

void sd_branch_end_(struct sd_branch_saves_ *s)
{
	sd_this.crash_jump = s->saved_jump;
	/* restore the stack in case of a crash. */
	/* also helps recovering from missing sd_pop()'s, */
	/* though you *really* shouldn't rely on this behaviour. */
	while (sd_this.stack_depth > s->saved_depth)
		sd_pop();
}

void sd_throw_(int ln, char const *format, ...)
{
	char *str = malloc(MAX_NAME_LENGTH);

	va_list va;
	va_start(va, format);
	vsnprintf(str, MAX_NAME_LENGTH, format, va);
	va_end(va);

	report(FAIL, THROW, ln, str);

	free(str);
}

void sd_assert_(int ln, int cond, char const *str)
{
	if (!cond) report(FAIL, ASSERT, ln, str);
}

void sd_assertiq_(int ln, long long a, long long b, char const *str)
{
	sd_assert_(ln, a == b, str);
}

void sd_assertfq_(int ln, double a, double b, double e, char const *str)
{
	/* because of the rounding behaviour of floating-point numbers, two expressions */
	/* that mathematically should evaluate to the same value can actually differ in */
	/* the lower digits. For user convenience sd_assertfq() therefore allow a small */
	/* difference between a and b. */
	/* If the user wants to use another epsilon value, he can either define his own */
	/* epsilon via SD_OPTION_EPSILON or write his own macro wrapping sd_assertfq_(). */
	/* If exact comparison is wanted, one can always use sd_assert(a == b). */
	double d = a - b;
	if (d < 0.0) d = -d; /* same as: d = fabsf(d); */
	sd_assert_(ln, d <= e, str);
}

void sd_assertsq_(int ln, char const *a, char const *b, char const *str)
{
	sd_assert_(ln, strcmp(a, b) != 0, str);
}

#endif
