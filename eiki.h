/*
 * eiki.h - Crash handling toolkit
 * Copyright (C) 2012-2013 Jamie Liu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef EIKI_H_
#define EIKI_H_

#include <signal.h>
#include <ucontext.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * I/O
 *****************************************************************************/

/** Write the given null-terminated string to stderr. */
void eiki_print_s(const char* s);

/** Write the given character to stderr. */
void eiki_print_c(char c);

/** Write the given signed decimal integer to stderr. */
void eiki_print_d(int d);
void eiki_print_ld(long ld);
#ifdef HAVE_LONG_LONG_INT
void eiki_print_lld(long long lld);
#endif

/** Write the given unsigned decimal integer to stderr. */
void eiki_print_u(unsigned int u);
void eiki_print_lu(unsigned long lu);
#ifdef HAVE_LONG_LONG_INT
void eiki_print_llu(unsigned long long llu);
#endif
void eiki_print_zu(size_t zu);

/** Write the given unsigned hexadecimal integer to stderr. */
void eiki_print_x(unsigned int x);
void eiki_print_lx(unsigned long lx);
#ifdef HAVE_LONG_LONG_INT
void eiki_print_llx(unsigned long long llx);
#endif
void eiki_print_zx(size_t zx);

/**
 * Write the given pointer to stderr in hexadecimal, prefixed by 0x and padded
 * with 0s.
 */
void eiki_print_p(const void* ptr);

/** Returns 1 if stdin is a tty (interactive) and 0 otherwise. */
int eiki_stdin_is_tty();

/*****************************************************************************
 * Memory management
 *****************************************************************************/

/**
 * As `malloc()`, but allocates out of a much smaller heap and is reentrant
 * (and hence both thread-safe and async-signal-safe).
 */
void *eiki_malloc(size_t sz);

/**
 * As `free`, but usable only for memory obtained from `eiki_malloc()`. Is also
 * reentrant.
 */
void eiki_free(const void *ptr);

/*****************************************************************************
 * Signals
 *****************************************************************************/

/** Print information about the given caught signal. */
void eiki_print_signal(int signum, const siginfo_t *info);

/** Print debugging information about the given context to stderr. */
void eiki_print_context(const ucontext_t *context);

/**
 * Signal handler:
 * - Calls `eiki_print_signal(signum, info)`.
 * - Calls `eiki_print_stack_trace(0)`.
 * - Calls `eiki_print_context(context)`.
 * - If EIKI_GDB_IF_TTY is defined and stdin is a tty, calls `eiki_gdb()`.
 * - Calls `abort()`.
 */
void eiki_signal_handler(int signum, const siginfo_t *info,
    const ucontext_t *context);

/**
 * Set `eiki_signal_handler()` as the default handler for SIGILL (illegal
 * instruction), SIGFPE (floating point exception), SIGSEGV (segmentation
 * violation), SIGBUS (bus error), SIGSYS (bad argument to syscall), and
 * SIGABRT (aborted). In addition, if EIKI_NO_SIGNAL_STACK is not defined, set
 * up an alternative signal stack and set `eiki_signal_handler()` to run on it.
 *
 * If successful, returns 0. Otherwise, returns -1, and errno is set.
 */
int eiki_install_signal_handler();

/**
 * Aborts the program via SIGABRT, unregistering any existing signal handler
 * for SIGABRT first. (Self-terminating via SIGABRT rather than, say, SIGKILL
 * matters because SIGABRT's default signal handler dumps core.)
 */
void eiki_abort();

/*****************************************************************************
 * Debugger support
 *****************************************************************************/

/**
 * Drop into a debugger, even if we were not run from one. If successful,
 * `eiki_gdb()` will not return until the debugger terminates. If
 * unsuccessful, `eiki_gdb()` will return immediately. Returns 1 on success and
 * 0 on failure.
 */
int eiki_gdb();

/*****************************************************************************
 * Stack traces
 *****************************************************************************/

typedef struct {
  const void *addr; /* instruction address (technically return address) */
  char *module; /* module (~binary) name */
  char *name; /* function name */
  char *offset; /* instruction byte offset within function */
  char *src; /* source file and line */
} eiki_stack_frame;

/**
 * Get a stack trace in the form of an array of up to `max_depth` stack frames,
 * dynamically allocated using `eiki_malloc` (where the strings in each stack
 * frame are also allocated using `eiki_malloc`.) The first `skip_count` stack
 * frames are skipped. If successful, returns a pointer to the stack trace
 * array, and sets `*depth` to the number of valid stack frames. (`depth` must
 * not be null.) Otherwise, returns null.
 */
eiki_stack_frame *eiki_get_stack_trace(size_t max_depth, size_t skip_count,
    size_t *depth);

/**
 * Prints the current stack trace to stderr. The first `skip_count` stack
 * frames are skipped.
 */
void eiki_print_stack_trace(size_t skip_count);

/**
 * Utility function to fully free a stack trace returned by
 * `eiki_get_stack_trace()` with depth `depth`. `stack_trace` may be null, in
 * which case this function is a no-op.
 */
void eiki_free_stack_trace(eiki_stack_frame *stack_trace, size_t depth);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* EIKI_H_ */
