/*
 * eiki.c - Crash handling toolkit
 * Copyright (C) 2012 Jamie Liu
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

/* Required for mkstemp(3) (the manpage says only 200112L is required, but the
 * manpage is wrong) */
#define _POSIX_C_SOURCE 200809L

#include <execinfo.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "eiki.h"

/*****************************************************************************
 * Configuration
 *****************************************************************************/

/**
 * Maximum number of frames in the stack trace printed by
 * `eiki_print_stack_trace()`.
 */
#ifndef EIKI_PRINT_STACK_FRAMES
  #define EIKI_PRINT_STACK_FRAMES 64
#endif

/** Stack trace temporary filename template. */
#ifndef EIKI_STACK_TRACE_TEMP
  #define EIKI_STACK_TRACE_TEMP "/tmp/eiki_stack_trace_XXXXXX"
#endif

#ifdef EIKI_SRC_PATHNAMES
  #define EIKI_ADDR2LINE_SRC_FLAGS "-e"
#else
  #define EIKI_ADDR2LINE_SRC_FLAGS "-se"
#endif

#ifndef EIKI_BINUTILS_DIR
  #define EIKI_BINUTILS_DIR "/usr/bin/"
#endif

/** Path to `addr2line(1)`. */
#ifndef EIKI_ADDR2LINE_PATH
  #define EIKI_ADDR2LINE_PATH EIKI_BINUTILS_DIR "addr2line"
#endif

/** Path to `c++filt(1)`. */
#ifndef EIKI_CXXFILT_PATH
  #define EIKI_CXXFILT_PATH EIKI_BINUTILS_DIR "c++filt"
#endif

/** Path to `gdb(1)`. */
#ifndef EIKI_GDB_PATH
  #define EIKI_GDB_PATH "/usr/bin/gdb"
#endif

/** Drop to a debugger on crash if we're on a tty? */
#define EIKI_GDB_IF_TTY

/*****************************************************************************
 * Assertions
 *****************************************************************************/

static void eiki_assertion_failed(const char* msg) {
  eiki_print_s(msg);
  abort();
}

#define EIKI_PP_STRINGIFY(X) EIKI_PP_STRINGIFY_(X)
#define EIKI_PP_STRINGIFY_(X) #X
#define EIKI_ASSERT_HERE "*** eiki: ASSERTION FAILED at " __FILE__ ":" \
    EIKI_PP_STRINGIFY(__LINE__)
#ifdef EIKI_NDEBUG
#define EIKI_ASSERT(EXPR) ((void)0)
#define EIKI_ASSERTF(EXPR, MSG) ((void)0)
#else
#define EIKI_ASSERT(EXPR) do { if (!(EXPR)) eiki_assertion_failed( \
    EIKI_ASSERT_HERE ": " #EXPR "\n"); } while (0)
#define EIKI_ASSERTF(EXPR, MSG) do { if (!(EXPR)) eiki_assertion_failed( \
    EIKI_ASSERT_HERE ": " MSG "\n"); } while (0)
#endif
#define EIKI_STATIC_ASSERT(EXPR) EIKI_STATIC_ASSERT_IMPL(EXPR, __COUNTER__)
#define EIKI_STATIC_ASSERT_IMPL(EXPR, TAG) EIKI_STATIC_ASSERT_IMPL2(EXPR, TAG)
#define EIKI_STATIC_ASSERT_IMPL2(EXPR, TAG) typedef int \
    static_assertion_failed_ ## TAG [(!!(EXPR))*2-1]

/*****************************************************************************
 * String manipulation
 *****************************************************************************/

/** Internal version of `strcpy(3)`, which is not async-signal-safe. */
static char *eiki_strcpy(char *dest, const char *src) {
  size_t i;
  for (i = 0; src[i]; i++) {
    dest[i] = src[i];
  }
  dest[i] = '\0';
  return dest;
}

/** Internal version of `strcat(3)`, which is not async-signal-safe. */
static char *eiki_strcat(char *dest, const char *src) {
  /* Find the \0 */
  char *ptr;
  ptr = dest;
  while (*ptr) {
    ptr++;
  }
  eiki_strcpy(ptr, src);
  return dest;
}

/** Internal version of `strlen(3)`, which is not async-signal-safe. */
static size_t eiki_strlen(const char *s) {
  const char* s2 = s;
  while (*s2) {
    s2++;
  }
  return s2 - s;
}

/** Get the number of digits in the given size_t. */
static size_t eiki_strlen_zu(size_t x) {
  size_t digits = 0;
  if (!x) {
    return 1;
  }
  while (x) {
    digits++;
    x /= 10;
  }
  return digits;
}

/** Get the hexadecimal representation of `x & 0xf`. */
static char eiki_hex_char(unsigned char x) {
  x &= 0xf;
  if (x < 10) {
    return x + '0';
  } else {
    return x + 'a' - 10;
  }
}

/*****************************************************************************
 * I/O
 *****************************************************************************/

/** Wrapper around `read(2)` that retries on EINTR. */
static ssize_t eiki_read(int fd, void *buf, size_t count) {
  size_t done = 0;
  while (done < count) {
    ssize_t delta = read(fd, (char *)buf + done, count - done);
    if (delta < 0) {
      if (errno != EINTR) {
        return -1;
      }
    } else if (delta == 0) {
      break;
    } else {
      done += delta;
    }
  }
  return done;
}

/** Wrapper around `write(2)` that retries on EINTR. */
static ssize_t eiki_write(int fd, const void *buf, size_t count) {
  size_t done = 0;
  while (done < count) {
    ssize_t delta = write(fd, (const char *)buf + done, count - done);
    if (delta < 0) {
      if (errno != EINTR) {
        return -1;
      }
    } else if (delta == 0) {
      break;
    } else {
      done += delta;
    }
  }
  return done;
}

/** Wrapper around `close(2)` that retries on EINTR. */
static int eiki_close(int fd) {
  int rv;
  while (1) {
    rv = close(fd);
    if (!rv) {
      break;
    } else if (errno != EINTR) {
      break;
    }
  }
  return rv;
}

/** Wrapper around `dup2(2)` that retries on EINTR. */
static int eiki_dup2(int oldfd, int newfd) {
  int rv;
  while (1) {
    rv = dup2(oldfd, newfd);
    if (!rv) {
      break;
    } else if (errno != EINTR) {
      break;
    }
  }
  return rv;
}

/**
 * Run the program `file` with the arguments `argv`. Returns its output as a
 * string allocated using `eiki_malloc()` if successful, and NULL otherwise.
 */
static char *eiki_execv(const char *file, char *const argv[]) {
  int pipe_fd[2] = { -1, -1 };
  int rv;
  char *buf = NULL;
  pid_t pid;
  rv = pipe(pipe_fd);
  if (rv) {
    goto fail;
  }
  pid = fork();
  if (pid < 0) {
    goto fail;
  } else if (pid) { /* In parent */
    int status;
    int pipe_len;
    ssize_t sz;
    rv = (int)waitpid(pid, &status, 0);
    if (rv <= 0) {
      goto fail;
    }
    if (WEXITSTATUS(status) == EXIT_FAILURE) {
      goto fail;
    }
    rv = ioctl(pipe_fd[0], FIONREAD, &pipe_len);
    if (rv) {
      goto fail;
    }
    buf = eiki_malloc(pipe_len + 1);
    if (!buf) {
      goto fail;
    }
    sz = eiki_read(pipe_fd[0], buf, pipe_len);
    if (sz < 0) {
      goto fail;
    }
    buf[sz] = '\0';
    eiki_close(pipe_fd[0]);
    eiki_close(pipe_fd[1]);
    return buf;
  } else { /* In child */
    char *envp[] = { NULL };
    eiki_close(STDERR_FILENO);
    eiki_close(STDIN_FILENO);
    rv = eiki_dup2(pipe_fd[1], STDOUT_FILENO);
    if (rv < 0) {
      /* Parent will clean up pipe_fd[1] */
      _exit(EXIT_FAILURE);
    }
    rv = execve(file, argv, envp);
    /* If we get here, execve failed */
    _exit(EXIT_FAILURE);
  }

fail:
  eiki_free(buf);
  if (pipe_fd[0] >= 0) {
    eiki_close(pipe_fd[0]);
  }
  if (pipe_fd[1] >= 0) {
    eiki_close(pipe_fd[1]);
  }
  return NULL;
}

/**
 * Run the program `file` with the arguments `argv` asynchronously, and return
 * control to the caller. The child's pid is returned on success, and -1 is
 * returned on failure.
 */
static pid_t eiki_execv_async(const char *file, char *const argv[]) {
  int rv;
  pid_t pid;
  int success_pipe_fd[2] = { -1, -1 };

  rv = pipe(success_pipe_fd);
  if (rv) {
    goto fail;
  }

  pid = fork();
  if (pid < 0) {
    goto fail;
  } else if (!pid) { /* In child */
    char *envp[] = { NULL };
    char junk[1] = { 0 };
    eiki_close(success_pipe_fd[0]);
    /* set pipe write-end as close-on-exec to communicate exec success
     * to parent via EOF */
    fcntl(success_pipe_fd[1], F_SETFD, fcntl(success_pipe_fd[1], F_GETFD) | FD_CLOEXEC);
    rv = execve(file, argv, envp);
    /* execve failed: indicate error to parent */
    eiki_write(success_pipe_fd[1], junk, sizeof(junk));
    _exit(EXIT_FAILURE);
  }
  else { /* In parent */
    /* wait for either EOF or data on pipe from child */
    ssize_t len;
    char buf[1];
    eiki_close(success_pipe_fd[1]);
    len = eiki_read(success_pipe_fd[0], buf, sizeof(buf));
    if (len) {
      goto fail;
    }
    eiki_close(success_pipe_fd[0]);
    return pid;
  }

fail:
  if (success_pipe_fd[0] >= 0) {
    eiki_close(success_pipe_fd[0]);
  }
  if (success_pipe_fd[1] >= 0) {
    eiki_close(success_pipe_fd[1]);
  }
  return -1;
}

void eiki_print_s(const char* s) {
  eiki_write(STDERR_FILENO, s, eiki_strlen(s));
}

void eiki_print_c(char c) {
  char buf[2];
  buf[0] = c;
  buf[1] = '\0';
  eiki_print_s(buf);
}

/*
 * Macros to define the numeric eiki_print_* functions. Some notes:
 * - A 64-bit integer, signed or unsigned, has at most 20 digits and at most
 *   16 hex characters.
 * - For signed types, *_MIN has to be handled specially since (in 2s
 *   complement) *_MIN = *_MAX - 1. This isn't too hard since no *_MIN ends in
 *   0.
 */

#define EIKI_DEFINE_PRINT_SIGNED_INTEGER(c_, type_, min_) \
  void eiki_print_ ## c_ (type_ x) { \
    int neg; \
    char buf[22]; \
    char *ptr; \
    EIKI_STATIC_ASSERT(sizeof(type_) * CHAR_BIT <= 64); \
    if (!x) { \
      eiki_print_c('0'); \
      return; \
    } \
    buf[21] = '\0'; \
    ptr = buf + 21; \
    if (x < 0) { \
      if (x == min_) { \
        neg = 2; \
        x = -(x + 1); \
      } else { \
        neg = 1; \
        x = -x; \
      } \
    } else { \
      neg = 0; \
    } \
    while (x) { \
      ptr--; \
      EIKI_ASSERT(ptr >= buf); \
      *ptr = (x % 10) + '0'; \
      x /= 10; \
    } \
    if (neg) { \
      ptr--; \
      EIKI_ASSERT(ptr >= buf); \
      *ptr = '-'; \
      if (neg == 2) { \
        buf[20]++; \
      } \
    } \
    eiki_print_s(ptr); \
  }

#define EIKI_DEFINE_PRINT_UNSIGNED_INTEGER(c_, type_) \
  void eiki_print_ ## c_ (type_ x) { \
    char buf[21]; \
    char *ptr; \
    EIKI_STATIC_ASSERT(sizeof(type_) * CHAR_BIT <= 64); \
    if (!x) { \
      eiki_print_c('0'); \
      return; \
    } \
    buf[20] = '\0'; \
    ptr = buf + 20; \
    while (x) { \
      ptr--; \
      EIKI_ASSERT(ptr >= buf); \
      *ptr = (x % 10) + '0'; \
      x /= 10; \
    } \
    eiki_print_s(ptr); \
  }

#define EIKI_DEFINE_PRINT_HEX_INTEGER(c_, type_) \
  void eiki_print_ ## c_ (type_ x) { \
    char buf[17]; \
    char *ptr; \
    EIKI_STATIC_ASSERT(sizeof(type_) * CHAR_BIT <= 64); \
    if (!x) { \
      eiki_print_c('0'); \
      return; \
    } \
    buf[16] = '\0'; \
    ptr = buf + 16; \
    while (x) { \
      ptr--; \
      EIKI_ASSERT(ptr >= buf); \
      *ptr = eiki_hex_char(x); \
      x >>= 4; \
    } \
    eiki_print_s(ptr); \
  }

EIKI_DEFINE_PRINT_SIGNED_INTEGER(d, int, INT_MIN)
EIKI_DEFINE_PRINT_SIGNED_INTEGER(ld, long, LONG_MIN)
#ifdef HAVE_LONG_LONG_INT
EIKI_DEFINE_PRINT_SIGNED_INTEGER(lld, long long, LLONG_MIN)
#endif

EIKI_DEFINE_PRINT_UNSIGNED_INTEGER(u, unsigned int)
EIKI_DEFINE_PRINT_UNSIGNED_INTEGER(lu, unsigned long)
#ifdef HAVE_LONG_LONG_INT
EIKI_DEFINE_PRINT_UNSIGNED_INTEGER(llu, unsigned long long)
#endif
EIKI_DEFINE_PRINT_UNSIGNED_INTEGER(zu, size_t)

EIKI_DEFINE_PRINT_HEX_INTEGER(x, unsigned int)
EIKI_DEFINE_PRINT_HEX_INTEGER(lx, unsigned long)
#ifdef HAVE_LONG_LONG_INT
EIKI_DEFINE_PRINT_HEX_INTEGER(llx, unsigned long long)
#endif
EIKI_DEFINE_PRINT_HEX_INTEGER(zx, size_t)

void eiki_print_p(const void *ptr) {
  const size_t bytes = sizeof(void *);
  const size_t bits = bytes * CHAR_BIT;
  size_t shift = ((bits - 1) / 4) * 4;
  size_t p;
  EIKI_STATIC_ASSERT(sizeof(size_t) == sizeof(void *));
  eiki_print_s("0x");
  p = (size_t)ptr;
  for (; shift; shift -= 4) {
    eiki_print_c(eiki_hex_char(p >> shift));
  }
  /* shift is now 0; print the last character */
  eiki_print_c(eiki_hex_char(p));
}

/** Print a general register as a 0-padded hexadecimal number. */
static void eiki_print_greg(greg_t reg) {
  const size_t bytes = sizeof(greg_t);
  const size_t bits = bytes * CHAR_BIT;
  size_t shift = ((bits - 1) / 4) * 4; /* round down to multiple of 4 */
  for (; shift; shift -= 4) {
    eiki_print_c(eiki_hex_char(reg >> shift));
  }
  /* shift is now 0; print the last character */
  eiki_print_c(eiki_hex_char(reg));
}

/** Essentially a safe version of `fprintf(stderr, "==%d== ", getpid())`. */
static void eiki_print_pid_prefix() {
  eiki_print_s("==");
  eiki_print_d(getpid());
  eiki_print_s("== ");
}

/** determine whether stdin is a tty. */
int eiki_in_is_tty() {
  return isatty(STDIN_FILENO);
}

/*****************************************************************************
 * Memory management. `eiki_malloc` and `eiki_free` serve memory out of a
 * statically-allocated reserve heap, since `malloc` and `free` cannot be
 * safely called during a crash / within a signal handler.
 *
 * The current implementation of Eiki's heap is thread-safe and
 * async-signal-safe, does not require locks (or pthreads), and is relatively
 * simple. Space efficiency and performance are sacrificed to achieve this.
 *
 * The heap, which is of size `EIKI_HEAP_BYTES`, is divided into blocks
 * `EIKI_HEAP_BLOCK_BYTES` in size. Each block is associated with an int "tag".
 * The tag is 0 when the block is unallocated, and non-zero when the block is
 * allocated; specifically, the first block in a contiguous allocation has tag
 * equal to the number of blocks in the allocation, and all remaining blocks
 * have tag -1.
 *****************************************************************************/

/**
 * Size of the Eiki heap in chars. Defaults to 2MB (assuming CHAR_BIT = 8).
 * Must be an integer multiple of EIKI_HEAP_BLOCK_SIZE and
 * sizeof(eiki_heap_type).
 */
#ifndef EIKI_HEAP_SIZE
  #define EIKI_HEAP_SIZE 2097152
#endif

/** Size of each block in the Eiki heap in chars. */
#ifndef EIKI_HEAP_BLOCK_SIZE
  #define EIKI_HEAP_BLOCK_SIZE 64
#endif

/** Number of blocks in the Eiki heap. */
#define EIKI_HEAP_BLOCKS (EIKI_HEAP_SIZE / EIKI_HEAP_BLOCK_SIZE)

/**
 * The type used to instantiate the Eiki heap. The heap isn't just
 * unsigned char[EIKI_HEAP_SIZE] due to alignment restrictions.
 */

typedef union {
#ifdef HAVE_LONG_LONG_INT
  unsigned long long val;
#else
  unsigned long val;
#endif
  void *ptr;
#ifdef EIKI_HEAP_ALIGNMENT_TYPE
  EIKI_HEAP_ALIGNMENT_TYPE other;
#endif
} eiki_heap_min_type;

typedef struct {
  eiki_heap_min_type x[EIKI_HEAP_BLOCK_SIZE/sizeof(eiki_heap_min_type)];
} eiki_heap_block;

/** The heap. */
static eiki_heap_block eiki_heap[EIKI_HEAP_BLOCKS]
#ifdef __GNUC__
    __attribute__((aligned(__BIGGEST_ALIGNMENT__)))
#endif
    ;

/** Heap block tags. */
static int eiki_heap_tags[EIKI_HEAP_BLOCKS];

/** Counter that gets bumped whenever the heap state changes. */
static int eiki_heap_ctr;

void *eiki_malloc(size_t sz) {
  if (!sz) {
    return eiki_heap;
  }
  while (1) {
    eiki_heap_block *head = NULL; /* head of the current free region */
    size_t cur_sz = 0;
    size_t i;
    int begin_ctr, end_ctr;
    begin_ctr = __sync_fetch_and_add(&eiki_heap_ctr, 0);
    for (i = 0; i < EIKI_HEAP_BLOCKS; i++) {
      if (__sync_fetch_and_add(&eiki_heap_tags[i], 0)) {
        /* Block is allocated */
        head = NULL;
        cur_sz = 0;
      } else { /* Block is unallocated */
        /* Check for start of free region */
        if (!head) {
          head = &eiki_heap[i];
        }
        cur_sz += EIKI_HEAP_BLOCK_SIZE;
        /* Check for satisfied allocation */
        if (cur_sz >= sz) {
          size_t head_i;
          size_t j;
          int success = 1;
          EIKI_ASSERT(head);
          head_i = head - eiki_heap;
          /* Try to acquire each block */
          for (j = head_i; j <= i; j++) {
            int newval;
            newval = (j == head_i) ? (int)(i - head_i + 1) : -1;
            if (!__sync_bool_compare_and_swap(&eiki_heap_tags[j], 0, newval)) {
              size_t k;
              /* Allocation failure; roll back what we've allocated so far */
              success = 0;
              for (k = head_i; k < j; k++) {
                int old_mem_val, old_val;
                old_val = (k == head_i) ? (int)(i - head_i + 1) : -1;
                old_mem_val = __sync_val_compare_and_swap(&eiki_heap_tags[k],
                    old_val, 0);
                EIKI_ASSERT(old_mem_val == old_val);
              }
              break;
            }
          }
          if (success) {
            __sync_fetch_and_add(&eiki_heap_ctr, 1);
            begin_ctr++;
            return head;
          }
        }
      }
    }
    /* Check if the heap changed while we were examining it, and if so retry */
    end_ctr = __sync_fetch_and_add(&eiki_heap_ctr, 0);
    if (begin_ctr == end_ctr) {
      return NULL;
    }
  }
}

void eiki_free(const void *ptr) {
  size_t head_i, i, n;
  int old_mem_val, old_val;
  if (!ptr) {
    return;
  }
  EIKI_ASSERTF(
      ((const unsigned char *)ptr - (const unsigned char *)eiki_heap) %
      EIKI_HEAP_BLOCK_SIZE == 0, "freeing invalid (unaligned) pointer");
  /* First tag contains allocation size */
  head_i = (const eiki_heap_block *)ptr - eiki_heap;
  old_val = __sync_fetch_and_add(&eiki_heap_tags[head_i], 0);
  EIKI_ASSERTF(old_val >= 0, "invalid head block tag");
  n = old_val;
  /* Free first block */
  old_mem_val = __sync_val_compare_and_swap(&eiki_heap_tags[head_i], old_val,
      0);
  EIKI_ASSERT(old_mem_val == old_val);
  /* Free remaining blocks */
  for (i = 1; i < n; i++) {
    old_mem_val = __sync_val_compare_and_swap(&eiki_heap_tags[head_i + i], -1,
        0);
    EIKI_ASSERT(old_mem_val == -1);
  }
  __sync_fetch_and_add(&eiki_heap_ctr, 1);
}

/*****************************************************************************
 * Signals
 *****************************************************************************/

/** Signals caught by `eiki_install_signal_handler()`. */
static const int EIKI_INSTALLED_SIGNALS[] = {
  SIGILL,
  SIGFPE,
  SIGSEGV,
#ifdef SIGBUS
  SIGBUS,
#endif
#ifdef SIGSYS
  SIGSYS,
#endif
  0
};

/** Register definitions. */
#if defined(__x86_64__)
enum {
  REG_R8 = 0,
  REG_R9,
  REG_R10,
  REG_R11,
  REG_R12,
  REG_R13,
  REG_R14,
  REG_R15,
  REG_RDI,
  REG_RSI,
  REG_RBP,
  REG_RBX,
  REG_RDX,
  REG_RAX,
  REG_RCX,
  REG_RSP,
  REG_RIP,
  REG_EFL,
  REG_CSGSFS,
  REG_ERR,
  REG_TRAPNO,
  REG_OLDMASK,
  REG_CR2
};
#elif defined(__x86__)
enum {
  REG_GS = 0,
  REG_FS,
  REG_ES,
  REG_DS,
  REG_EDI,
  REG_ESI,
  REG_EBP,
  REG_ESP,
  REG_EBX,
  REG_EDX,
  REG_ECX,
  REG_EAX,
  REG_TRAPNO,
  REG_ERR,
  REG_EIP,
  REG_CS,
  REG_EFL,
  REG_UESP,
  REG_SS
};
#endif

static const char *eiki_sigill_info(int code) {
  switch (code) {
#ifdef ILL_ILLOPC
    case ILL_ILLOPC:
      return "illegal opcode";
#endif
#ifdef ILL_ILLOPN
    case ILL_ILLOPN:
      return "illegal operand";
#endif
#ifdef ILL_ILLADR
    case ILL_ILLADR:
      return "illegal addressing mode";
#endif
#ifdef ILL_ILLTRP
    case ILL_ILLTRP:
      return "illegal trap";
#endif
#ifdef ILL_PRVOPC
    case ILL_PRVOPC:
      return "privileged opcode";
#endif
#ifdef ILL_PRVREG
    case ILL_PRVREG:
      return "privileged register";
#endif
#ifdef ILL_COPROC
    case ILL_COPROC:
      return "coprocessor error";
#endif
#ifdef ILL_BADSTK
    case ILL_BADSTK:
      return "internal stack error";
#endif
    default:
      return NULL;
  }
}

#ifdef SIGBUS
static const char *eiki_sigbus_info(int code) {
  switch (code) {
#ifdef BUS_ADRALN
    case BUS_ADRALN:
      return "invalid address alignment";
#endif
#ifdef BUS_ADRERR
    case BUS_ADRERR:
      return "non-existent physical address";
#endif
#ifdef BUS_OBJERR
    case BUS_OBJERR:
      return "object specific hardware error";
#endif
    default:
      return NULL;
  }
}
#endif

static const char *eiki_sigfpe_info(int code) {
  switch (code) {
#ifdef FPE_INTDIV
    case FPE_INTDIV:
      return "integer divide by zero";
#endif
#ifdef FPE_INTOVF
    case FPE_INTOVF:
      return "integer overflow";
#endif
#ifdef FPE_FLTDIV
    case FPE_FLTDIV:
      return "floating point divide by zero";
#endif
#ifdef FPE_FLTOVF
    case FPE_FLTOVF:
      return "floating point overflow";
#endif
#ifdef FPE_FLTUND
    case FPE_FLTUND:
      return "floating point underflow";
#endif
#ifdef FPE_FLTRES
    case FPE_FLTRES:
      return "floating point inexact result";
#endif
#ifdef FPE_FLTINV
    case FPE_FLTINV:
      return "floating point invalid operation";
#endif
#ifdef FPE_SUBRNG
    case FPE_SUBRNG:
      return "subscript range out of bounds";
#endif
    default:
      return NULL;
  }
}

static const char *eiki_sigsegv_info(int code) {
  switch (code) {
#ifdef SEGV_MAPERR
    case SEGV_MAPERR:
      return "address not mapped to object";
#endif
#ifdef SEGV_ACCERR
    case SEGV_ACCERR:
      return "invalid permissions for mapped object";
#endif
    default:
      return NULL;
  }
}

void eiki_print_signal(int signum, const siginfo_t *info) {
  const char *siginfo = NULL;
  int sigcode;
  eiki_print_s("Caught signal ");
  eiki_print_d(signum);
  eiki_print_s(" (");
  if (signum == SIGFPE) {
    eiki_print_s("Arithmetic exception");
  } else {
    eiki_print_s(strsignal(signum));
  }
  if (info) {
    sigcode = info->si_code;
    switch (signum) {
      case SIGILL:
        siginfo = eiki_sigill_info(sigcode);
        break;
#ifdef SIGBUS
      case SIGBUS:
        siginfo = eiki_sigbus_info(sigcode);
        break;
#endif
      case SIGFPE:
        siginfo = eiki_sigfpe_info(sigcode);
        break;
      case SIGSEGV:
        siginfo = eiki_sigsegv_info(sigcode);
        break;
    }
  }
  if (siginfo) {
    eiki_print_s(": ");
    eiki_print_s(siginfo);
  }
  eiki_print_s(")\n");
}

void eiki_print_context(const ucontext_t *context) {
  size_t i;
  /* Print registers */
  if (context) {
    eiki_print_s("Registers:\n");
#define EIKI_PRINT_REG(name_, reg_) do { \
    eiki_print_s(name_ " = "); \
    eiki_print_greg(context->uc_mcontext.gregs[reg_]); \
    eiki_print_c('\n'); } while (0)
#if defined(__x86_64__)
    EIKI_PRINT_REG("rax", REG_RAX);
    EIKI_PRINT_REG("rbx", REG_RBX);
    EIKI_PRINT_REG("rcx", REG_RCX);
    EIKI_PRINT_REG("rdx", REG_RDX);
    EIKI_PRINT_REG("rdi", REG_RDI);
    EIKI_PRINT_REG("rsi", REG_RSI);
    EIKI_PRINT_REG("rbp", REG_RBP);
    EIKI_PRINT_REG("rsp", REG_RSP);
    EIKI_PRINT_REG(" r8", REG_R8);
    EIKI_PRINT_REG(" r9", REG_R9);
    EIKI_PRINT_REG("r10", REG_R10);
    EIKI_PRINT_REG("r11", REG_R11);
    EIKI_PRINT_REG("r12", REG_R12);
    EIKI_PRINT_REG("r13", REG_R13);
    EIKI_PRINT_REG("r14", REG_R14);
    EIKI_PRINT_REG("r15", REG_R15);
    EIKI_PRINT_REG("rip", REG_RIP);
    EIKI_PRINT_REG("efl", REG_EFL);
    EIKI_PRINT_REG("cr2", REG_CR2);
    EIKI_PRINT_REG("0:fs:gs:cs", REG_CSGSFS); /* [sic] (endianness) */
#elif defined(__x86__)
    EIKI_PRINT_REG("eax", REG_EAX);
    EIKI_PRINT_REG("ebx", REG_EBX);
    EIKI_PRINT_REG("ecx", REG_ECX);
    EIKI_PRINT_REG("edx", REG_EDX);
    EIKI_PRINT_REG("edi", REG_EDI);
    EIKI_PRINT_REG("esi", REG_ESI);
    EIKI_PRINT_REG("ebp", REG_EBP);
    EIKI_PRINT_REG("esp", REG_ESP);
    EIKI_PRINT_REG("eip", REG_EIP);
    EIKI_PRINT_REG("efl", REG_EFL);
    EIKI_PRINT_REG(" cs", REG_CS);
    EIKI_PRINT_REG(" ds", REG_DS);
    EIKI_PRINT_REG(" es", REG_ES);
    EIKI_PRINT_REG(" fs", REG_FS);
    EIKI_PRINT_REG(" gs", REG_GS);
    EIKI_PRINT_REG(" ss", REG_SS);
#else /* generic */
    for (i = 0; i < NGREG; i++) {
      eiki_print_s("r[");
      eiki_print_zu(i);
      eiki_print_s("] = ");
      eiki_print_greg(context->uc_mcontext.gregs[i]);
      eiki_print_c('\n');
    }
#endif
#undef EIKI_PRINT_REG
  } else {
    eiki_print_s("Register values not available\n");
  }
  (void)i;
}

void eiki_signal_handler(int signum, const siginfo_t *info,
    const ucontext_t *context) {
  eiki_print_pid_prefix(); eiki_print_signal(signum, info);
  eiki_print_pid_prefix(); eiki_print_stack_trace(0);
  eiki_print_pid_prefix(); eiki_print_context(context);

#ifdef EIKI_GDB_IF_TTY
  if (eiki_in_is_tty()) {
    eiki_gdb();
    _exit(1);
  }
#endif
  abort();
}

int eiki_install_signal_handler() {
  int rv;
  const int *signum;
  struct sigaction action;
#ifndef EIKI_NO_SIGNAL_STACK
  stack_t sig_stack;
  sig_stack.ss_size = SIGSTKSZ;
  sig_stack.ss_flags = 0;
  /* Allocate and install the signal stack. */
  sig_stack.ss_sp = malloc(sig_stack.ss_size);
  if (sig_stack.ss_sp) {
    rv = sigaltstack(&sig_stack, NULL);
    if (rv) {
      return -1;
    }
  } else  {
    errno = ENOMEM;
    return -1;
  }
#endif
  action.sa_handler = (void (*)(int))eiki_signal_handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_SIGINFO;
#ifndef EIKI_NO_SIGNAL_STACK
  action.sa_flags |= SS_ONSTACK;
#endif
  for (signum = EIKI_INSTALLED_SIGNALS; *signum; signum++) {
    rv = sigaction(*signum, &action, NULL);
    if (rv) {
      return -1;
    }
  }
  return 0;
}

/*****************************************************************************
 * Debugger support
 *****************************************************************************/

/* forward decl */
static int eiki_pid_to_str(pid_t pid, char *str);

void eiki_gdb() {
  pid_t gdb_pid = -1;
  pid_t pid;
  char pid_str[16];
  char *argv[] = { NULL, NULL, NULL, NULL };

  /* construct command line: gdb <my_binary> <my_pid> */
  argv[0] = eiki_malloc(4);
  if (!argv[0]) {
    goto end;
  }
  eiki_strcpy(argv[0], "gdb");
  argv[1] = eiki_malloc(32);
  if (!argv[1]) {
    goto end;
  }
  eiki_strcpy(argv[1], "/proc/");
  pid = getpid();
  eiki_pid_to_str(pid, pid_str);
  eiki_strcat(argv[1], pid_str);
  eiki_strcat(argv[1], "/exe");
  argv[2] = eiki_malloc(16);
  if (!argv[2]) {
    goto end;
  }
  eiki_strcpy(argv[2], pid_str);

  gdb_pid = eiki_execv_async(EIKI_GDB_PATH, argv);
  if (gdb_pid != -1) {
    int status;
    waitpid(gdb_pid, &status, 0);
  }

end:
  return;
}

/*****************************************************************************
 * Stack traces
 *****************************************************************************/

/**
 * Read a line emitted by backtrace_symbols_fd. Each line is of the form
 *
 *     module(name+offset) [address]
 *
 * where each part except for [address] is optional. For each of the pointers
 * `module`, `name`, `offset`, and `address`, if the pointer is not null and
 * the given part is present, the pointed-to pointer is set to a string
 * containing that part, dynamically allocated using `eiki_malloc()`. If the
 * given part is not present, the pointed-to pointer is set to null. If a line
 * is successfully read, returns 0, and `fd` is advanced to the next line.
 * Otherwise, returns -1, all allocated memory is freed, `fd` is restored to
 * its original position, and all pointed-to pointers are unmodified.
 */
static int eiki_read_backtrace_symbols_line(int fd, char **module, char **name,
    char **offset, char **address) {
  off_t orig_pos, eol_pos;
  /* [0] => module, [1] => name, [2] => offset, [3] => address */
  off_t pos[4];
  size_t len[4] = { 0, 0, 0, 0 };
  char *str[4] = { NULL, NULL, NULL, NULL };
  size_t *cur_len = &len[0];
  int i;
  /* Remember where we started */
  orig_pos = lseek(fd, 0, SEEK_CUR);
  pos[0] = orig_pos;
  /* Do a first pass to measure the length of everything */
  while (1) {
    char c;
    ssize_t sz = eiki_read(fd, &c, 1);
    if (sz < 0) {
      goto fail;
    } else if (sz == 0) {
      /* EOF */
      break; /* goto end_of_line; */
    } else {
      switch (c) {
        case '(':
          cur_len = &len[1];
          pos[1] = lseek(fd, 0, SEEK_CUR);
          break;
        case '+':
          cur_len = &len[2];
          pos[2] = lseek(fd, 0, SEEK_CUR);
          break;
        case '[':
          cur_len = &len[3];
          pos[3] = lseek(fd, 0, SEEK_CUR);
          break;
        case ')':
        case ' ':
        case ']':
          cur_len = NULL;
          break;
        case '\n':
          goto end_of_line;
        default:
          if (cur_len) {
            (*cur_len)++;
          }
      }
    }
  }
end_of_line:
  eol_pos = lseek(fd, 0, SEEK_CUR);
  /* Force length to 0 for anything the user doesn't want */
  if (!module) {
    len[0] = 0;
  }
  if (!name) {
    len[1] = 0;
  }
  if (!offset) {
    len[2] = 0;
  }
  if (!address) {
    len[3] = 0;
  }
  /* Read out everything available */
  for (i = 0; i < 4; i++) {
    if (len[i]) {
      ssize_t sz;
      str[i] = eiki_malloc(len[i] + 1);
      if (!str[i]) {
        goto fail;
      }
      lseek(fd, pos[i], SEEK_SET);
      sz = eiki_read(fd, str[i], len[i]);
      if (sz < 0) {
        goto fail;
      }
      str[i][sz] = '\0';
    }
  }
  /* Done */
  if (module) {
    *module = str[0];
  }
  if (name) {
    *name = str[1];
  }
  if (offset) {
    *offset = str[2];
  }
  if (address) {
    *address = str[3];
  }
  lseek(fd, eol_pos, SEEK_SET);
  return 0;

fail:
  for (i = 0; i < 4; i++) {
    eiki_free(str[i]);
  }
  lseek(fd, orig_pos, SEEK_SET);
  return -1;
}

/**
 * Stringify `pid`. `str` must be a buffer of length at least 12 bytes
 * (assuming pid_t is 32 bits). If pid is negative, sets `*str` to an empty
 * string and returns 0; otherwise sets `*str` to a string containing the value
 * of `pid` and returns 1.
 */
static int eiki_pid_to_str(pid_t pid, char *str) {
  size_t digits;
  char *ptr;
  EIKI_STATIC_ASSERT(sizeof(pid_t) * CHAR_BIT <= 32);
  EIKI_STATIC_ASSERT(sizeof(size_t) >= sizeof(pid_t)); /* laziness: (1) */
  EIKI_ASSERT(str);
  if (!pid) {
    str[0] = '0';
    str[1] = '\0';
    return 1;
  } else if (pid < 0) {
    str[0] = '\0';
    return 0;
  }
  digits = eiki_strlen_zu((size_t)pid); /* (1) */
  str[digits] = '\0';
  ptr = &str[digits];
  while (pid) {
    ptr--;
    EIKI_ASSERT(ptr >= str);
    *ptr = (pid % 10) + '0';
    pid /= 10;
  }
  EIKI_ASSERT(ptr == str);
  return 1;
}

/**
 * Try to set the `name` field of the given stack frame. `addr` must be
 * non-null, and `*addr` must be the address of the instruction being probed in
 * hexadecimal, with or without the 0x prefix.
 */
static void eiki_fill_stack_frame_name(eiki_stack_frame *frame, char *addr) {
#ifdef EIKI_NO_BINUTILS
  (void)frame;
  (void)addr;
  return;
#else
  char pid_str[] = "-2147483648";
  char *argv[] = { NULL, NULL, NULL, NULL, NULL };
  /* If this assertion fails, the length of pid_str and argv[2] below need to
   * be increased. */
  EIKI_STATIC_ASSERT(sizeof(pid_t) * CHAR_BIT <= 32);
  /* This is necessary because `execve(2)` needs an array of pointers to
   * *mutable* char. (But we don't bother making copies for argv[3] because any
   * changes will actually be made in a fork.) */
  argv[0] = eiki_malloc(10);
  if (!argv[0]) {
    goto end;
  }
  eiki_strcpy(argv[0], "addr2line");
  argv[1] = eiki_malloc(5);
  if (!argv[1]) {
    goto end;
  }
  eiki_strcpy(argv[1], "-fse");
  argv[2] = eiki_malloc(21);
  if (!argv[2]) {
    goto end;
  }
  eiki_strcpy(argv[2], "/proc/");
  eiki_pid_to_str(getpid(), pid_str);
  eiki_strcat(argv[2], pid_str);
  eiki_strcat(argv[2], "/exe");
  argv[3] = addr;
  frame->name = eiki_execv(EIKI_ADDR2LINE_PATH, argv);
  if (frame->name) {
    /* Truncate at the first newline */
    char *ptr;
    ptr = frame->name;
    while (*ptr && *ptr != '\n') {
      ptr++;
    }
    *ptr = '\0';
  }
end:
  eiki_free(argv[0]);
  eiki_free(argv[1]);
  eiki_free(argv[2]);
#endif /* EIKI_NO_BINUTILS */
}

/**
 * Try to set the `src` field of the given stack frame. `addr` must be
 * non-null, and `*addr` must be the address of the instruction being probed in
 * hexadecimal, with or without the 0x prefix.
 */
static void eiki_fill_stack_frame_src(eiki_stack_frame *frame, char *addr) {
#ifdef EIKI_NO_BINUTILS
  (void)frame;
  (void)addr;
  return;
#else
  char pid_str[] = "-2147483648";
  char *argv[] = { NULL, NULL, NULL, NULL, NULL };
  /* If this assertion fails, the length of pid_str and argv[2] below need to
   * be increased. */
  EIKI_STATIC_ASSERT(sizeof(pid_t) * CHAR_BIT <= 32);
  /* This is necessary because `execve(2)` needs an array of pointers to
   * *mutable* char. (But we don't bother making copies for argv[3] because any
   * changes will actually be made in a fork.) */
  argv[0] = eiki_malloc(10);
  if (!argv[0]) {
    goto end;
  }
  eiki_strcpy(argv[0], "addr2line");
  argv[1] = eiki_malloc(4); /* The longer possibility, "-se", is 3+1 bytes */
  if (!argv[1]) {
    goto end;
  }
  eiki_strcpy(argv[1], EIKI_ADDR2LINE_SRC_FLAGS);
  argv[2] = eiki_malloc(21);
  if (!argv[2]) {
    goto end;
  }
  eiki_strcpy(argv[2], "/proc/");
  eiki_pid_to_str(getpid(), pid_str);
  eiki_strcat(argv[2], pid_str);
  eiki_strcat(argv[2], "/exe");
  argv[3] = addr;
  frame->src = eiki_execv(EIKI_ADDR2LINE_PATH, argv);
  if (frame->src) {
    /* Remove the newline */
    frame->src[eiki_strlen(frame->src)-1] = '\0';
  }
end:
  eiki_free(argv[0]);
  eiki_free(argv[1]);
  eiki_free(argv[2]);
#endif /* EIKI_NO_BINUTILS */
}

/**
 * Demangle the mangled C++ symbol name `mangled` and place it in a region of
 * memory allocated with `eiki_malloc()`. Returns a pointer to the buffer
 * containing the demangled name if successful and null otherwise.
 */
static char *eiki_cxx_demangle(const char *mangled) {
#ifdef EIKI_NO_BINUTILS
  (void)mangled;
  (void)length;
  (void)status;
  return NULL;
#else
  char *argv[] = { NULL, NULL, NULL };
  char *buf = NULL;
  if (!mangled) {
    return NULL;
  }
  /* See `eiki_fill_stack_frame_src()` for an explanation. */
  argv[0] = eiki_malloc(8);
  if (!argv[0]) {
    goto end;
  }
  eiki_strcpy(argv[0], "c++filt");
  argv[1] = eiki_malloc(eiki_strlen(mangled) + 1);
  if (!argv[1]) {
    goto end;
  }
  eiki_strcpy(argv[1], mangled);
  buf = eiki_execv(EIKI_CXXFILT_PATH, argv);
  if (buf) {
    /* Remove the newline */
    buf[eiki_strlen(buf)-1] = '\0';
  }
end:
  eiki_free(argv[0]);
  eiki_free(argv[1]);
  return buf;
#endif /* EIKI_NO_BINUTILS */
}

eiki_stack_frame *eiki_get_stack_trace(size_t max_depth, size_t skip_count,
    size_t *depth) {
  void **addr_buffer = NULL;
  eiki_stack_frame *stack_trace = NULL;
  size_t i;
  size_t max_addr_frames;
  size_t addr_frames;
  size_t frames;
  int temp_fd = -1;
  char temp_filename[] = EIKI_STACK_TRACE_TEMP;
  /* Check if the user can follow instructions */
  if (!depth) {
    return NULL;
  }
  /* Skip this frame */
  skip_count++;
  /* Get addresses using glibc backtrace() */
  max_addr_frames = max_depth + skip_count;
  addr_buffer = eiki_malloc(max_addr_frames * sizeof(void *));
  if (!addr_buffer) {
    goto fail;
  }
  addr_frames = backtrace(addr_buffer, max_addr_frames);
  if (addr_frames <= skip_count) {
    goto fail;
  }
  frames = addr_frames - skip_count;
  /* Write the symbols out to a temporary file since backtrace_symbols() uses
   * malloc() */
  temp_fd = mkstemp(temp_filename);
  if (temp_fd < 0) {
    goto fail;
  }
  backtrace_symbols_fd(addr_buffer + skip_count, frames, temp_fd);
  /* Allocate and initialize the stack trace array */
  stack_trace = eiki_malloc(frames * sizeof(*stack_trace));
  if (!stack_trace) {
    goto fail;
  }
  for (i = 0; i < frames; i++) {
    stack_trace[i].addr = addr_buffer[skip_count + i];
    stack_trace[i].module = NULL;
    stack_trace[i].name = NULL;
    stack_trace[i].offset = NULL;
    stack_trace[i].src = NULL;
  }
  /* Done with the address buffer, free it now so we have more free memory */
  eiki_free(addr_buffer);
  addr_buffer = NULL;
  /* Rewind back to the beginning of the file and read it back */
  lseek(temp_fd, 0, SEEK_SET);
  for (i = 0; i < frames; i++) {
    char *addr_str = NULL;
    int rv = eiki_read_backtrace_symbols_line(temp_fd,
        &stack_trace[i].module, &stack_trace[i].name,
        &stack_trace[i].offset, &addr_str);
    if (rv) {
      goto fail;
    }
    if (addr_str) {
      if (!stack_trace[i].name) {
        eiki_fill_stack_frame_name(&stack_trace[i], addr_str);
      }
      eiki_fill_stack_frame_src(&stack_trace[i], addr_str);
      eiki_free(addr_str);
    }
#ifndef EIKI_NO_STACK_TRACE_DEMANGLE
    if (stack_trace[i].name) {
      char *demangled;
      demangled = eiki_cxx_demangle(stack_trace[i].name);
      if (demangled) {
        eiki_free(stack_trace[i].name);
        stack_trace[i].name = demangled;
      }
    }
#endif
  }
  /* Done */
  eiki_close(temp_fd);
  unlink(temp_filename);
  *depth = frames;
  return stack_trace;

fail:
  if (temp_fd >= 0) {
    eiki_close(temp_fd);
    unlink(temp_filename);
  }
  if (stack_trace) {
    eiki_free_stack_trace(stack_trace, frames);
  }
  if (addr_buffer) {
    eiki_free(addr_buffer);
  }
  return NULL;
}

void eiki_print_stack_trace(size_t skip_count) {
  eiki_stack_frame *stack_trace;
  size_t frames;
  size_t i;
  skip_count++; /* skip this stack frame */
  stack_trace = eiki_get_stack_trace(EIKI_PRINT_STACK_FRAMES, skip_count,
      &frames);
  if (stack_trace) {
    size_t frame_digits;
    frame_digits = eiki_strlen_zu(frames - 1); /* -1 since 0-indexed */
    eiki_print_s("Stack trace:\n");
    for (i = 0; i < frames; i++) {
      size_t digit;
      for (digit = eiki_strlen_zu(i); digit < frame_digits; digit++) {
        eiki_print_c(' ');
      }
      eiki_print_zu(i);
      eiki_print_s(": ");
      eiki_print_p(stack_trace[i].addr);
      if (stack_trace[i].module) {
        eiki_print_s(" in ");
        eiki_print_s(stack_trace[i].module);
      }
      if (stack_trace[i].name) {
        eiki_print_s(" (");
        eiki_print_s(stack_trace[i].name);
        if (stack_trace[i].offset) {
          eiki_print_c('+');
          eiki_print_s(stack_trace[i].offset);
        }
        eiki_print_c(')');
      }
      if (stack_trace[i].src) {
        eiki_print_s(" {");
        eiki_print_s(stack_trace[i].src);
        eiki_print_c('}');
      }
      eiki_print_c('\n');
    }
  } else {
    eiki_print_s("Stack trace unavailable\n");
  }
  eiki_free_stack_trace(stack_trace, frames);
}

void eiki_free_stack_trace(eiki_stack_frame *stack_trace, size_t depth) {
  size_t i;
  if (!stack_trace) {
    return;
  }
  for (i = 0; i < depth; i++) {
    eiki_free(stack_trace[i].module);
    eiki_free(stack_trace[i].name);
    eiki_free(stack_trace[i].offset);
    eiki_free(stack_trace[i].src);
  }
  eiki_free(stack_trace);
}
