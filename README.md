Synopsis
========

Eiki is a lightweight, standalone C library that provides features to support
handling crashes, including signal-safe output to stderr, memory management,
and stack traces (including C++ name demangling).

Requirements
============

- GCC, for builtin atomics (`__sync_fetch_and_add()`, etc.)

- glibc 2.1 or newer, for `backtrace(3)`.

- POSIX.1-2008, for `strsignal(3)`.

- Optionally, `addr2line(1)` and `c++filt(1)` from `binutils` at runtime.

Eiki has no other external dependencies.

Usage
=====

See eiki.h for function documentation. In short, most programs can simply call
`eiki_install_signal_handler()` at the beginning of `main()`. Depending on what
features are required in your stack traces and whether or not Eiki can use
`addr2line(1)` and `c++filt(1)`, you may need to compile with debug symbols
(`-g`) and/or link with `-rdynamic`; see "Stack Traces" below.

Eiki's behavior is controlled by the following preprocessor flags at the time
eiki.c is compiled:

- If EIKI\_NO\_BINUTILS is defined, `eiki_get_stack_trace()` will not attempt
  to use `c++filt(1)` to perform name demangling and `addr2line(1)` to perform
  source line identification. (Note that even without EIKI\_NO\_BINUTILS
  defined, Eiki will still function correctly if these utilities are not
  available; however, symbol resolution will not be possible on
  statically-linked binaries, source line information will not be available,
  and C++ names will not be demangled.)

- If EIKI\_SRC\_PATHNAMES is defined, `addr2line(1)` will be asked to
  provide full source pathnames rather than just filenames.

- If EIKI\_NO\_STACK\_TRACE\_DEMANGLE is defined, `eiki_get_stack_trace()` will
  not perform C++ name demangling on function names.

- If EIKI\_NO\_SIGNAL\_STACK is defined, `eiki_install_signal_handler()` will
  not configure an alternate stack for `eiki_signal_handler()`, which means
  that stack overflows cannot be handled.

- If EIKI\_SIGNAL\_HANDLER\_DEBUGGER is defined, `eiki_signal_handler()` will
  attempt to drop into a debugger before aborting, provided that standard input
  is a tty and Eiki does not detect an existing debugger.

- EIKI\_PRINT\_STACK\_FRAMES defines the maximum number of stack frames that
  will be shown by `eiki_print_stack_trace()`. The default is 64.

- EIKI\_ADDR2LINE\_PATH and EIKI\_CXXFILT\_PATH define the pathnames of
  `addr2line(1)` and `c++filt(1)` respectively, and default to
  EIKI\_BINUTILS\_DIR + "addr2line" and EIKI\_BINUTILS\_DIR + "c++filt", where
  EIKI\_BINUTILS\_DIR defaults to "/usr/bin/".

- EIKI\_DEBUGGER\_PATH defines the pathname of the debugger invoked by
  `eiki_attach_debugger()`. Defaults to "/usr/bin/gdb" (`gdb(1)`).

Stack Traces
------------

Stack traces may provide the following information for each frame (in the
absence of memory exhaustion, and provided `backtrace(3)` and
`backtrace_symbols_fd(3)` are functioning correctly):

- Return address. This is always available.

- Binary module name. This is available if the binary is not linked with
  `-static`.

- Function name. This is available if:

  - The binary is not linked with `-static` and is linked with `-rdynamic`; or

  - `addr2line(1)` is available.

  In addition, C++ function names will be demangled if `c++filt(1)` is
  available.

- Offset of the return address within the function. This is available if the
  binary is not linked with `-static` and is linked with `-rdynamic`.

- Source filename and line number. This is available if the source file is
  compiled with `-g` and `addr2line(1)` is available.

License and Third-Party Notices
===============================

Eiki is provided under the MIT license:

> Copyright (C) 2012-2013 Jamie Liu
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the “Software”), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

EIKI\_GDB\_IF\_TTY and `eiki_gdb` were implemented by Chris Fallin
(https://github.com/cfallin/).

