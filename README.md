# the Dynamic Hierarchy-based C Unit Testing System

## Description

*dh_cuts* is a very unconventional unit testing library intended for use
in small, C based projects, like those developed at www.suckless.org.

## Design

If you have used other unit testing frameworks before, you might be
familiar with their hierarchical structuring of tests nested in test cases
nested in test suites.

The central idea behind *dh_cuts* is to replace this fixed hierarchy
with a naming hierarchy that is completely dynamic at runtime.
This is realized as follows:

When you want your code to enter a new nested level in the hierarchy,
you call `dh_push("<the name of the level>")`,
and when you want to leave it again, you call `dh_pop()`.

An example:

```c
#define DH_IMPLEMENT_HERE
#include "dh_cuts.h"

void test_the_flux_capacitor() {
    dh_push("flux capacitor");
    ...
    dh_assert(condition_1 == true);
    ...
    dh_push("turning some knobs");
        ...
        dh_assert(condition_2 == true);
        ...
    dh_pop();

    dh_pop();
}

void run_scifi_testsuite() {
    dh_push("sci-fi");
    test_the_flux_capacitor();
    dh_pop();
}

int main() {
    dh_init(stderr);
    run_scifi_testsuite();
}
```

Per default, if all asserts are passed, this program will print nothing.
But suppose the test fails because `condition_2` is false. In that case, dh_cuts
will print a trace of the part of the hierarchy where the error occurred:

```
└ sci-fi
․․└ flux capacitor
․․․․└ turning some knobs
․․․․․․└ triggered assert in line 013: condition_2 == true               ← FAIL
```

This system is great in terms of debuggability, because your tests can convey
as much diagnostic information via `dh_push()` as you see fit.
`dh_push()` even accepts the same formatted messages as `printf()`, so you can
insert things like iteration counts into the hierarchy, and they won't clutter
the output because they're only shown for asserts that fail:

```c
void monte_carlo_test() {
    dh_push("monte carlo");
    for (int n = 0; n < 1000000; n++) {
        dh_push("iteration %d", n);
        /* perform the n-th round of randomized testing */
        ...
        dh_pop();
    }
    dh_pop();
}
```

There are a handful of other features to *dh_cuts* that make it more practical:

- You can use the macro `dh_branch()` like this:
  ```c
  dh_branch(
      do_some_stuff();
      more *stuff = ...;
      ...
  )
  ```
  to sandbox the code in the parentheses, meaning if that code crashes,
  then code following the `dh_branch()` macro should still be able to execute.

- There's multiple different `dh_assert()` variations for convenience as
  well as `dh_throw()` to unconditionally fail with a custom error
  message.

- `dh_summarize()` can be used to print a one-line summary of executed
  vs failed checks.

- If you don't want the output to include fancy Unicode sequences, you
  can define `DH_OPTION_ASCII_ONLY` before including `dh_cuts.h`.

- The entire thing is just a tiny single header library, so you can
simply copy-paste it if you want, no dependency management neccessary.

## Rationale

I've tried multiple well-known C unit testing frameworks in the past,
but they all suffered from the same issues:

- They're quite large and complicated because they pack lots of
  features for huge projects with huge development teams.
  For small projects like mine (or pretty much any suckless project)
  most of the offered features are complete overkill.

- they force you to organize your tests into a fixed hierarchy of
  'test suite' > 'test case' > 'test' or the like.
  This is a bad fit for any project but those of one specific size class.

- they make debugging really hard, because they tend to manage the
  overall control flow themselves,
  spawning all sorts of threads and child processes, so that merely
  attaching a debugger can be a pain.

- they love to spam info logs, often making it difficult to see
  whether anything went wrong or not.
  On a side note, some of them have this absurd notion that failing a
  couple tests is not a big deal ?!
