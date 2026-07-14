# Repository Guidelines

## Project Structure & Module Organization

chibicc is a small C11 compiler organized by compilation stage. Top-level C files implement the compiler: `tokenize.c`, `preprocess.c`, `parse.c`, `type.c`, and `codegen.c`; `main.c` provides the driver, while `chibicc.h` contains shared declarations. Built-in headers live in `include/`. Feature tests are individual `test/*.c` programs, driver behavior is exercised by `test/driver.sh`, and larger compatibility checks live under `test/thirdparty/`. `helper/trace_malloc.c` provides allocation-tracing support. Generated binaries, objects, and `stage2/` output should not be committed.

## Build, Test, and Development Commands

- `make` builds the `chibicc` executable with the system C compiler.
- `make test` compiles and runs all feature tests, then runs compiler-driver checks.
- `make test-stage2` rebuilds chibicc with itself and tests that self-hosted compiler.
- `make test-all` runs both stage 1 and stage 2 suites; use this before submitting changes.
- `make clean` removes generated executables, objects, temporary files, and stage 2 output.

For a quick manual check, run `./chibicc -Iinclude -S example.c` after building.

## Coding Style & Naming Conventions

Write straightforward C11 that favors readability over abstraction. Follow existing formatting: two-space indentation, braces on the same line as function or control declarations, `snake_case` for functions and variables, and uppercase names for enum constants and macros. Keep functions focused, but tolerate small duplication when it makes compiler grammar or control flow easier to follow. There is no configured formatter or linter; compile warnings from the Makefile (`-Wall`) are the primary static check.

## Testing Guidelines

Add regression coverage to the closest feature file, such as `test/struct.c` or `test/macro.c`. Tests generally use `ASSERT(expected, expression)` from `test/test.h` and print `OK` on success. Add command-line and file-output behavior to `test/driver.sh`. Run `make test-all`; no numeric coverage threshold is defined.

## Commit & Pull Request Guidelines

Recent commits use short, imperative subjects such as `Add malloc test` or `Update README`. Keep each commit narrowly focused and explain behavior changes in the body when needed. Pull requests should describe the bug or feature, include a minimal reproducer, and identify the added tests. Note that upstream treats history as book material: maintainers may rewrite earlier commits and reimplement submitted patches, and force-pushes can require manual rebasing.
