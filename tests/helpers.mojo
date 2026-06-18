# Test assertion shared across all socket-mojo tests.
#
# Returns 0 on pass, 1 on fail (prints a marker on fail). Each test
# `run() raises -> Int` sums these to produce a failure count;
# tests/run_tests.mojo sums the per-file counts to report total
# failures. Tests don't stop on the first failure — every check
# runs so you see the full picture.


def check(cond: Bool, name: String) -> Int:
    if not cond:
        print("FAIL:", name)
        return 1
    return 0
