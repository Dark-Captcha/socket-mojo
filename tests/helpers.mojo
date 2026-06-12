# Test assertions shared across all socket-mojo tests.

def check(cond: Bool, name: String) raises:
    if not cond:
        raise Error("FAIL: " + name)


def check_eq[T: EqualityComparable & Stringable](got: T, want: T, name: String) raises:
    if got != want:
        raise Error("FAIL: " + name + " got " + String(got) + " want " + String(want))
