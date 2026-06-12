# Discovering how to make a NULL UnsafePointer in this Mojo nightly.
from std.memory import UnsafePointer
def main():
    # Maybe a static factory?
    var p1 = UnsafePointer[UInt8]()  # empty parens
    print("p1:", Int(p1))
