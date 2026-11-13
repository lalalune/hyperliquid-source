"""Behavioural model of node #115 routine 0x143ddc0.

The model lives inside this evidence packet (not under tools/) because
it describes only what the bytes in the FDE range
0x143ddc0..0x143ddf2 do, nothing more. It is a direct transcription of
the disassembly in main.txt:

    143ddc0  mov    %rsi,%rax            ; rax = arg2 (the sink pointer)
    143ddc3  cmpb   $0x0,(%rdi)          ; read one byte at *arg1 (a bool)
    143ddc6  je     143dddd              ; byte == 0 -> "false" path
    143ddc8  lea    0x459fd8,%rsi        ; &"true"  (.rodata)
    143ddcf  mov    $0x4,%edx            ; length 4
    143ddd4  mov    %rax,%rdi            ; rdi = the sink pointer
    143ddd7  jmp    *0x64df720           ; tail-call through the .got slot
    143dddd  lea    0x479247,%rsi        ; &"false" (.rodata)
    143dde4  mov    $0x5,%edx            ; length 5
    143dde9  mov    %rax,%rdi            ; rdi = the sink pointer
    143ddec  jmp    *0x64df720           ; tail-call through the .got slot

Observed facts the model encodes:

  * Exactly one memory read inside the routine's own body: a single
    byte at (%rdi), the caller-provided pointer in arg1. It is compared
    against 0 with `cmpb`, so only the low 8 bits decide the branch.
    The routine writes nothing.
  * The routine never dereferences either string pointer. It only
    computes the two fixed .rodata addresses with `lea` and hands one
    of them, with its length, to the tail-callee; the string bytes are
    read by that callee, not here.
  * The branch is a two-way select with no fall-through merge: the
    zero byte selects (&"false", 5) and any non-zero byte selects
    (&"true", 4). Each arm moves the saved arg2 into rdi and tail-jumps
    indirectly through the same .got slot 0x64df720. There is no `ret`
    and no direct call anywhere in the body.
  * The lengths are literal immediates (4 and 5) that equal the byte
    lengths of the strings the arms point at; the routine itself does
    not compute them from the strings.

The tail-callee (the routine whose pointer the loader installs into the
.got slot, addend 0x167fa70) and the meaning of the sink pointer are
NOT modelled or claimed here. The model reports only the arm selected
and the (string address, length) pair passed on.
"""

TRUE_PTR = 0x459FD8       # &"true"  in .rodata, passed on the non-zero arm
FALSE_PTR = 0x479247      # &"false" in .rodata, passed on the zero arm
TRUE_LEN = 4              # immediate moved into edx on the non-zero arm
FALSE_LEN = 5             # immediate moved into edx on the zero arm
TAIL_SLOT = 0x64DF720     # .got slot both arms tail-jump through


def shim(bool_byte):
    """Return (string_ptr, length, tail_slot) exactly as 0x143ddc0 would.

    bool_byte is the raw byte value at (%rdi); only its low 8 bits are
    consulted (the routine uses `cmpb`). A zero byte selects "false";
    any non-zero byte selects "true". The returned tail_slot is the
    fixed .got slot both arms jump through.
    """
    if (bool_byte & 0xFF) == 0:
        return (FALSE_PTR, FALSE_LEN, TAIL_SLOT)
    return (TRUE_PTR, TRUE_LEN, TAIL_SLOT)


def self_test():
    """Enumerated checks; raises AssertionError on any mismatch.

    Returns the number of assertions performed.
    """
    n = 0

    def check(byte, expected):
        nonlocal n
        got = shim(byte)
        assert got == expected, "shim(%#x) -> %r, expected %r" % (
            byte, got, expected)
        n += 1

    # Zero byte -> "false" arm.
    check(0x00, (FALSE_PTR, FALSE_LEN, TAIL_SLOT))
    check(0x100, (FALSE_PTR, FALSE_LEN, TAIL_SLOT))   # low byte 0 -> false
    # Any non-zero low byte -> "true" arm (bool is canonically 1, but the
    # compare is against 0, so every non-zero byte takes the true arm).
    check(0x01, (TRUE_PTR, TRUE_LEN, TAIL_SLOT))
    check(0xFF, (TRUE_PTR, TRUE_LEN, TAIL_SLOT))
    check(0x101, (TRUE_PTR, TRUE_LEN, TAIL_SLOT))     # low byte 1 -> true
    check(0x02, (TRUE_PTR, TRUE_LEN, TAIL_SLOT))      # non-canonical, still true
    # The two arms share one tail slot and never swap their constants.
    assert shim(0)[0] != shim(1)[0]
    n += 1
    assert shim(0)[2] == shim(1)[2] == TAIL_SLOT
    n += 1
    return n


if __name__ == "__main__":
    count = self_test()
    print("model self-test OK (%d assertions)" % count)
