"""Behavioural model of node #115 routine 0x636c880.

The model lives inside this evidence packet (not under tools/) because
it describes only what the bytes in the FDE range 0x636c880..0x636c8b3
do, nothing more. It is a direct transcription of the disassembly in
main.txt:

    636c880  endbr64
    636c884  lea    0x6713606,%rax     ; gate byte A address (.bss)
    636c88b  cmpb   $0x0,(%rax)
    636c88e  je     636c8b0            ; A == 0  -> return NULL
    636c890  lea    0x6717690,%rdx     ; gate byte B address (.bss)
    636c897  cmpb   $0x1,(%rdx)
    636c89a  jne    636c8b0            ; B != 1  -> return NULL
    636c89c  cmp    $0x23,%rcx
    636c8a0  ja     636c8b0            ; (unsigned) rcx > 0x23 -> NULL
    636c8a2  lea    0x64ddc20,%rax     ; the constant base pointer
    636c8a9  ret                       ; return &0x64ddc20
    636c8b0  xor    %eax,%eax
    636c8b2  ret                       ; return NULL (0)

Observed facts the model encodes:

  * Exactly two one-byte reads of fixed .bss globals (gate A at
    0x6713606, gate B at 0x6717690) and one register input in rcx.
    Nothing is written; no call or jump leaves the routine.
  * The two gate comparisons are byte comparisons (cmpb), so only the
    low 8 bits of each gate value decide the branch. Gate A opens on
    any non-zero byte; gate B opens only on the exact byte value 1.
  * The index in rcx is bounds-checked as an UNSIGNED value against
    0x23 with `ja` (jump-if-above). Values 0..0x23 inclusive (36
    values) pass; everything else, including any value whose unsigned
    interpretation exceeds 0x23, fails.
  * When all three checks pass the routine returns the FIXED address
    0x64ddc20. The index is NEVER used to scale or offset the result:
    the returned pointer is the same constant for every in-range index.
    When any check fails the routine returns 0 (NULL).

BASE is the returned constant; NULL models the zero return. The caller's
interpretation of either return value is NOT modelled or claimed here.
"""

BASE = 0x64DDC20          # constant pointer returned when the gate is open
NULL = 0                  # the xor %eax,%eax return path
INDEX_MAX = 0x23          # inclusive unsigned upper bound on the rcx index
GATE_A_ADDR = 0x6713606   # .bss byte; routine returns NULL when it is 0
GATE_B_ADDR = 0x6717690   # .bss byte; routine returns NULL unless it is 1

_U64 = (1 << 64) - 1


def accessor(gate_a, gate_b, index):
    """Return BASE or NULL exactly as routine 0x636c880 would.

    gate_a, gate_b are the raw byte values at the two .bss globals;
    only their low 8 bits are consulted (the routine uses cmpb).
    index is the value in rcx, treated as an unsigned 64-bit integer
    (the routine uses `cmp`/`ja`).
    """
    if (gate_a & 0xFF) == 0:
        return NULL
    if (gate_b & 0xFF) != 1:
        return NULL
    if (index & _U64) > INDEX_MAX:
        return NULL
    return BASE


def self_test():
    """Enumerated checks; raises AssertionError on any mismatch.

    Returns the number of assertions performed.
    """
    n = 0

    def check(args, expected):
        nonlocal n
        got = accessor(*args)
        assert got == expected, "accessor%r -> %#x, expected %#x" % (
            args, got, expected)
        n += 1

    # Gate A closed -> NULL regardless of B and index.
    check((0, 1, 0), NULL)
    check((0, 1, 0x23), NULL)
    check((0, 2, 5), NULL)
    # Gate A open requires any non-zero low byte.
    check((1, 1, 0), BASE)
    check((0xFF, 1, 0), BASE)
    check((0x100, 1, 0), NULL)   # low byte 0 -> closed
    check((0x101, 1, 0), BASE)   # low byte 1 -> open
    # Gate B must be exactly byte value 1.
    check((1, 0, 0), NULL)
    check((1, 2, 0), NULL)
    check((1, 0xFF, 0), NULL)
    check((1, 0x101, 0), BASE)   # low byte 1 -> open
    check((1, 0x1, 0), BASE)
    # Index bound: unsigned <= 0x23 inclusive passes.
    check((1, 1, 0x23), BASE)
    check((1, 1, 0x24), NULL)
    check((1, 1, 0xFF), NULL)
    check((1, 1, _U64), NULL)    # 0xffff...ffff unsigned -> above 0x23
    # Result is the same constant for every in-range index.
    for i in range(0, INDEX_MAX + 1):
        check((1, 1, i), BASE)
    return n


if __name__ == "__main__":
    count = self_test()
    print("model self-test OK (%d assertions)" % count)
