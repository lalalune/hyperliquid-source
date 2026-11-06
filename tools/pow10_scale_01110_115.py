"""Model of node #115 routine 0x5a01110: checked power-of-ten
scale select.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes three arguments: an object pointer in rdi, a
value in rsi, and a reference in rdx. It returns one power of
ten in rax. End to end, in order:

1. Scale cascade on the reference (rdx). The result is
   10 ** max(0, digits - 5), where digits is the decimal digit
   count of the reference (the reference 0 yields 1). The binary
   computes it with a literal cascade: direct compares against
   10**5 .. 10**9, shift-based band checks for 10**10 .. 10**13
   (the value shifted right by 10..13 compared against
   9765625, 48828125, 244140625, 1220703125), compares against
   10**14 - 1 and 10**15 - 1 whose successor values are taken
   with an increment, and direct compares against 10**16 ..
   10**19 where the 10**18 band reuses the 10**14 - 1 constant
   through a cmovb before the same increment. pow10_scale()
   below transcribes that cascade instruction by instruction;
   the tests prove it equal to the closed form on every band
   boundary and on random inputs.

2. Checked decomposition of the value (rsi). The binary divides
   the value by 10000 with the magic multiplier
   0x346dc5d63886594b: the quotient is the 128-bit product
   shifted right by 75, the remainder is value - quotient*10000.
   It then compares the quotient against the qword at object
   +0x50 and the remainder against the qword at object +0x10:
   - if the quotient differs from *(object +0x50), or the
     remainder is not strictly below *(object +0x10), the
     routine calls the panic shim at 0x1680c10 (reached through
     the relocated slot at 0x64df830) with rdi pointing at the
     static location record at 0x64768a8. That shim panics with
     the message "called `Option::unwrap()` on a `None` value"
     at l1/src/perp_meta.rs:163:38 and never returns.
   The model raises Panic with that message and location.

3. Table byte. Only on the checked path, the binary reads the
   byte at *(object +0x8) + remainder*32 + 0x1d: a table of
   32-byte entries indexed by the remainder, the byte at offset
   0x1d of the entry. If that byte is 7 or more, the routine
   calls the panic shim at 0x1681e40 (through the relocated
   slot at 0x64df848) with rdi pointing at the static location
   record at 0x6478258. That shim panics with the message
   "attempt to subtract with overflow" at
   l1/src/perp_meta.rs:287:28 and never returns. The model
   raises Panic with that message and location.

4. Result. With the byte b in 0..6, the binary computes
   10 ** (6 - b) by exponentiation by squaring over the bits of
   6 - b (x10 for bit 0, x100 for bit 1, x10000 for bit 2, with
   early exits) and returns min(cascade, 10 ** (6 - b)): the
   final combine is a cmovb after cmp cascade-candidate, which
   keeps the smaller of the two powers.

NOT modelled: what the object, its table, or its fields denote
beyond the pinned offsets; what the callers do with the result;
the panic runtime past the two shims' pinned entry behaviour
(the unwrap shim forwards through 0x1680e60, which rewrites the
message length len -> 2*len + 1 before calling the payload
builder at 0x1680e80; the subtract-overflow shim passes the
pre-encoded length 2*33 + 1 = 67 for its 33-byte message
directly). A null object pointer or a table pointer that does
not cover the remainder's entry faults in the binary on the
same reads; the model takes the table byte through a caller
supplied lookup and does not invent table contents.
"""

ROUTINE = 0x5A01110
ROUTINE_FDE = (0x5A01110, 0x5A0130B)
ROUTINE_SIZE = 507

TABLE_POINTER_OFFSET = 0x8
BOUND_OFFSET = 0x10
QUOTIENT_OFFSET = 0x50
ENTRY_STRIDE = 32
BYTE_OFFSET = 0x1D

DIVISOR = 10000
DIV_MAGIC = 0x346DC5D63886594B
DIV_SHIFT = 75

UNWRAP_SLOT = 0x64DF830
UNWRAP_SHIM = 0x1680C10
UNWRAP_ENCODE_SLOT = 0x64DF730
UNWRAP_ENCODE = 0x1680E60
UNWIND_BUILDER = 0x1680E80
UNWIND_SLOT = 0x64DF6B8
UNWRAP_LOCATION_RECORD = 0x64768A8
UNWRAP_MESSAGE_ADDRESS = 0x46E992
UNWRAP_MESSAGE = "called `Option::unwrap()` on a `None` value"
UNWRAP_FILE = "l1/src/perp_meta.rs"
UNWRAP_LINE = 163
UNWRAP_COL = 38

SUB_SLOT = 0x64DF848
SUB_SHIM = 0x1681E40
SUB_LOCATION_RECORD = 0x6478258
SUB_MESSAGE_ADDRESS = 0x46EB80
SUB_MESSAGE = "attempt to subtract with overflow"
SUB_FILE = "l1/src/perp_meta.rs"
SUB_LINE = 287
SUB_COL = 28

FILE_STRING_ADDRESS = 0x437DF7

MASK64 = 0xFFFFFFFFFFFFFFFF


class Panic(Exception):
    """A non-returning panic exit of the routine. Carries the
    pinned message and the source location the binary passes."""

    def __init__(self, message, file, line, col):
        super().__init__(message)
        self.message = message
        self.file = file
        self.line = line
        self.col = col


def pow10_scale(reference):
    """Transcription of the cascade at 0x5a01110..0x5a01263.

    Returns 10 ** max(0, digits - 5) for the decimal digit count
    of reference; the tests prove the closed form against this
    transcription. All arithmetic is on unsigned 64-bit values.
    """
    x = reference & MASK64
    ecx = 1
    if x < 100000:
        return ecx
    ecx = 10
    if x < 1000000:
        return ecx
    ecx = 100
    if x < 10000000:
        return ecx
    ecx = 1000
    if x < 100000000:
        return ecx
    ecx = 10000
    if x < 1000000000:
        return ecx
    rax = x >> 10
    ecx = 100000
    if rax < 9765625:
        return ecx
    rax = x >> 11
    ecx = 1000000
    if rax < 48828125:
        return ecx
    rax = x >> 12
    ecx = 10000000
    if rax < 244140625:
        return ecx
    rax = x >> 13
    ecx = 100000000
    if rax < 1220703125:
        return ecx
    rax = 99999999999999  # 0x5af3107a3fff = 10**14 - 1
    ecx = 1000000000
    if x <= rax:
        return ecx
    rcx = 999999999999999  # 0x38d7ea4c67fff = 10**15 - 1
    if x <= rcx:
        return 9999999999 + 1  # 0x2540be3ff + 1 = 10**10
    if x < 10000000000000000:  # 0x2386f26fc10000 = 10**16
        return 99999999999 + 1  # 0x174876e7ff + 1 = 10**11
    if x < 100000000000000000:  # 0x16345785d8a0000 = 10**17
        return 999999999999 + 1  # 0xe8d4a50fff + 1 = 10**12
    if x < 1000000000000000000:  # 0xde0b6b3a7640000 = 10**18
        return 9999999999999 + 1  # 0x9184e729fff + 1 = 10**13
    if x < 10000000000000000000:  # 0x8ac7230489e80000 = 10**19
        rcx = rax  # cmovb: rcx = 10**14 - 1
    return rcx + 1


def pow10_scale_closed(reference):
    """Closed form of pow10_scale: 10 ** max(0, digits - 5)."""
    x = reference & MASK64
    digits = len(str(x))
    return 10 ** max(0, digits - 5)


def divmod_10000(value):
    """The binary's magic division by 10000: the quotient is
    (value * 0x346dc5d63886594b) >> 75 over the 128-bit product,
    the remainder is value - quotient * 10000."""
    x = value & MASK64
    quotient = (x * DIV_MAGIC) >> DIV_SHIFT
    return quotient, x - quotient * DIVISOR


class ScaleObject:
    """The routine's object, folded to the three things the
    binary reads: the expected quotient at +0x50, the remainder
    bound at +0x10, and a table-byte lookup standing in for the
    table pointer at +0x8 (entry stride 32, byte at +0x1d). The
    lookup is only consulted on the checked path, exactly like
    the binary's read."""

    def __init__(self, quotient, bound, table_byte):
        self.quotient = quotient & MASK64
        self.bound = bound & MASK64
        self.table_byte = table_byte


def pow10_scale_select(obj, value, reference):
    """Run the pinned behaviour. Returns the selected power of
    ten, or raises Panic on either non-returning exit."""
    if obj is None:
        raise ValueError("null object pointer")
    quotient, remainder = divmod_10000(value)
    if quotient != obj.quotient or remainder >= obj.bound:
        raise Panic(UNWRAP_MESSAGE, UNWRAP_FILE, UNWRAP_LINE,
                    UNWRAP_COL)
    byte = obj.table_byte(remainder) & 0xFF
    if byte >= 7:
        raise Panic(SUB_MESSAGE, SUB_FILE, SUB_LINE, SUB_COL)
    return min(pow10_scale(reference), 10 ** (6 - byte))
