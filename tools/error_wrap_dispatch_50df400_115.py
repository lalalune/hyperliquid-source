"""Model of node #115 routine 0x50df400: the error-wrap
dispatch.

The routine (FDE 0x50df400..0x50df4b6, 182 bytes) is the
callee the merged loader-checkpoint packet
(RE-017-loader-checkpoint-result-115) named twice from the
caller side -- compact_binary_error_wrap at 0x50ddc6a and
expanded_binary_error_wrap at 0x50dedca both call it -- but
left as a boundary ("the callee body is not pinned"), and
the merged curl-body-helper packet (RE-012) passed a
three-word descriptor to it while recording "Error/result
enum names are unknown". This model pins the routine's own
instructions end to end.

Signature: the routine takes rdi = an opaque pointer (never
dereferenced, only stored into the descriptor below) and
rsi = a pointer to a 24-byte value V:

    V +0x00  tag word (the discriminant carrier)
    V +0x08  payload word A
    V +0x10  payload word B

What the routine does, in its own instruction order:

  1. It builds a 32-byte descriptor on its stack:
       D +0x00 = the rdi argument, verbatim
       D +0x08 = 0x5616320 (a 19-byte thunk, FDE
                 0x5616320..0x5616333, that re-packs a
                 two-word environment and tail-jumps through
                 the GOT slot 0x64df520, resolved by an
                 R_X86_64_RELATIVE record to 0x1681da0)
       D +0x10 = the rsi argument (the value pointer)
       D +0x18 = the qword loaded from the GOT slot
                 0x64e0a48, resolved by an R_X86_64_RELATIVE
                 record to 0x5c3f000 (an FDE start,
                 0x5c3f000..0x5c3f100)
     and calls the wrap callee 0x5101070 (FDE
     0x5101070..0x51010aa, 58 bytes) once, with
     rdi = 0x44e417 (a .rodata address inside the binary's
     string-fragment table) and rsi = the descriptor
     address. The callee's body is by contract only here
     (below); the routine returns the callee's rax on every
     non-exception path.
  2. It loads the tag word T = [V +0x00] (after the call)
     and computes an effective discriminant:
       disc = T XOR 0x8000000000000000   if T, read as a
                                          signed qword, is
                                          negative (top bit
                                          set)
       disc = 4                          otherwise
  3. If 1 <= disc <= 3 (tested as (disc - 1) < 3,
     unsigned), it returns the wrap result at once: the
     value's payload words are not read and nothing is
     dropped.
  4. If disc == 0 (which forces T == 0x8000000000000000),
     it calls the drop callee 0x50f0580 (FDE
     0x50f0580..0x50f064e, 206 bytes) with rdi = the
     payload word B ([V +0x10], passed by value), then
     returns the wrap result.
  5. On the remaining slow path (disc == 4 or disc >= 5):
     if T == 0 it returns the wrap result with no drop.
     Otherwise it calls the function pointer stored in
     the GOT slot 0x64df4a0 -- resolved by an
     R_X86_64_RELATIVE record to 0x635de30 (FDE
     0x635de30..0x635ded5, 165 bytes) -- with
     rdi = payload word A ([V +0x08], by value),
     rsi = T (the tag word, still in rsi from step 2) and
     rdx = 0, then returns the wrap result.

The routine writes nothing outside its own stack frame: the
value V, the rdi pointee and the descriptor's two function
words are read (or stored into the frame) but never written
through. It has no loop; every path makes the wrap call,
then at most one drop call.

Exception exit: the block at 0x50df49d..0x50df4b6 is the
FDE's landing pad (no direct branch in the body targets
it). It saves the exception pointer in r14, calls the
cleanup callee 0x50f0690 (FDE 0x50f0690..0x50f06d6, 70
bytes) on the value pointer -- that callee opens with the
same tag/discriminant computation as step 2 and is the
value's full destructor -- then calls _Unwind_Resume
through the PLT at 0x63f0a50, and ends with a call through
the GOT slot 0x64df4c0, resolved by an R_X86_64_RELATIVE
record to the 20-byte message stub at 0x1680cab (FDE
0x1680cab..0x1680cbf), reachable only if _Unwind_Resume
returns. The only call in the body that can throw is the
wrap call (the two drop calls run after it, on the return
path the pad does not cover). Exception behaviour is
pinned at this level only; the model and the packet
differential cover non-throwing runs.

Callee contracts (bodies not claimed by this packet):
  * wrap(desc_id, descriptor) -> result: called exactly
    once, with desc_id = 0x44e417 and the descriptor built
    in step 1; its return value is the routine's return
    value on every non-exception path.
  * drop_b(word_b): called only on the disc == 0 path,
    with the payload word B as its sole argument.
  * drop_tagged(word_a, tag, 0): called only on the slow
    path with T != 0, with the payload word A, the tag
    word and a zero third argument, through the GOT
    function pointer above.

Memory interface: `mem` is a bytearray addressed by
absolute address minus MEM_BASE (MEM_BASE = 0 in the
model's own coordinate system; callers translate). The
three callees are supplied as one `env` object with
wrap/drop_b/drop_tagged callables, so the tests and the
differential answer them with recording stubs.
"""

DESCRIPTOR_ID = 0x44E417
DESCRIPTOR_THUNK = 0x5616320
DESCRIPTOR_FN = 0x5C3F000

SIGN_BIT = 0x8000000000000000
MASK64 = 0xFFFFFFFFFFFFFFFF


def _rd64(mem, addr):
    return int.from_bytes(mem[addr:addr + 8], "little")


def discriminant(tag):
    """The routine's effective discriminant for a tag word:
    the tag with its sign bit flipped when the tag is
    negative as a signed qword, else the constant 4."""
    if tag & SIGN_BIT:
        return tag ^ SIGN_BIT
    return 4


def build_descriptor(out, value):
    """The 32-byte stack descriptor the routine passes to
    the wrap callee, as a tuple of four qwords."""
    return (out & MASK64, DESCRIPTOR_THUNK, value & MASK64,
            DESCRIPTOR_FN)


def error_wrap(mem, out, value, env):
    """Run the error-wrap dispatch 0x50df400 against the
    model memory.

    `out` is the rdi argument (stored into the descriptor,
    never dereferenced), `value` is the address of the
    24-byte value. `env.wrap(desc_id, descriptor)` is
    called once and its return value is returned on every
    path; `env.drop_b(word_b)` and
    `env.drop_tagged(word_a, tag, 0)` are the conditional
    drop calls. Only non-throwing runs are modelled.
    """
    result = env.wrap(DESCRIPTOR_ID, build_descriptor(out, value))
    tag = _rd64(mem, value)
    disc = discriminant(tag)
    if (disc - 1) & MASK64 < 3:
        return result
    if disc == 0:
        env.drop_b(_rd64(mem, value + 0x10))
        return result
    if tag == 0:
        return result
    env.drop_tagged(_rd64(mem, value + 0x08), tag, 0)
    return result
