"""Model of node #115 routine 0x60d4f70: the guarded
mem-mapping release.

The routine (FDE 0x60d4f70..0x60d4f91, 33 bytes) is the
callee the merged destructor-pair packet
(RE-001-destructor-pair-115, PR #2133) called the
"element destroy" and cited by contract only, listing
"the internals of the element destroy 0x60d4f70" among
its unknowns. This model pins the routine's own
instructions end to end.

Signature: rdi = a pointer to a 16-byte pair:

    pair +0x00  mapping pointer (ptr)
    pair +0x08  mapping length in bytes (length)

What the routine does, in its own instruction order:

  1. It loads ptr = [pair +0x00]. If ptr == 0 it returns
     at once: the +0x08 word is never read, no call is
     made, and rax holds 0 (the loaded pointer) on return.
  2. Otherwise it loads length = [pair +0x08], moves ptr
     into rdi and length into rsi, and tail-jumps to
     munmap through the PLT stub at 0x63f0c00 (GOT slot
     0x64ee250, R_X86_64_JUMP_SLOT munmap@GLIBC_2.2.5).
     munmap's return value reaches the caller in rax
     unchanged; the routine adds no instruction of its
     own after the jump.

The routine writes no memory at all: the pair is not
zeroed, stored into or otherwise modified on either
path (the move-assignment caller at 0x60d4fb5 zeroes
its source pair itself, after calling). It has no
stack frame, no stack canary, no LSDA and no landing
pad; the only external transfer is the munmap tail
jump. The pair pointer itself is never null at any
census call site (every caller passes an object member
or a walking array pointer); the routine would fault
on a null pair pointer, which is outside its contract.

Identity (provenance only, not claimed from this
packet's own evidence): the RE-002 vendor census
identifies this FDE as rocksdb::MemMapping's
destructor (librocksdb-sys 0.11.0+8.1.1, published-
crate rebuild match 30/33) -- a {pointer, length}
mapping descriptor whose destructor unmaps a non-null
mapping, which is exactly the layout and behaviour
pinned here from the binary.

Census (this packet): 11 direct call sites, no tail
jumps, no stored-qword or RELATIVE-addend references
to the window start anywhere in the file. The sites
sit in five containing FDEs; see the packet's
callers.tsv for the site-by-site argument setup.

Callee contract (body not claimed by this packet):
  * munmap(ptr, length): called at most once, only on
    the non-null path, as a tail jump, with the pair's
    two words as its arguments; its return value is
    the routine's rax on that path. Every census call
    site ignores rax (the routine is void at source
    level).

Memory interface: `mem` is a bytearray addressed by
absolute address minus MEM_BASE (MEM_BASE = 0 in the
model's own coordinate system; callers translate).
The callee is supplied as an `env` object with a
munmap(ptr, length) callable, so the tests and the
differential answer it with a recording stub.
"""


def _rd64(mem, addr):
    return int.from_bytes(mem[addr:addr + 8], "little")


def mem_mapping_release(mem, pair, env):
    """Run the guarded mem-mapping release 0x60d4f70
    against the model memory.

    `pair` is the address of the 16-byte {ptr, length}
    pair. On the null-pointer path no callee runs and
    the result is 0; on the non-null path
    `env.munmap(ptr, length)` runs once as a tail call
    and its return value is the result. The model
    writes no memory, mirroring the routine.
    """
    ptr = _rd64(mem, pair)
    if ptr == 0:
        return 0
    length = _rd64(mem, pair + 0x08)
    return env.munmap(ptr, length)
