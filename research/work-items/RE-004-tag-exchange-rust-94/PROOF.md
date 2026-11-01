# Atomic byte exchange, normalization and full register values

Target: node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete leaf is `[0x4f7fb20,0x4f7fb38)`, 24 bytes and nine
instructions. Eight following INT3 bytes are padding. Its memory-form
XCHG is part of the relation: an ordinary load followed by an ordinary
store would not preserve the original indivisible exchange.

## Complete operation

Let I be incoming RSI and O incoming RDI. Define the selected byte and
numeric field address by

```
t = I mod256
v = 0 if t=0, 2 if t=2, otherwise 1
A = (O+16) mod2^64
```

The leaf atomically exchanges v with the byte at A. Let p be the value
replaced by that exchange, at the exchange's position in the memory
modification order. The full returned data-register relation is

```
RAX = zero_extend8(p)
RCX = 0
```

The exchanged-in value is v. Under interference, another operation can
replace it before the call returns; neither the native operation nor the
source promises that a later load still sees v. For an isolated call,
the final field value is v and all other data bytes are unchanged.

CMP SIL,2 and SETE AL make AL one exactly for t=2. INC AL changes that
to two for t=2 and one otherwise; it cannot overflow. XOR ECX,ECX clears
full RCX. TEST SIL,SIL sets ZF iff t=0. MOVZBL AL,EAX leaves the flags
unchanged and clears every higher RAX bit. CMOVE ECX,EAX therefore
selects zero for t=0, retaining one or two otherwise. That dword write
also clears high RAX. The XCHG exchanges only AL with the field byte,
so bits 8..63 of RAX remain zero while AL becomes arbitrary p in 0..255.
RCX remains zero. RET preserves these data registers.

Only the low tag byte matters, for all possible incoming RSI patterns.
Incoming RAX and RCX do not need API inputs because the preceding writes
fully remove their influence. RDI/RSI are not modified. Flags and RET's
RSP/control transition are outside the projection.

The actual bytes `86 47 10` select memory-form byte XCHG at RDI+16;
there is no explicit LOCK prefix. Intel specifies that a memory operand
automatically invokes the locking protocol for the exchange, independently
of that prefix. See [Intel SDM volume 2D, XCHG, pages 6-28–6-29](https://cdrdv2-public.intel.com/671143/334569-sdm-vol-2d.pdf).
The packet claims the atomic byte operation, not a recovered lock protocol,
application state machine or surrounding memory-order invariant.

## Safe source correspondence

`exchange(tag_bits, object, &AtomicU8)` represents the byte at the numeric
original field address with a supplied safe atomic cell. The Rust cell's
physical address is unrelated to the reported number. All u64 tag/object
values and every cell byte are admitted. The enum-free byte normalization
matches the three preimages above. One `AtomicU8::swap` performs the
read-modify-write, and widening its previous byte gives full RAX. The
reported RCX is zero and explicit wrapping addition gives A.

The source uses `Ordering::SeqCst`. Rust documents swap as storing a value
and returning its predecessor, and the ordering includes one total order
among sequentially consistent operations. The exact compiler-generation
reference is the [Rust 1.94.1 atomic implementation and API documentation](https://github.com/rust-lang/rust/blob/1.94.1/library/core/src/sync/atomic.rs).
This is a deliberate atomic source operation; separate atomic load/store
calls would still permit an intervening writer. The proof concerns this
one-byte exchange and histories of these exchanges. It does not assert
equivalence of arbitrary surrounding Rust and x86 memory-model behavior.

Original correspondence requires a valid ordinary read/write byte at A,
stable code and valid return control. The Rust side requires a valid
atomic cell and Rust's access discipline, excluding data races and
conflicting mixed-width accesses. Other threads using this API can share
the same cell. A different physical layout or numeric address that cannot
be mapped by the original process remains a mathematical input only.
Code/control aliases, MMIO, fault timing, other-memory synchronization,
flags, original ABI and whole-program concurrency are excluded. No unsafe
conversion of captured pointers or memory is performed.

The safe library has no allocation or fallible path. Its normalization
and widening cannot overflow, the address addition explicitly wraps, and
swap accepts SeqCst. The component requires a target supporting byte
atomic read-modify-write; the recorded host is aarch64-apple-darwin.
It is not a portability claim for targets lacking those operations.

## Static boundary and references

The verifier authenticates the entire 91,774,280-byte target, binds the
unique overlapping FDE and actual CIE, and checks all body/padding bytes.
GNU, LLVM and Capstone agree on all nine boundaries. There are no calls,
branches, RIP-relative references or outgoing dependencies.

All 36 entry-naming records are symbol-zero R_X86_64_RELATIVE entries
with actual raw-zero qwords in `.data.rel.ro`. Their exact records and
mappings are retained. The verifier scans all 80,300 RELA entries and
requires each slot to have exactly its expected eight-byte writer;
another addend or a partially overlapping writer is rejected too.
No relocation overlaps the complete body/padding. E8/E9 scans of `.text`
find no direct candidates. This says nothing about indirect callers,
short transfers, slot consumers or source-level pointer-table ownership.
The slots are entry-reference context, not data read by the leaf.

Twenty-one structural controls exercise byte predicates, zero extension,
the exchange opcode/displacement, padding, FDE/CIE and representative
first/middle/last relocation records and slots. These run below the
whole-target digest check; they are not claims of exhaustive corruption
testing. All 36 slots are checked on every successful static pass.

## Independent values, concurrency and compiler evidence

Before Rust existed, 76,240 isolated input/output records were frozen.
The oracle uses two predicate indicator values for the byte partition,
an abstract exchange pair and unbounded modular address arithmetic. It
does not run an atomic implementation or interpret target instructions.
All 65,536 pairs of low input byte and replaced byte are included, plus
ignored high tag bits, high old-byte bits and wrapped addresses.

Isolated value tuples cannot distinguish an atomic exchange from separate
load/store operations, or SeqCst from a weaker ordering. The qualification
therefore treats these as separate obligations rather than reporting
those mutations as detected by the value corpus. The final optimized LLVM
IR, emitted from the exact library source with `link-dead-code=yes` so its
public function remains materialized, must contain one byte `atomicrmw
xchg` with SeqCst ordering and no separate atomic load/store or cmpxchg.
Compiled weakened-order and split-load/store controls retain the same
isolated values but fail that explicit IR requirement. This qualifies
the recorded source/compiler IR, not captured x86 bytes or a different
compiler's generated code.

A separate host test runs 64 three-thread rounds per optimization. Each
round starts from byte 129 and exchanges distinct values 0,1,2 after a
barrier. The three returned old bytes and post-join final byte must match
one of the six complete exchange orders. The expected histories come
from permutations of indivisible updates, not scheduled instruction
execution. This is finite concurrent qualification, not an exhaustive
scheduler or weak-memory proof. The atomic operation's API contract and
the instruction-level exchange establish the bounded correspondence.

No source-level identity, field/tag meaning, original compiled-byte
identity, whole-node equivalence or completed component gate is claimed.
