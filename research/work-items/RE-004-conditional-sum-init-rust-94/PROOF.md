# Complete signed-low32 initializer

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete selected FDE is `[0x5475e80,0x5475ead)`,45 bytes/11 instructions.
Three following INT3 bytes are separate padding. No field meaning, source type,
constructor identity or application protocol is inferred from this leaf.

## Instruction relation and eliminated redundant choice

Let N=2^64, X be entry RSI, Y entry RDX, and D entry RDI. Let
`u=Y mod 2^32` and `s=u` when u<2^31, otherwise `s=u-2^32`.
MOVSXD RAX,EDX writes the full sign extension `(s mod N)` into RAX. It does
not modify RDX. The first two stores write qword0 at D and `(s mod N)` at D+24.
ADD RAX,RSI computes `t=(X+s) mod N`.

TEST EDX,EDX and CMOVNE RSI,RAX update RSI to t exactly when u!=0. When u=0,
s=0, hence t=X and preserving RSI yields the same t. Thus **for every raw
64-bit Y**, final RSI is t; no input-dependent branch is required in the
reconstructed value relation. High32 Y bits neither affect sign extension
nor the TEST, but all64 Y bits remain unchanged in RDX. This simplification
does not claim a different target instruction sequence or original compiler.

The remaining stores write qword0 at D+16 and final RSI=t at D+8. MOV EAX,1
zero-extends, making full final RAX=1. The complete four little-endian output
qwords in address order are `[0,t,0,s mod N]`. Full observed registers are
RAX=1, RSI=t, RDX=Y; RDI remains D and every other non-control GP register is
untouched. Original flags, native register allocation, stack and return state
are outside the safe result structure.

All inputs are values in registers, not memory fields. There are no data reads,
calls, imports, static constants in memory, or value restrictions such as a
nonnegative EDX or bounded RSI. The actual store order is0,24,16,8; the four
disjoint eight-byte fields cover the admitted32-byte output exactly. With
ordinary stable memory and no intervening read, their final values are identical
to writing the four qwords in address order. This is a final-state relation,
not an MMIO, concurrent-observer or partial-fault store-order claim.

## Safe image and all-input arithmetic

The image covers `[base,base+len)` with mathematical endpoint at most N. The
API requires one complete nonwrapping32-byte destination span inside it;
unaligned destinations and an endpoint exactly equal to the image end are
admitted. No prior output bytes need any particular value. Bytes outside the
32-byte span are unchanged. Numeric D is never converted to a host pointer.

The global interval check widens to u128. Checked D-base, usize conversion,
and checked offset+32 establish every later slice. An invalid mapping/span
returns None without modifying any byte. None is a new safe refusal, not an
original return or exception trace. Correspondence applies to successful
ordinary writes and valid normal return/control state disjoint from output
storage. It excludes wrapped output layouts, invalid accesses, MMIO, races,
control-stack aliases, native ABI and original partial faults. The pure input
arithmetic nevertheless accepts every RSI/RDX bit pattern.

Rust's `Y as u32 as i32 as i64 as u64` first discards high32 bits, interprets
the remaining sign bit, extends that sign to64bits, then gives its modulo-N
unsigned representation. `X.wrapping_add(extended)` is precisely t. No signed
overflow is evaluated, and explicit wrapping is independent of checked-overflow
profile. The four u64 values are serialized with fixed-width little-endian
encoding. The implementation contains no unsafe code, allocation, dependencies,
pointer dereference or data-derived index. The full RDX value is retained
separately and is not accidentally replaced with its low dword/sign extension.

## Static closure and independent expectations

The full unique FDE/CIE, body and padding are bound with GNU/LLVM/Capstone byte
partitions. Every direct E8/E9 candidate is checked at a decoded boundary in
its complete caller FDE; callers' surrounding behavior is context only. All
RELA records are checked for entry naming and code writers. No outgoing helper,
static-data or opaque dependency exists. This is not a complete indirect-xref
census or an original source identity claim.

Before Rust, the oracle used unsigned remainder plus subtraction for signed32
interpretation, unbounded integer addition and final remainder for t, and an
immutable address dictionary with four byte patches. It does not call Rust,
decode/execute an instruction stream, or derive expectations from host results.
Fixtures cover all single-bit raw Y positions and complements, low32 sign
boundaries, high-only Y, RSI carry/wrap corners, every fixture destination offset,
exact ends, missing spans, global image overflow and arbitrary unchanged bytes.
All image bytes and full RAX/RSI/RDX are compared.

The instruction and arithmetic argument covers the entire admitted domain;
finite native cases support implementation/comparator qualification. Captured
execution, instruction emulation, original compiled-byte identity, whole-node
equivalence and component-gate completion remain unclaimed. Pins and imported
evidence remain unchanged.
