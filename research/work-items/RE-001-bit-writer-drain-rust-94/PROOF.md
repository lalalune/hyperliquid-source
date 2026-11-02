# Relation and admitted memory domain

This proof concerns linked ELF VA `[0x5494050,0x54940d8)` in node #94,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Both complete decoder exports, target bytes, FDE records and call bindings are
in `static/`. “Drain” and field names are descriptive inferences, not recovered
source identities. No ordinary `0..16` counter invariant is assumed.

## Scalar relation

Let `c` be the signed interpretation of the dword at RDI+0x1734, `a` the
unsigned word at RDI+0x1730, `p` the unsigned qword at RDI+0x28, and `B` the
pointer at RDI+0x10. Let `L=a mod 256`, `H=floor(a/256)`, and `M=2^64`.
The load at 0x5494054 zero-extends the counter's 32 bits into RAX. The first
comparison is exactly `c == 16`. The following JLE uses **signed** comparison
with 7. These two tests partition all 2^32 possible counter bit patterns.

| Counter class | Ordered bytes | Final counter | Final accumulator | Final position | Raw RAX at RET |
|---|---|---|---|---|---|
| c <= 7 | none | c | a | p | c mod 2^32 |
| c == 16 | L, H | 0 | 0 | (p+2) mod M | 0 |
| c >= 8 and c != 16 | L | c-8 | H | (p+1) mod M | p |

The subtraction cannot signed-overflow in its actual branch: its input lies
in `[8,2^31-1]`. The accumulator operation is a logical **word** shift by 8;
it leaves H, including for a with bit 15 set. No carry enters either byte.
Both position increments are 64-bit LEAs and therefore wrap. RAX is an
observed register value, not a recovered source return type or calling ABI.
The 0x549408e alignment instruction lies inside the FDE but is unreachable
from the function entry: the preceding instruction is RET and both branches
target 0x5494090 or 0x549408d. There are no internal calls or static data reads.

## Ordered memory accesses and alias restriction

For the no-output path, only the counter is read. The one-byte path loads p,
a, B in that order; stores p+1; stores L at B+p; then performs memory read /
modify / writes on the counter and the accumulator, in that order. Thus a
byte store aliasing either field can alter subsequent arithmetic.

The two-byte path loads p, a, B; stores p+1; stores L at B+p; **reloads p,
loads the high accumulator byte, and reloads B**; stores p+1 again; stores
the loaded high byte at the newly computed destination; zeroes RAX; stores
zero to the word accumulator; stores zero to the dword counter. The first
byte store can therefore change the second position, high byte or pointer
when aliases are permitted. The native field layout is not flattened into
a universally valid snapshot claim.

The value projection assumes the four state fields have stable values and
that output stores do not overlap any state field, including B. Under this
premise the reloads equal the prior values, except p has deliberately been
incremented. Sequential output addresses are `(B+p) mod M`, and, on the
flush path, `(B+((p+1) mod M)) mod M`. This is an arithmetic description, not
a claim these addresses are mapped or canonical.

The Rust value API `project(State)` returns the table's values for all i32,
u16 and u64 inputs. Its fixed two-byte array zero-fills unused entries; those
entries are only a representation choice and not claimed native writes. It
neither reads pointers nor performs output writes. In particular its wrapping
position results remain defined when an equivalent native memory operation
would fault or when the slice application below rejects the position.

## Safe application domain and error behavior

`drain(&mut State, &mut [u8])` applies that projection. The two mutable borrows
are disjoint for safe callers. The Rust struct has no claimed native layout.
For zero emitted bytes, it succeeds for **every** p, including p above the
slice length, and returns the zero-extended counter bits with no state/output
change. This agrees with the native path's lack of position/output access.

For n=1 or 2 emitted bytes it first requires conversion of p to usize,
nonoverflowing `p+n`, and `p+n <= output.len()`. No state or output mutation
occurs until all checks pass. A rejected call leaves both unchanged and has
no corresponding native error branch; refusal is an explicit safe API policy.
On success, the interval `[p,p+n)` is replaced with the n ordered digits,
all other slice bytes are unchanged, and the table's next state and RAX are
returned. On Rust targets with narrower usize, conversion rejects positions
that could not index a slice; the value projection remains full-width.

For correspondence to the native pointer routine, the slice must correspond
to the mapped, writable B-based buffer and all accessed address additions
must be nonwrapping. Successful Rust range checks prove index bounds and
nonwrapping position increments; the mapped B-based buffer premise establishes
actual target address validity. Together with stable disjoint state, the
native accesses all succeed and produce the same bytes, final field values,
and observed RAX. The Rust store schedule differs (buffer first, final state
second); the difference is unobservable under these premises. Aliases with
state, concurrent mutation/observation, volatile/MMIO behavior, fault order,
partial writes on a fault, raw pointer layout/ABI, other registers and flags
are excluded. No captured execution or arbitrary wrapped-pointer equivalence
is claimed.

## Independent expectations

`oracle.py` classifies n algebraically, obtains L/H with integer remainder and
quotient, computes the modulo-M final position, and models the buffer result
as mathematical interval replacement. It does not import the historical rule
model, Rust, disassembler, or an instruction emulator. Its source, 9,600
inputs and expectations were SHA-256 frozen before the Rust component existed.
The input-only Rust client receives only state and initial output bytes.
All returned bytes, final state, RAX and rejection preservation are compared;
no values or output bytes are masked. Tests are finite corroboration of this
static argument, not a differential execution of the captured target.
