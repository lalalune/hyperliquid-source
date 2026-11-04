# RE-014: packed three-word millisecond conversion in node115

Component: foundation / time arithmetic, approved bounded reconstruction.
Target: Linuxx86-64 node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base:8fd8db680ec4bfef40996e5616bce3d5156d0b86. All addresses are ELF virtual
addresses before load bias; FDEs, raw unwind records and complete body exports
bind their byte coordinates. New code/evidence is MIT; capture rights remain
upstream. No unlicensed inferred source or dependency code is copied.

## Bounded question

Recover one shared integer conversion in five native instances:
3673a38..3673ae7,4230772..4230818,2d1d6f6..2d1d7a1,
51852f6..51853a1,5185576..5185621. The current tree lacks this owned
implementation. Each consumes three loaded u32 words and publishes raw signed
milliseconds in RCX and its signed-positive-or-zero clamp in RAX. The source
identity/type and original valid-input restrictions remain unproved; these
are raw machine-boundary words, not a recovered chrono API.

The first word's signed shift13 and ordinal bits4..12, 400year correction,
century arithmetic, epoch bias, seconds and nanosecond scaling are established
by original instructions. DERIVATION.md explains why the magic multiplies are
exact bounded divisions and why raw intermediates fit the native widths.
It also explains the negative-year cycle correction. This mathematical
explanation is separate from the native expected results, which come from
actual instruction interpretation. Invalid raw dates/time values are included
as boundary states, not asserted reachable original timestamp objects.

## Native model and independence

The model reads only synthetic INPUT..INPUT+12 bytes; load/reload both enforce
bounds, memory store/spill and calls are forbidden, registers/flags begin
unknown, and every CFG exit/step budget is checked. Input bases and field
positions follow each owner's actual load instructions. Only the second
instance supplies an initial EDX0, bound to XOR at423070b with static prelude
no-clobber/no-call verification. This is a supplied path boundary; optional
asset/float prelude behavior and reachability are not modeled.

Both RCX and RAX are observed independently. Negative raw outputs are kept:
comparing only the many clamped0 values would hide calendar errors. No masks
or high-level calendar model creates the oracle. Actual private COW mutations
cover the year shift, ordinal mask, epoch, seconds field, nanos shift, signed
clamp and negative-cycle arithmetic at every owner. The original ELF remains
read-only and is hashed before/after the full freeze. No captured code is
transplanted into a candidate executable.

Five full FDE bodies supply context; selected conversion instructions alone
are the semantic denominator. Context includes the previously published
three bucket wrappers, not new whole-function recovery or first-party source
attribution. Two additional helper owners and their complete exports are new
context. Large callers, original layouts/types/ABI, helper closure, aliasing,
calendar validity and whole-node equivalence remain unknown. Gates stay false.

## Reproduce

The frozen source chronology is in FREEZE-NOTE.md. Freeze producer refuses an
existing Rust component, including under python-O. Normal replay uses native
verification and the owned build script; full streams are in ignored work.
Use Python3.12.14,Capstone5.0.6,GNUobjdump and owned rustc1.94.1/LLVM21.1.8
macOSarm64. The latter is a research compiler, not an original build recipe.
Exact commands, observed results/counts and negative controls belong in the
machine-readable freeze/build reports and validation.txt. No fake root Cargo
workspace or dependency graph is introduced. Full local baseline receipt from
PR2334 is a separate tested head; per-component current-head checks are
reported separately and must not be mislabeled as hosted or full-head CI.

Next: compose this primitive into a reviewed caller with validated timestamp
production and original valid-state restrictions before claiming an integrated
calendar/state operation.
