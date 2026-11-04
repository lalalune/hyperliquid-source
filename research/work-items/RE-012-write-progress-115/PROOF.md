# Conditional transition derivation

At0x2b7af85 the selected initial path moves the prepared owner into+0x218,
loads its+0x78 pointer, and LOCK ADD at0x2b7af90 adds the original remaining
qword to+0x10 with x86 wrapping arithmetic. Pointer/count are saved in+0x230/
+0x238. The outer state3 dispatch enters0x2b7af4f; nested state3 table entry
at0x604d0c reaches0x2b7b31a. That block reloads only remaining and jumps to
0x2b7afb1, after the counter charge. Thus charge is separate and not repeated
on this selected resume path. Other state-table entries remain boundaries.

At0x2b7afc0 an empty remaining count bypasses the raw helper, zeros the result
word, and writes inner1. Otherwise the call at0x2b7afda reaches0x5cdfc90.
The first branch at0x2b7afe2 tests ALL of RAX against zero: it is not the old
odd-bit test. Nonzero status2 writes inner3 and selects the pre-scheduler
pending route; every other raw nonzero value supplies RDX to opaque0x2a026d0
and ultimately writes inner1. Actual helper-produced values and error
semantics are separate from this conditional statement.

For raw status0 the code first stores pointer1/count0, then subtracts RDX
from the old count at0x2b7b008. Borrow reaches0x2b7b383; there is no rollback
of those preceding stores in this prefix. Otherwise it stores wrapping
old_pointer+RDX and old_count-RDX. Nonzero progress returns to the length test,
including exactly exhausted writes (the NEXT test completes without a helper).
Zero progress with nonempty input supplies0x1700000003 to the opaque transform.
The Rust kernel returns CONTINUE for the loop-back edge, not delivered bytes.

The pure Rust arithmetic directly implements these scalar cases for raw u64
inputs; pointer arithmetic is numeric, not an allocation or provenance claim.
The synthetic probe emits six explicit qwords using volatile stores so its
layout has no inferred Rust ADT padding. Its sixth word independently exercises
`charge`; a consumer must not use it as a new charge on every loop iteration.
None is emitted as zero only in the probe's documented synthetic layout.
3136 compiled evaluations are finite checks of this derivation, not exhaustive
IO equivalence. Source and original-operand controls probe the comparator.

The helper's complete body is authenticated and exported, with selected imports
bound to send and __errno_location, but is not reimplemented or called. Its
readiness/CAS effects, scheduler and error transform remain opaque. In
particular preservation of prepared fields across such calls and absence of
conflicting aliases are assumptions. This proof ends before scheduler handling
at0x2b7b077. No outer async ABI, panic rollback or complete ownership proof is
inferred from the selected scalar transitions.
