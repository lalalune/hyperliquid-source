# Source relation to the immutable pre-code contract

This additive proof was written after pre-code freeze
`122007baa10ea76e4bcaa84320e68fe5f484157db5cb7609dcf1fc0b83d4cc1e`.
The native proof, oracle and 912 expected frames remain unchanged. This source
phase establishes a real standalone component, not a full node reconstruction.
The source-admission checkout is main966865f1637a29ce75b019e1bf11d5529cc6f519,
recorded separately in SOURCE-AUDIT;
the pre-code derivation remains based on main56c0ec672bd8fdcfaa80f2db700a61e6240b3663.

## Admission and state representation

The complete package has five files, no external dependencies and only the
library plus one integration-test target. `Address([u8;20])` uses Rust's array
lexicographic ordering of unsigned u8. State uses BTreeMap/BTreeSet for abstract
key identity and ordering, not the captured SwissTable/B-tree heap layout.
Record contains exactly72 initialized bytes. Raw mode is an explicit u32;
no guessed native enum or constructor is introduced. All represented fields,
including inactive margin/cross fields, are ordinary supplied bit patterns.

For nonnegative u64 n,m and positive widths, `n <= floor(MAX/width)` is equivalent
to `width*n <= MAX` without overflowing the implementation. `checked_counts`
tests104*n,80*n and72*m. The 80-byte constraint is redundant when104*n holds,
but records its independent native provenance. The operation first converts
actual lengths to u64 and uses checked addition across every input record vector,
then actually calls this helper. It never substitutes the flattened prefix count.
All-input row admission is conservative safe policy, not native allocation
identity. Kind1 frames test this same public helper mathematically; they never
allocate vectors of their huge reported counts. The helper's call from the
operation is a source-proof obligation, not something a finite realistic
allocation corpus alone can prove. Allocation/panic failure remains outside the
typed-error guarantee.

Sorting the owned Summary vector by address gives the same order as the frozen
unique-key summary insertion and destructive traversal proof. Adjacent duplicate
checking is complete after sorting and occurs before any state mutation. Duplicate
rejection is a new safe policy; native overwrite/collision behavior is not inferred.
An error can consume the supplied vector, but cannot write borrowed State.

## Ordered fold, winner and flatten

The loop invariant after k summaries is: `total` is the sequential signed
saturating sum of exactly the first k address-ordered totals; `winner` is the
first present maximum unsigned magnitude among those k summaries; `records`
is the concatenation of their individual prefixes before each zero u32 marker.

The base values zero/None/empty satisfy the invariant. The step applies one
`saturating_add`, preserving overflow clipping at each step rather than once
at the end. On a present selection, None accepts even magnitude0; otherwise
strict u64 `>` replaces only a greater magnitude. Thus ties retain the earlier
address. The selected address is constructed from the summary key, enforcing
one frozen supplied-stream premise without inventing a native constructor.

The inner loop decodes precisely bytes60..64 as LE u32. Nonzero rows move all72
bytes to output. Zero breaks only this inner loop and drops its remaining suffix;
the next summary still participates in all three reductions. No record byte is
recomputed. Sorting, aggregation and flattening finish before selected-state
access. These properties correspond to frozen PROOF/TREE-PROOF's full collector,
summary insertion/traversal and front-prefix flattening closure, with their
memory, ordinary allocation/copy/free and opaque-worker frames retained.

## Active residual and exact auxiliary order

A zero total bypasses the entire selected-state block. None also bypasses it.
The returned safe observations still expose the computed total and winner.
Therefore missing unused user/position and unused sizeMIN do not trigger errors.
On an active residual, immutable lookups admit user, then position, then checked
absolute size. These are the only remaining typed failures, and all occur before
ARU insertion, so typed refusals preserve every represented state field. Native
sizeMIN can fail after earlier mutations; that path is excluded from native
correspondence and not called rollback by this API.

After admission, owned state is exclusively borrowed and no external callback
occurs. Inserting the selected address into ARU cannot remove another address.
The reborrowed position is the pre-admitted one. Raw mode==1 applies signed
`saturating_sub(total)` to margin; all other values apply it to cross balance.
The other scalar, leverage, size, user count and other map entries are not assigned.
This matches the frozen selected-existing-entry and debit path under its frame.

The auxiliary entry is acquired with absent default0 even when size0. Let
`a=abs(size)`, so0<=a<=MAX, and its old value be x. The implementation first stores
`sat_sub(x,a)`, then stores `sat_add(previous,a)`. For x>=MIN+a, the first result
is x-a and the second is x. For x<MIN+a, the first saturates to MIN and the second
is MIN+a. No second overflow occurs in either case. Hence final value is
`max(x,MIN+a)`, the independently frozen oracle's closed formula. This is not
identity for all signed x; MIN,size1 yields MIN+1. An absent key becomes present
even at size0. Equal old/new native size and unchanged leverage justify skipping
later count/leverage/membership paths only under the frozen frame, not as opaque
inert callbacks. This safe API invokes no such callbacks and preserves those fields.

## Scope and qualification limits

The 853 native-corresponding cases retain the supplied unique-summary, tag/address,
post-worker frame, valid finite tree/table/span/lifetime, selected existing state,
size!=MIN and ordinary helper premises. The59 separate safe-policy cases test
bounds and pre-mutation refusals; they are not native failure observations.
The source does not execute the worker, determine economic magnitude meaning,
construct absent accounts/positions, compute rates, reset premium storage,
perform timing/logging/network operations, or prove scheduler completeness.
All native observations have one target/repository lineage; same-project reviews
and multiple disassemblers are not independent target-source provenance.

Thirteen authored integration tests cover the branches and preservation relation.
One test embeds the exact opaque record/input of frozen C000001 and checks its
complete represented effect. The input-only client will compare all912 original
full-state result frames, in both profiles and clean rebuilds, after a separate
source/build gate.22 exact compiling behavioral mutants are planned:19 require
a difference on the853 native-conditional cases; duplicate acceptance and the
two count-bound off-by-one controls must differ only on the59 safe-policy cases
and leave every native-conditional output unchanged. Per-domain counts are
reported from the frozen cases metadata. A compile
error, malformed/incomplete output or unexpected driver exit is a failed
qualification, never a semantic mutant detection. No successful build, source
execution or universal equivalence claim exists at this source-freeze stage.
