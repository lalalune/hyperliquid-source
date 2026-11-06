# RE-004: quantity-change ordered stores and call frontiers

One bounded assets/quantities question: what memory changes occur before the
lookup, notification and diagnostic calls, and which ordinary paths reach
RET? This independently authored Rust reconstruction advances approvedScope.
It is not a deployed-node defect, complete quantity type or invented policy.

Sole target node115,105896032bytes,SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390; unrebased ELF VAs.
Merged #2204 originally mapped the hook and one clear caller. That static
evidence is credited, including conditional normal-return saturation relations;
no new static-byte credit is claimed. Live all-state quantity/bookkeeping,
quantity-change/Rust, occupancy/total and point-address searches found no
competing implementation within indexing/unpublished-work limits. Open
quantity/change issue searches found no assigned work.

## Exact original scope

Complete containing FDE `0x4206f70..0x4207104`:404 bytes/115 instructions.
Actual FDE/CIE bytes, full GNU and agreeing Capstone exports are retained.
Selected348 bytes/103 instructions are all visited in the frozen corpus; the
remaining12 instructions and56 bytes include opaque calls/post-call rejoins
and receive no executed-source claim.

There are two actual entry modes (R8 zero/nonzero) and one **independently fresh**
post-lookup point at `0x4206ff2`. The latter supplies a new total pointer and
old/new words; it does not supply a lookup result or constitute a composed
trace from the earlier entry. Valid disjoint synthetic memory and frames are
explicit premises. Other registers/flags begin unknown. Entry begins at actual
function entry and executes its prologue; the fresh interior point supplies its
existing frame. Ordinary paths execute actual RET and check RSP/return marker.
No original return type/numeric RAX value is inferred.

All actual helper invocations are stop boundaries:

| Actual call VA | Observation |
| --- | --- |
|0x4206fe5|lookup requested after the actual counter operation|
|0x4207061|notification with actual raw words and copied20-byte payload|
|0x420709b|subtract diagnostic, pending endpoint not yet stored|
|0x42070d0|add diagnostic, first store already performed|
|0x42070fe|absolute-value diagnostic with the actual current cell|

No helper is called, stubbed or assumed to return. In particular, the parent
describes two-stage saturation **conditioned on diagnostic-helper returns**;
this API stops before those calls. It never silently replaces them by a logger
that returns a chosen value. No atomicity, rollback or final diagnostic outcome
is asserted.

## Ordered stores and source contract

Entry stores the occupancy word when old0 becomes new-nonzero, using unsigned
saturation. A saturated insertion still writes u64MAX. A nonzero-to-zero removal
stores counter-1 only when the counter is nonzero. Equal-zero/nonzero cases have
no store. Those operations precede the optional lookup. A sign flip can select
notification while leaving occupancy unchanged.

The fresh total point first forms abs(old). INT64MIN selects its diagnostic
without a total write. Otherwise subtraction either selects the pre-store
diagnostic, or actually stores the subtracted word. Only then is abs(new)
formed: new INT64MIN therefore leaves that first write visible. Addition
overflow selects its diagnostic after the first write; ordinary addition stores
the result. Even equal-valued repeated stores are observed in order.

The independently authored Rust APIs implement these stage observations with
checked signed arithmetic, an explicit list of writes, and unresolved boundary
labels. Those labels and owned record shapes are not original Rust variants or
layouts. The optional raw notification word is preserved rather than narrowed
to a boolean. Actual payload copying is evaluated from original MOV instructions;
a real displacement corruption changes the observed copied bytes.

## Frozen evidence and validation

Original expectations were committed before new Rust in
`3649e42abb2e9dec64d280acd9a8d6783f6cf1b0`. Freeze104.227sPASS.3403 distinct
point-input tuples produce632 actual returns,1385 notification boundaries,
864 lookup boundaries,69 add diagnostics,276 absolute diagnostics and177
subtract diagnostics. These are observations in one function family, not six
implemented functions or component completions. The corpus includes zero,
u64/signed endpoints, overflow and store boundaries, signed flips, deterministic
fresh words and all256 payload seeds on selected notification rows.

Sixteen actual byte-COW controls change counter gates/decrement/saturation,
optional lookup selection, notification condition/copy, absolute diagnostics,
signed arithmetic, overflow branches and actual stores. They bypass the outer
identity gate only on private COW mappings; original SHA is checked before/after.
Raw inputs/expectations, compiler/client outputs, test logs and failed attempts
are preserved externally; durable hashes/results are committed here.

The public builder compiles the owned library and input-only client at opt0/3
and compares freshly regenerated frozen expectations. The client receives only
six input words in an empty cwd. Expected records remain comparator-side and
under source cfg(test). Native source observations include actual ordered
stores, current cell, RET/frontier and active notification data. Unrelated
input cells/descriptor bytes remain unchanged, and every read/write is bounded
to the declared synthetic footprint. No ISA extension is introduced.

Use the source README commands. `freeze.py` intentionally refuses once new Rust
exists; build.py/native.verify regenerate the sealed streams afterward. Check
MANIFEST.sha256 from the repository root; entries are root-relative.
Build and repository results are recorded in rust-results.json,
repository-checks.json and validation.txt after actual completion.

Limits: finite conditional point correspondence, not exhaustive ISA/compiler,
original ABI, whole-hook, clear-caller, original lifetime, callback/diagnostic
effects, integrated quantity semantics or full-node equivalence. All92 gates
remain false. No captured executable/Unicorn, service, chain, signing or wallet
operation runs. New analysis/source MIT; mmap/build scaffold reuses licensed
book-source/symbol-prefix project work with credit. No unlicensed inferred
source copied. Slop opened/OAuth remains deferred by the operator.

Actual validation: owned source build204.868sPASS; seven focused tests17.247sPASS, formatting/Clippy/twelve packet-integrity tests/doctor/verify/staged catalogue-check/actual reproduce PASS; complete scoped381.459s. New source/README were staged before inventory generation. Only catalogue steps use the exact already-submitted2655snapshot helper; hashes/scope in validation-overlay.json and baseline restored before reproduce/commit. The helper fix is not duplicated, and no unmodified-head catalogue or local full-suite pass is claimed. Own fullCI pending.
