# RE-001: node115 TLS fallback key and destructor-list lifecycle

- Component: foundation, a shared runtime dependency of the #115 poll path.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source base: 8fd8db680ec4bfef40996e5616bce3d5156d0b86.
- Status: static observations, source-consistent inferences, unresolved runtime contracts.
- Question: when the registration import is absent, how do key initialization,
  registration storage and the installed list callback connect?
- Before: own [PR #2266](https://github.com/lalalune/hyperliquid-source/pull/2266)
  retained the complete registration helper as context but explicitly left its
  null-import arm uninterpreted. After: this packet binds that arm through key
  initialization, capacity installation and the installed draining callback.
  It does not resubmit #2266's import-present result or call the registration
  helper an initializer that immediately invokes its input destructor.

## Scope, ownership and coordinates

All coordinates are ELF link-time virtual addresses with exclusive upper bounds.
File offsets come from the actual section mappings; nearest-symbol labels in
objdump output do not identify these functions.

| Role | Complete FDE | Bytes | Logical instructions | Attribution |
| --- | --- | ---: | ---: | --- |
| key initialization | 0x5ca0e20..0x5ca0eea | 202 | 52 | #2050 dependency context |
| list callback and visible final cleanup | 0x5ca53f0..0x5ca5510 | 288 | 50 | new |
| growth wrapper | 0x5c8b620..0x5c8b649 | 41 | 12 | #2050 dependency context |
| capacity installation | 0x5c8b980..0x5c8b9ee | 110 | 33 | #2050 dependency context |
| registration caller | 0x5ca0d20..0x5ca0e1f | 255 | 58 | own #2266 context |

The denominator is **288 new bytes / 50 instructions**, plus **608 context
bytes / 155 instructions**, **896 total bytes / 205 instructions in five FDEs**.
These are retained static body extents, not reconstructed Rust or byte-comparison
credit. No masks, source-built comparison, gate change or whole-runtime coverage
percentage is requested.

[PR #2050](https://github.com/lalalune/hyperliquid-source/pull/2050) already
lists the key initializer and both growth functions as relocation-masked
standard-library comparisons. They are **dependency context**, with no new
function-ownership or byte-comparison claim here. The three reported target
body hashes were independently checked against the authenticated input; their
source builds and source-comparison results were not reproduced here. Its
census has no overlapping record for the 288-byte drain FDE. This packet's
new result is that callback's instruction/unwind map and its actual relocation
connection to the selected registration path; #2050 explicitly leaves masked
relocation fields unresolved. The captured Rust revision is already known
provenance context, not a newly discovered compiler release.

The shared allocation/layout callee 0x5c8b8f0..0x5c8b980 is owned by
[draft PR #2310](https://github.com/lalalune/hyperliquid-source/pull/2310).
Only its call edge and FDE boundary are retained here. No source, evidence files,
implementation or arithmetic result from that draft is copied or claimed.
The adjacent cooperative-context packet #2137 and deallocation packets #2365/
#2371 were checked for overlap; their distinct bodies remain outside this scope.
The ownership.json file records the complete open-PR body-scan inventory and limits.

## Observed registration and key protocol

At 0x5ca0d35 a zero check of the import slot 0x64ec9b0 selects the fallback.
The nonzero arm tail-calls the symbol-qualified __cxa_thread_atexit_impl with
(callback, storage, &0x64fe448); this arm is context from #2266.

In the zero arm, TLS qword FS:-0x1150 must be zero. The code writes -1, calls
0x5ca0e20, and reads the count at FS:-0x1138. Capacity and buffer are at
FS:-0x1148 and FS:-0x1140. When count equals capacity it passes ([FS:0]-0x1148)
to slot 0x64ec878 -> 0x5c8b620. After that call returns, it appends a 16-byte
(storage, callback) pair at buffer + old_count*16, increments count, then
increments the guard. This conditional account assumes helpers return and the
list is well formed; it does not establish allocator success for every input.

The key helper reads qword 0x64feda8, whose file-backed initial value is zero.
For a zero word it calls the dynamically named pthread_key_create using callback
cell 0x64fedb0; that cell has raw value zero and a unique RELATIVE addend
0x5ca53f0. Nonzero creation status branches to the diagnostic/final-helper path.
A returned key of zero causes a second creation, deletion of key zero, and a
second-key nonzero check. This establishes the visible zero-sentinel handling;
it is not permission to execute the callback or the captured binary.

A nonzero candidate is published by locked cmpxchg from zero into 0x64feda8.
The losing path deletes its candidate, keeps the winner returned in RAX, and
uses that winner. Both the fast and initialized paths pass the selected key
and numeric value 1 to pthread_setspecific. **Its returned status is not
checked.** Calls to pthread_key_delete also have no visible status check.
Import identities are static relocation/symbol observations, not runtime
interposition or successful thread-exit guarantees.

## Observed list growth and draining

The growth wrapper passes the current capacity to 0x5c8b980 and accepts the
sentinel 0x8000000000000001; other returns go to slot 0x64df498. The installer
computes the unsigned maximum of wrapped (old capacity+1), wrapped twice the
capacity, and 4. It passes old capacity, buffer and requested count to the
peer-owned allocation/layout helper. On a zero output tag it installs the new
buffer and capacity, then returns that sentinel. Otherwise it forwards two
output words. The capacity arithmetic here is a literal instruction account;
the peer's allocation-domain proof and all allocator runtime contracts remain
outside the new result.

The installed callback ignores its incoming argument in the retained body.
It checks the same guard, writes -1, re-reads count, decrements/stores it, then
loads storage and callback from the final 16-byte entry. It **releases the
guard to zero before calling the popped callback** at 0x5ca545a. On ordinary
return it checks the guard and re-enters the loop only when zero. Thus it
re-reads the current list, rather than iterating over a cached initial length;
registrations made by a returning callback are visible to this next iteration.
Termination is not established if callbacks keep registering more entries.

On an empty list, nonzero capacity causes a symbol-bound free(buffer) call.
After that call returns, the code increments the then-current guard and resets
capacity=0, buffer=8, count=0. With zero capacity it writes guard=0 directly.
Do not erase this distinction by assuming that arbitrary interposed free
preserves TLS state. The subsequent TLS qword at FS:-0x428 is compared unsigned
with 3. Values >=3 are replaced with 2; the qword at old_value-0x10 is atomically
decremented, and a zero result invokes slot 0x64dfe58 -> 0x5c98b40. That helper's
internal ownership/drop effects are **unresolved here**.

## Unwind evidence and source attribution

The records.json file retains actual FDE/CIE records, full FDE record hashes, and two
bounded raw LSDA contexts ending at the next FDE-referenced LSDA. These context
bounds are not proven LSDA object or action/type-table extents.

The registration call-site row [0x5ca0d80,0x5ca0dab) selects landing pad
0x5ca0e0e, action 0: increment guard and call the _Unwind_Resume PLT/import.
The callback's row [0x5ca53f0,0x5ca5468) has no landing pad and includes the
indirect destructor call. The row [0x5ca5468,0x5ca5475) selects 0x5ca550a,
action 1, which calls slot 0x64e0588 -> 0x1680e23. **This is not a local
catch/cleanup around the destructor call.** Action/type tables and the
personality body are not interpreted.

The failure call at 0x5ca546f passes 0x64c3bf8. Its raw first word is zero,
but the unique RELATIVE addend is 0x43c29e. The adjacent fields are length
100, line 26, column 31. The referenced bytes are:

    /rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/thread_local/destructors/list.rs

This is a captured location/path observation, not a complete build receipt.
At that immutable Rust revision, the independently read
[list source](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/thread_local/destructors/list.rs)
has the borrow/pop/release-before-callback loop at that location;
the matching guard and Linux registration sources are listed with hashes in
references.json. Their structure supports the destructor-list and lazy-key
labels. It does not prove exact compiler flags, every monomorphized ABI,
absence of local patches, a complete crate graph or function equivalence.
Reference source text is retained privately for audit, not copied into the PR.

The key failure branches visibly pass rodata addresses and EDX constants to
0x5cad560, followed by 0x5c731f0 and slot 0x64e02e8 -> 0x5c9b050. Those helpers
are boundary-only. In particular, an EDX constant is not asserted to be a
diagnostic string length or proof of which bytes are printed.

## Reproduce and controls

Python 3.12.3; Capstone 5.0.7 (also checked with 5.0.6); GNU binutils 2.42;
LLVM 18.1.3 on Linux x86-64. The packet uses repository ELF/FDE readers and
independently authored static checks. Small ELF/LSDA/native-reader routines
reuse the author's MIT code from #2266; no unlicensed inferred source is used.

From the repository root, with installed Capstone on PYTHONPATH:

    python3 -B research/work-items/RE-001-node115-tls-fallback/collect.py --check
    python3 -B -m unittest tests.test_node115_tls_fallback -v
    python3 -O -B -m unittest tests.test_node115_tls_fallback -v
    python3 -B research/work-items/RE-001-node115-tls-fallback/export.py --output work/tls-fallback-recapture
    diff -r research/work-items/RE-001-node115-tls-fallback/native work/tls-fallback-recapture/native
    cmp research/work-items/RE-001-node115-tls-fallback/records.json work/tls-fallback-recapture/records.json
    make doctor verify test catalogue-check reproduce

The exporter authenticates the full 105,896,032-byte input before invoking
either native disassembler. It creates a new output directory and never
launches or emulates captured instructions. GNU and Capstone partitions match
exactly; LLVM splits exactly two LOCK prefixes, joined only at 0x5ca0e87 and
0x5ca54f3 with exact continuation bytes checked. All 896 bytes have the same
logical instruction partition across all three decoders.

The focused suite has 14 tests. With whole-input and body-hash admission bypassed,
120 selected instruction mutations, five data/PLT mutations, 32 physical
relocation mutations, six import-symbol mutations, five raw FDE mutations,
four LSDA mutations, duplicate relocation and FDE/CIE metadata controls must
still fail structural validation. Additional cases reject malformed/truncated
LSDA/ULEB inputs, non-file-backed bytes, native gaps/byte mismatches and incorrect
LOCK continuation. These are static comparator corruption controls, not a
synthetic execution model. The validation.json file records actual commands, results,
regenerations and the retained limits of the full repository run.

No original target execution, CPU emulation, captured networking, Rust reconstruction,
chain/signing activity, full helper closure, hosted CI success or container
claim is made. All 92 full-scope milestone gates remain unchanged. The next
question is a separately scoped proof of the FS:-0x428 final-release object's
identity and lifetime, with ownership checked before entering 0x5c98b40.
