# RE-001 / consensus: predecessor walk and exact watermark join

Question: does this helper scan all earlier records, or follow one 32-byte link
chain, and what ends that walk? Scope: selected resolved-record protocol,
tools/controls/packet; no complete mempool/index/collection implementation or gate.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed can1357-hl reference revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `node/consensus/mempool.rs`,
names the seed as collecting prior-block transaction hashes. Names/types are
leads only; no reference implementation is copied.

## Observations

ELF virtual addresses, no masks. Actual FDE `0x44b9800..0x44b9a4a`:
**586 bytes / 135 instructions**, raw FDE/CIE, full hash, complete contiguous
export and selected boundaries. Only the selected resolved-record walk is modeled,
not full index traversal or helper behavior.

Initial lookup key: input `+0x30/+0x40`, copied as 32 bytes to the local key.
The comparison watermark is copied from state `+0x198`. The caller searches for
that key. For a resolved record cursor RBX, it compares the word at `+0x80`
with the saved watermark. The branch is more specific than a generic <= stop:

1. Record word **above** watermark: read the element pointer at `+0` and count
   at `+8`, call `0x4929600` for every 32-byte element in order, then replace
   the current key with record `+0x40/+0x50` and look up again. Empty payloads
   still advance to that next key.
2. Record word **equal** watermark: JBE at `0x44b9931` reaches `0x44b99d0`;
   JNE is not taken, so the local collection header is copied and status byte
   0 is stored. The equal record's elements are not submitted to the inserter.
3. Record word **below** watermark: the same JBE reaches the **taken JNE** at
   `0x44b99d0`, routing to status byte 1 plus the current 32-byte key.
4. Absent lookup: also returns status byte 1/current key and calls local cleanup
   `0x49ac240`. Prior insertion calls may have occurred, but no accumulated
   collection result is claimed on this path.

The CMP flags survive the intervening LEA and JBE; equality is still available
at the JNE join. Treating every <= value as success would miss the below-watermark
failure route. The reference's loop across every earlier sequence/fork is not
evidence for this selected one-link-at-a-time chain.

## Inferences and limits

Record/block/sequence/hash/parent names follow reference context and widths;
original Rust types are unproved. The model accepts stable, resolved synthetic
records through an opaque index lookup. It records **ordered insert-call
arguments, preserving duplicates**, not a deduplicated final set: `0x4929600`
and collection ownership are unclosed. Raw index/node geometry is deliberately
not replaced with an invented typed B-tree layout.

Input record validity, actual history/index lookup, insertion/dedup effects,
valid chain topology, final payload type, logging, initialization and unwind are
unclosed. A synthetic model step bound is not a native cycle-prevention claim.
No live record, mempool, hash helper, captured node or networking is executed.
Before: a reference broad prior-record scan. After: link advancement, ordered
payload calls and exact equal/below/missing terminal paths are byte-bound.
Next question: close index lookup and collection insertion/return ownership before
claiming a complete hash-set result API.

## Reproduce and controls

Python 3.12.14, stdlib static ELF readers and conditional resolved-record model.
Optional Capstone 5.0.6 x86-64 Intel export; no captured instructions run natively.

```
python tools/mempool_parent_walk.py --out research/work-items/RE-001-mempool-parent-walk-94/records.json
python research/work-items/RE-001-mempool-parent-walk-94/export_disassembly.py
python -m unittest tests.test_mempool_parent_walk -v
```

Six focused methods pass in 0.611 seconds: chain order, duplicate insertion calls,
unrelated forks, empty payloads, equal/below/missing and u64 boundary classes.
Changing the actual JNE join to JE reverses equal/below terminal outcomes in the
model and the binding verifier rejects it. Other capture controls change key,
watermark/payload operands, insertion target/stride, return stores, FDE and digest.
Declared synthetic records need not be valid/reachable original block states.
Make is unavailable; required Python commands ran directly. Full suite:
**363 tests in 163.320 seconds; 7 failures, 16 errors, 21 skips**. All six
new methods pass. Existing Windows newline/POSIX-path/native-tool constraints
remain; this branch excludes unmerged #227. Doctor reports missing prerequisites.
Eight artifact sizes/digests pass before missing GPG prevents signature verification.
Imports reject the Windows reference checkout; catalogue-check rejects backslash
paths. Reproduce stops at artifact verification. No full-suite/signature/hosted-CI
or native-equivalence success is claimed.
