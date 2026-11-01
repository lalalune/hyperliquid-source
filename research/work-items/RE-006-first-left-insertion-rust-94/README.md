# RE-006: one node94 short-run insertion in Rust

This closes one local state transition below the fallback left open by #1455.
It is separate from that PR's completed monotone module and does not implement
a complete short-run sort, seed helper, merge or order-book transition.

- Target: node94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: upstream main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Existing component: `src/node94-orderbook`; manifest/lock unchanged.
- Reference pin: can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  no inferred reference implementation was read or copied for this relation.
- Coordinates: linked ELF VAs, half-open ranges. New code/docs are MIT;
  captured evidence retains its original rights.

## Exact native domain and effect

On the first core iteration for n=21..32, the first natural run shorter than
`ceil(n/2)` branches at `0x4dbd6f1` to `0x4dbd593`. Call `0x4dbd5d1` uses
RELATIVE slot `0x57768a0 ->0x4497a90`; the adapter's n<33 arm calls
`0x4918d30` at `0x4497acd`. The delegate requires scratch capacity >=n+16
qwords (the selected wrapper supplies 512). It calls opaque seed `0x4912a50`
twice, then sets j=8. Since `floor(n/2)` is 10..16, first-left insertion is
reached after ordinary seed returns. Exact arguments/FDEs are in the native
proof and `native-validation.json`; seed value semantics are not assumed.

The local claim is `0x4918eef..0x4918f4d`, 94 bytes / 26 instructions,
ending at the **first** arrival at `0x4918f06`, before incrementing j.
For the arbitrary eight words p0..p7 left in scratch S, and x=A[8], it moves
only the maximal contiguous suffix strictly unsigned-greater than x right,
then inserts x. Equality stops. Earlier greater words remain untouched:

```text
prefix [8,0,7,1,6,2,9,10], x=5
result [8,0,7,1,6,2,5,9,10]
```

The initial full-qword store is S[8]=x. Unsigned JAE at `0x4918f22` skips
shifts on equality. Otherwise the byte offset starts at64, decreases by8,
and the guard at `0x4918f34/38` checks offset8 before a lower read. Unsigned
JB at `0x4918f46` continues only for x<predecessor. At most eight words shift;
reads stay within S[0..8), writes within S[0..9), and A/other scratch remain
unchanged. There is no call in this local envelope. Sorted output requires
a separately sorted prefix; arbitrary prefixes are permitted by this relation.

Memory premises are valid, stable, nonwrapping A[8] and S[0..9), disjoint from
each other and from the **callee's live frame, spills and return machinery**.
Scratch may legitimately occupy an ancestor's stack frame, as the selected
wrapper's scratch does. At delegate entry stack pointer T, seven pushes make
its own live interval `[T-0x38,T+8)`; the local 94-byte envelope has no stack
instruction. Historical shorthand about disjointness from "the stack" excludes
that live machinery, not all stack-backed memory. No runtime pointer/alias or
complete-call reachability certificate is inferred.

## Independent source and pre-source expectations

`first_left_insertion::insert_loaded(&mut [u64;9], loaded_value)` implements
only this local effect. The fixed array and by-value input are chosen safe
projections of the state after the native load, not an original ABI/layout.
The returned insertion index is chosen observation metadata corresponding to
the final native store position; it is not recovered native RAX. All nine
words are compared. Physical compiled store count/order is unclaimed.

The 18 literal states (12 unique/high-bit/tie plus 6 unsorted cases) were frozen
before this Rust source. `frozen-states.json` remains byte-for-byte SHA-256
`d6c3e42b061125f42a420b3b3e08e94bd896f4eae020e2b355f752282cbe50e4`.
The pre-source control plan also remains unchanged, SHA-256
`33dfd94bf2b10691b5d921ce4bb76b5b27393eece0538495dcc63fcf30f4ca0b`.
These are local sequence records, not external timestamp attestations.
The 12 admitted counts are not counted as 216 distinct compiled states.

The original plan predicted equality-shifting would be index-only. That
prediction was **falsified** by the already-frozen unsorted last-equality case:

```text
prefix [9,0,8,1,7,2,6,5], x=5
native-derived result [9,0,8,1,7,2,6,5,5]
equality-shift mutant [9,0,8,1,7,2,5,6,5]
```

Native JAE stops immediately at the equal last word; shifting it exposes an
earlier 6>x. The initial invocation exited 1 at its classification guard even
though production outputs matched. `INITIAL-CLASSIFICATION-FAILURE.json`
preserves that failure, source/stream identities and counterexample. The
outer CLI traceback was observed in tool output but not retained as a raw
file; no raw CLI hash is invented. Actual child-command streams, including
the complete failing mutant output, are retained and hashed. The original
plan, vectors, native-control labels and historical `NATIVE-PROOF.md` remain
historical records, superseded on this prediction by the failure receipt.
Neither production Rust nor expected arrays was changed to obtain the fix.

## Observed compiled checks

Official Rust 1.94.1 (`e408947bf`, LLVM 21.1.8), executable SHA-256
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`,
builds the existing component directly with edition 2024 and overflow checks
at opt0/opt3, twice each. A fresh corrected source snapshot passes all four
18-state input-only comparisons: 72 state records, zero array/index mismatches.
Both direct component test profiles pass 30 tests. Official Cargo debug and
release `--offline --locked` runs also pass 30 tests each (zero doc-tests).
These are repeated profiles of 30 unique tests, not 120 unique tests.

All 40 corrected-harness commands exit 0 with empty stderr; production builds
deny warnings. Client bytes repeat within each optimization and all four
output byte streams agree. Raw rlib hashes differ and are retained without
normalization. Toolchain download verification is attributed to the parent's
preserved official receipt; this lane did not repeat the installer or download.

| Compiled wrong variant | Changed arrays | Matching arrays with wrong index |
| --- | ---: | ---: |
| signed comparisons |5|0|
| skip first predecessor |16|2|
| wrong shift value |13|0|
| omit final insertion |13|0|
| omit initial append |5|0|
| stop before front |4|0|
| truncate loaded value to 32 bits |5|0|
| shift equal predecessors |1|8|

Every variant has a native-domain array-value witness. The last column remains
separate chosen-index observations; it supplies no target return or physical
store-trace claim. `compiled-results.json` pins all compiler-read source files,
package pins, frozen fixture identities and first counterexamples. Builds and
mutants use fixed source snapshots; live source must still match, both binary
fixture hashes are checked before each client and at final report, and the
verified input bytes themselves are passed to the client. The driver receives
only IDs, loaded values and nine-word states; expected values stay external.

## Reproduce and remaining gates

```sh
python3 -B research/work-items/RE-006-first-left-insertion-rust-94/verify_native.py \
  --llvm /path/to/llvm-objdump --out work/first-insertion-native
python3 -O -B research/work-items/RE-006-first-left-insertion-rust-94/verify_native.py \
  --llvm /path/to/llvm-objdump --out work/first-insertion-native-O
python3 -B research/work-items/RE-006-first-left-insertion-rust-94/verify_rust.py \
  --rustc /path/to/approved/rustc-1.94.1 --out work/first-insertion-rust
python3 -B -m unittest discover -s tests -p test_first_left_insertion_rust94.py -v
```

Use fresh output directories. Normal and optimized native replay match all
three outputs byte-for-byte: four FDE/body bindings, helper/relocation edges,
both decoders for the 94-byte envelope and nine inert native mutations.
Those are static operand/CFG checks below identity/window guards, not captured
execution or complete x86 semantic equivalence. `checks.json` records required
repository checks and the local input-materialization failure/recovery.

No captured node, instruction evaluator or network service ran. Remaining
gates include seed outputs, later left insertions, right-half extension,
bidirectional merge, exception/failure composition, original ABI/lifetimes
and complete sort/caller reachability. Book callers and #1455 are untouched.
No byte-window credit, whole-node equivalence, full repository suite, hosted
CI success or component gate is claimed. Raw compiler binaries/logs stay ignored.
