# RE-001: node #94 EVM bloom prefilter quantifiers

- Component: `evm-rpc`; bounded RE-001 control/data-flow research and an
  independently authored Rust predicate. This is not completion of RE-011.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Submission base: `d3af75257a396c85d20857f421c370ddb8cb40e5`.
  Research began at `3324e50333042b391312515e542279ca21f63dc8`; the packet
  was moved onto updated main after its integration batch, with fresh checks.
- Pinned can1357 reference: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its unlicensed `db/block_reader.rs` is a research lead only; no code was
  copied into the new MIT implementation.
- Claim status: the instructions, branch edges, helper relocations and source
  Locations below are observed. Bloom/prefilter terminology is an inference
  from the 256-byte bit-containment operations and EVM source context.

## Gap and relationship to prior work

The inferred `BlockFilter` has a flat required-mask list and an excluded-mask
list. Its second list rejects on a contained mask. In the captured function,
the second input instead consists of **positive groups of alternatives**:
every nonempty group must find a contained mask. A match advances to the next
group; exhausting a nonempty group skips the candidate. Empty groups are
unrestricted. This is a concrete semantic distinction, not a new address label.

For a bloom with bit 0 set and one second-stage group containing just that
bit's mask, this prefilter passes. With an empty bloom it fails. Treating that
same mask as an exclusion would reverse both outcomes. This comparison is
between the lead's proposed predicate and the recovered subpath; it does not
establish that their parameter layouts or whole functions correspond.

[PR #23](https://github.com/lalalune/hyperliquid-source/pull/23) recorded the
seed's FDE and absence of a `block_reader.rs` Location.
[PR #126](https://github.com/lalalune/hyperliquid-source/pull/126) recorded its
EVM source Locations while mapping method strings and router setup. Neither
packet establishes this predicate. The nearby fee-history work in
[PR #355](https://github.com/lalalune/hyperliquid-source/pull/355) concerns
`0x27b6540`, not this prefilter. These earlier findings are retained unchanged.

`scope-check.json` records the all-state PR inventory, search terms, counts,
related work and search limitations. Open and closed submissions were checked,
along with the current repository and the related historical patches. No
duplicate semantic claim was found. This is a bounded search result, not a
claim that every historical patch was fully reviewed.

## Evidence and proof

All code/data addresses are ELF virtual addresses. The containing unwind range
is **`[0x27c1710, 0x27c347f)`**, 7,535 bytes, file offset `0x27c0710`.
Its body hash, actual FDE/CIE VAs and instruction anchors are in `records.json`.
`owner-fde.readelf.txt` independently records GNU readelf's section-relative FDE
offset `0x417ba0`; it is not a code VA. The range contains async state dispatch
and cleanup beyond this claim. An FDE is not proof of a complete source function.

`owner.objdump.txt` covers the entire range, with original instruction bytes.
Objdump's nearest exported `ctype` symbol is unrelated and supplies no name.
The observed Location LEAs bind this range to `evm_rpc/src/evm_rpc.rs:272:87`
and `evm_rpc/src/evm_store.rs:102:27`. These are captured source line numbers,
not a correspondence with lines in the inferred tree.

On the selected record-walk path:

1. `0x27c1cd0..0x27c1ce5` advances by `0x398` and copies that many bytes to
   stack `+0x680` through `memcpy`. A tag of 2 jumps out of the record walk.
   The selected mask loops read 256 bytes at stack `+0x770`, hence offset
   `+0xf0` in this in-memory record. This is **not a serialized block offset**.
2. The flat list's count is shifted left by eight. A zero count at `0x27c1d29`
   goes directly to the groups. Otherwise `0x27c1d50` tests the remaining mask
   bytes. Exhaustion jumps to the skip path at `0x27c2150`.
3. `0x27c1d6b..0x27c1ee8` loads all sixteen 16-byte lanes from the current
   mask, ANDs each with the copied bloom, and stores all lanes in scratch.
   `bcmp(scratch, mask, 256)` therefore returns zero exactly when every mask bit
   is contained. A nonzero result retries the next mask; zero proceeds to the
   groups. This is OR across flat alternatives, not AND.
4. Groups have an observed 24-byte descriptor stride, pointer at `+8` and
   count at `+16`; word `+0` is not interpreted. A zero group count bypasses
   all groups. Within a group, a zero mask count advances to the next group
   (`0x27c1f59 -> 0x27c1f40`). Each nonempty group uses the same 256-byte
   containment operation at `0x27c1f8b..0x27c2108`.
5. Inequality at `0x27c212d` retries this group's next mask. Equality takes
   `0x27c2133 -> 0x27c1f40`, advancing to the next group. Exhaustion at
   `0x27c1f73 -> 0x27c2140` skips the candidate. Reaching the group end goes
   to `0x27c2160`: AND across groups, OR within each group.
6. Only the passing path reaches the call at `0x27c2198`, through relocated
   slot `0x57709c8` to `0x1647680`. Both failure paths bypass this call.
   Its full behavior is unproved here, so prefilter success is not log-match
   success. Cleanup and the record loop continue outside the predicate.

The actual `.rela.dyn` bindings resolve the copy slot to `memcpy` and the
comparison slot to **`bcmp`**, not a guessed local comparator. Raw readelf
records are retained. This assumes the normal ELF symbol contracts; the host's
libc implementation and runtime interposition are not recovered.

For valid finite mask slices, the recovered predicate is:

```text
contains(B, M) = for every i in 0..256: (B[i] & M[i]) == M[i]
passes(B, flat, groups) =
    (flat is empty OR some M in flat satisfies contains(B, M))
    AND for every G in groups:
        (G is empty OR some M in G satisfies contains(B, M))
```

Both vector bodies are checked byte-for-byte against explicit encodings of
all 16 lane loads/ANDs/stores. The proof uses normal pointer/count validity on
this path; malformed arbitrary pointers, impossible lengths and count-shift
overflow are not modeled as valid Rust slices.

## Reproduce

Run from the repository root. Analysis host: Darwin arm64, Python 3.14.7,
GNU binutils `2.47.20260726`; Rust `1.94.1 (e408947bf 2026-03-25)`.
On macOS, prepend the installed GNU binutils directory to `PATH` for GNU
cross-checks. The Python verifier itself uses only stdlib and existing repo
ELF/FDE readers; no new tooling framework or external dependency is added.

```sh
python3 research/work-items/RE-001-evm-bloom-prefilter-94/verify.py --controls
python3 -m unittest discover -s tests -p test_node94_bloom_prefilter.py -v
objdump -d -M intel --insn-width=16 --start-address=0x27c1710 \
  --stop-address=0x27c347f artifacts/node/94/hl-node
readelf --debug-dump=frames artifacts/node/94/hl-node
readelf -Wr artifacts/node/94/hl-node
make doctor
make verify test catalogue-check
make reproduce
```

`verify.py --write` regenerates only `records.json` after authenticating the
entire image. Ordinary invocation requires exact regeneration. `--binary`
allows a different input path but never a different identity. The nine
controls corrupt branch direction/target, stride, comparison length, the last
SIMD lane, a GOT displacement, the downstream relocation and the whole image.
The first eight deliberately bypass only the outer digest check so that they
exercise structural evidence checks. Raw results are in `controls.json`.
The manifest covers this packet, the Rust files and the integration test;
paths in it are repository-relative.

## Implementation, validation and limits

`src/node94-bloom-prefilter/lib.rs` is an independent safe `no_std` predicate
with a newly chosen slice API. Its README gives exact direct `rustc` commands.
It has no dependencies or invented workspace/lockfile. Five tests pass at
optimization levels 0 and 3: empty cases, OR/AND behavior, positive groups,
zero masks, and every one of the 2,048 bit positions (including missing-bit
controls). Three Python tests pass, including nine evidence corruption cases.

Two opt-level-3 rlib builds with the same flags, source path and output
basename, in separate output directories, were raw-equal on this host:
`f95bbdc8ab523adb0b128b72e152971c20ec5c9c5a33b41b19745cf661a6fb19`.
This is self-build reproducibility, **not comparison to original node code**.
There are no normalization masks, transplanted machine bytes or original
compiled-code-equivalence claims. Build logs and gate results are summarized
in `validation.json`.

The complete official test-file inventory was also run at source commit
`8560a4f4abd5e8acbcee0d37364eb5e96e2b133b`, partitioned by sorted file index
modulo four across separate detached worktrees. Each file used the same fresh
`python -m unittest discover -s <checkout>/tests -p <file> -v` command as
`tools/run_tests.py`. All **958 files** were attempted, with **15,231 test cases
reported and 73 skipped**. Skips include the existing captured-execution opt-in,
optional tool and platform gates; they are not passes. Two existing modules
initially could not find installed `llvm-objdump`. Adding LLVM 18.1.4's bin
directory to `PATH` and rerunning just those modules produced 9 passing tests
each. There are zero unresolved module failures. The initial failure and rerun
statuses are preserved in `validation.json`; no hosted CI success is claimed.
To reproduce sequentially, put GNU binutils and LLVM tools on `PATH`, use
Python with `capstone==5.0.7` and Node 24.22.2, and run `make test`.

Before this change, the base had address/source-context evidence and an
unvalidated exclusion predicate in the reference. After it, this packet binds
the two positive mask loops to bytes and helpers, and the Rust model implements
that bounded predicate. This is new research rather than a demonstrated bug
fix in an existing reconstructed node.

Unresolved: the two mask-building helpers (`0x135c0f0`, `0x135bf00`), exact
downstream matching at `0x1647680`, routing from the `eth_getLogs` method,
JSON admission, block-range selection, hashing, original ABI and async/runtime
behavior. Calling the flat masks addresses and the groups positional topics
is plausible but **not proved**; the API deliberately uses neutral names.
The complete original helper/data/relocation closure is not established.
Captured node/visor execution and live network/chain operations were not used.

**No progress gate is changed.** The explicit denominator is one containing
FDE and two selected 16-lane mask loops, not EVM or whole-node coverage.
Next question: follow the two mask constructors and the downstream callee to
establish which address/topic conditions the bloom test approximates.
