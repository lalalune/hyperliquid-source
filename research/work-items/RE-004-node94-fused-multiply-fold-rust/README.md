# RE-004: raw prepared-register fused multiply/fold

This contribution reconstructs all 786 bytes of node94
`[0x565d440,0x565d752)` in independent Rust. Its bounded question is the exact
arithmetic and memory/register relation for arbitrary prepared register values,
not merely the conventional input subset of its two observed wrappers. It
closes interleaved product accumulation, four low-word folds, 384-bit overflow,
the final extended subtraction and all final modified GP registers.

Target: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Repository base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Component/task: bounded foundation reconstruction under RE-004. All addresses
are original ELF VAs, not host addresses. The [source](../../../src/node94-fused-multiply-fold/lib.rs)
and [universal proof](PROOF.md) retain separate incoming RAX/R15 values and impose
no inverse, parity, nonzero-modulus, canonical-input or caller-consistency rule.

The helper has 231 instructions, no internal call or branch, and no static data
dependency. Its unique actual FDE and full CIE are bound; 14 following NOP bytes
are separate padding. Two E8 sites, 0x565d383 and 0x565d406, are qualified in
complete 109-byte/30-instruction and 112-byte/31-instruction caller bodies.
Those dispatch wrappers' global feature tests, alternate targets and behavior
remain outside the reconstruction. E9/EB scans find none. All 80,300 RELA
records are inspected for naming addends and overlapping full-width writes to
retained bodies/padding. No such naming/writer exists. This is not a complete
indirect-reference census.

The prior 0x565d8a0 four-fold helper has no interleaved A-times-B accumulation;
this leaf also has independent prepared words, actual six-word accumulator
overflow and a supplied output-address stack slot. Neighboring and wrapper
implementations are excluded. Live PR/issue/recent-merge and source overlap
checks are in `overlap.json`. Prior evidence, imported pins, catalogue and
progress gates remain unchanged. No unlicensed inferred source was inspected
or copied.

## Frozen independent expectations

Before the Rust source directory existed, `oracle.py` was frozen at
`2026-11-01T22:47:52.292689+00:00`, SHA-256
`eec015895071183f353cf035866faa7ebf43591638776a54c1b7134f9c9dc560`.
Its initial state is a whole-integer polynomial of independent register values.
It adds whole 256×64 products at one-word offset modulo 2^384, then applies a
quotient/remainder equation for each fold. Final register RDX is derived from
a three-word prefix quotient. Memory output uses immutable concatenation.
This is structurally separate from Rust's fixed word arrays, u128 products and
carry/borrow operations; it imports no Rust and simulates no instructions.

`frozen/ORACLE-FREEZE.json` binds the oracle, complete target/static facts and
the raw fixture hashes: input
`34dd21b70c7c05381c0a5d772b1b319c0ce19db1a17622a913a7f4964b200efb`,
expected `416d2878251f5920f7cfa7daece74f4d8b265a3f8dd8058032eea585ca57448f`.
There are 10,896 descriptors: 10,677 admitted and 219 explicit API refusals.
The admitted vectors include 375 data aliases, 3,317 accumulator-wrap cases,
3,953 folded-carry-drop cases, 4,171 selected subtractions and 2,068 final fifth
words equal to 1. Register/data bit ranks, adjacent values, arbitrary factors
and M words, zero/MAX, consistent-wrapper subsets, unread B+0 storage and image
endpoints are represented. Finite vectors complement the all-input proof.

Each 240-byte input consists of 14 little-endian u64 fields followed by 128
synthetic bytes. The fields are incoming RAX,R9,R10,R14,R12,RBP,R15,R8; image
base; A/B/M addresses; supplied output address D; and active image length.
Each 240-byte expected output is status, then the 13 registers in source struct
order, followed by all 128 bytes, including the inactive suffix. On refusal the
driver encodes status/registers as zero; this is new driver/API behavior.

## Actual native and structural results

The pinned compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Qualification ran on macOS arm64 with Python 3.14.3, Capstone 5.0.7 and GNU
binutils 2.47.20260726. The input-only client receives only an input path; no
expected outputs or oracle are linked or passed. Builds use `-Dwarnings`,
overflow checks, panic abort and opt0/opt3, each repeated.

All 43,584 observations matched without masks. Repeated same-profile library,
client and stdout hashes were identical. All 22 compiled controls were detected:
21 change successful admitted values, while one changes only 20 refusal images.
Selected concrete mismatches include 2,578 for equating prepared RAX/R15,
3,317 for saturating rather than wrapping the six-word accumulation, 3,953 for
keeping a discarded fold carry, 2,068 for ignoring the final fifth subtraction
word and 3,499 for returning the selected output in RAX rather than its saved
pre-subtraction word. Alias and unread-B+0 controls are also executed; the audit
separates successful-value changes from original-admitted/new-refusal changes.

All 60 static corruptions were rejected. A corrupted expected record causes
exactly one mismatch against actual native output. Malformed driver input
exits2 with no stdout. No failed native run or ineffective control occurred.
Exact commands, results, compiled patch text/hashes and native counterexamples
are retained under `observed/`.

`observed/raw-streams.json.gz` contains 170 exact command streams. The first
native stdout is base64; other fixed-width native outputs are XOR deltas to it,
then base64. Every raw size/hash and command label is retained and reconstructed
by `verify_recorded.py`. The readable GNU exports remove trailing whitespace
only; their complete bytes and their raw archive counterpart are both checked.
The huge GNU frame stdout is explicitly represented by selected complete
CIE/FDE excerpts. All other invoked command streams are retained losslessly.

## Reproduce, domain and limits

```sh
python3 -O research/work-items/RE-004-node94-fused-multiply-fold-rust/validate.py \
  --output work/node94-fused-multiply-fold/recheck
python3 -O research/work-items/RE-004-node94-fused-multiply-fold-rust/verify_recorded.py
python3 -m unittest tests.test_fde_extents tests.test_elf_index tests.test_readelf_crosscheck -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH \
  make doctor verify catalogue-check reproduce
```

The 24 focused tests passed; exact repository gate outcomes/streams are retained
separately. The shared baseline covered 971 files / 15,462 reported tests / 69
skips. Original `make test` exited2 solely on three disk-full errors; isolated
retry of all 20 affected tests passed. That sweep was not rerun on this head.
Hosted CI and skipped Linux-only runtime qualification are not claimed.

`evaluate` projects stable, successfully read data plus the supplied original
stack-slot value. The finite-image adapter has an explicit nonwrapping interval,
checks all reached spans, and permits arbitrary data aliases. Original stack
and control storage are disjoint; no original stack dereference or native
pointer is manufactured. `None` is a new atomic refusal, not recovered native
fault behavior. Flags, exception handling, MMIO, concurrency, CET/native ABI,
wrapper semantics, quantity meanings, compiled-byte identity and whole-node
reconstruction remain excluded. No progress gate is advanced.

Only newly authored Rust executes. No captured binary, instruction emulator,
networked node, chain or key material is used. Authorship assistance is
OpenAI/Codex; the runtime did not expose an exact model ID.
