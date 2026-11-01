# RE-004 — node94 pointer-mark walk in independent Rust

This packet reconstructs the complete state-changing leaf
`[0x50e69f0,0x50e6a82)` as a dependency-free `no_std` Rust snapshot API. It adds
native implementation evidence beyond the prior
[foundation packet](../foundation-pointer-mark-walk-94/README.md), which is
preserved unchanged. The result is bounded partial RE-004 work, not a completed
component gate or a recovered node.

## Identity and scope

- Target: node #94 Linux x86-64 ELF, 91,774,280 bytes; full SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Leaf: 146 bytes, 38 instructions; body SHA-256
  `feffa56e7925e6e7b66fd727b80d7612758342f5f615c5ca527c54348b76b1a7`.
- Coordinates: ELF VAs. Leaf FDE `.eh_frame+0x297df0`; CIE offset zero.
  Next FDE starts at `0x50e6a90`; fourteen `int3` bytes separate the functions.
  The next function is excluded. No leaf callee or RIP-relative data reference
  exists; the sentinel is an immediate and all data edges are runtime loads.
- New paths: `src/node94-pointer-mark-walk/` and this packet only. Existing
  pins, foundation evidence, catalogue, byte windows and progress gates stay
  unchanged. No target-byte match or normalization mask is claimed.

The four direct call sites are qualified at instruction boundaries in complete
FDE-bounded caller decodes, rather than inferred from E8 bytes alone:

| Caller range | Direct site | FDE offset | Decoded instructions | Argument setup near site |
| --- | --- | --- | ---: | --- |
| `[0x50409d0,0x5041eed)` | `0x5041978` | `0x629b64` | 971 | RSI=`[rsp+0x40]`, RDI=R15 |
| `[0x50ebfb0,0x50ec9d7)` | `0x50ec3cb` | `0x630268` | 460 | RSI=`[rbp-0x290]`, RDI=RAX |
| `[0x50eca90,0x50ed403)` | `0x50ecf60` | `0x6302c8` | 442 | RSI=`[rsp+0x10]`, RDI=RBX |
| `[0x50ed4b0,0x50edda0)` | `0x50edac8` | `0x630340` | 418 | RSI=R14=`[rsp+0x18]`, RDI=RBX |

Caller CIE offset is `0x6205d0`. All caller bodies, FDE/CIE records and call
setups are bound in `frozen/ORACLE-FREEZE.json`. A complete 70,370,352-byte
`.text` E8 search finds exactly these four sites; 80,300 RELA records contain
no addend naming the leaf. This does not rule out indirect runtime callers.
Caller meaning and complete caller reconstruction are outside this claim.

## Recovered relation and safe projection

The mark is loaded once through `[RDI+0x68]+0x108`. The count is the u64 wrapping
sum of `[RSI]` and the signed arithmetic-shift-by-three of the raw tail pointer
difference. Under the admitted valid forward array-span premise, this is
`base_count + tail_heads.len()` modulo 2^64. The first eight indices select the
inline array regardless of `base_count`; later ones select the tail.

Each entry supplies a head through `[entry+0x8f8]`. A link supplies its successor
at `+0` and a distinct payload-node pointer at `+0x10`. While the payload's u64
stamp at `+0xcc8` equals `0x00ffffffffffffff`, the function saves the next link,
writes the once-loaded mark to the old payload, and stops at the head or the
first non-sentinel stamp. Shared payloads retain their updated state across
links and entries. In particular, a changed mark can stop a cyclic walk upon
revisiting a payload; an unchanged sentinel can leave an off-head cycle
nonterminating.

The [source proof](../../../src/node94-pointer-mark-walk/PROOF.md) defines the
admitted domain and proves the relation, counter bounds, and refusal ordering.
Opaque link/stamp IDs and immutable head arrays replace native pointers.
Distinct stamp cells do not overlap immutable link, head, entry or count
fields. Arbitrary partial byte aliasing and concurrent mutation are excluded.
A supplied mark does not emulate the original initial pointer reads, even
when the count is zero. Return RAX, original types and application purpose
remain unknown.

`InvalidMap`, `MissingEntry`, `MissingLink`, `MissingNode` and
`NonterminatingCycle` are **new safe API refusals**, not recovered target
returns. Malformed maps are rejected before writes. Other refusals occur only
at reached operations and retain the preceding write prefix. The cycle bound
checks reached cells and the current stamp gate before refusing; it does not
misclassify the normal stop produced by revisiting an already changed stamp.

## Oracle provenance and native checks

`oracle.py` was written and frozen before `src/node94-pointer-mark-walk/`
existed. Freeze timestamp: `2026-11-01T20:34:01.622989+00:00`; frozen source
SHA-256 `f2eb8c84dff43e2aa0afcfb6f7668593e5ff2e808393f08ad6ee86e759ede028`.
The oracle bytes have not been edited since that freeze. It imports only
previous packet constants and ELF section parsing; it does not invoke the
previous decoded walk or interpreter experiment. Its mathematical orbit
construction ignores stamp gates, chooses a first barrier from initial
non-sentinel and repeated-payload positions, then batch-updates the prefix.
Missing/cycle terminals are deferred so earlier gates retain precedence.

The 86,147 frozen cases include exhaustive functional graphs with one through
three non-head links, all payload-sharing assignments, all sentinel/zero stamp
assignments, three marks, plus inline/tail edges, raw count wrapping, marker
width, high-bit IDs, missing cells, malformed maps and 4,096 seeded additional
layouts. Status counts: 68,467 success; 12,452 missing link; 556 missing node;
106 missing entry; 4,542 nontermination refusals; 24 invalid maps. The latter
classes validate the new API boundary and are not original-target results.

`validate.py` re-admits the complete binary, regenerates and checks the frozen
bytes, and compiles the new library plus input-only driver. Expected results
are never given to the client. rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8), edition 2021, warnings denied, overflow checks enabled,
`panic=abort`, one codegen unit and no debug info are pinned. Each optimization
level 0 and 3 gets two independent builds. All four runs have **zero
mismatches over 86,147 cases each**; library, executable and stdout hashes are
identical between same-optimization repeats. This is arm64 macOS native
execution of independently authored Rust, not captured x86 code execution.

Thirteen separately compiled wrong libraries actually run through the same
input-only client. Every control has at least one counterexample whose
original expected result is successful:

| Compiled wrong behavior | Mismatching cases | Successful-original cases changed |
| --- | ---: | ---: |
| Invert sentinel gate | 77,949 | 62,519 |
| Use 64 sentinel one-bits | 36,383 | 21,424 |
| Truncate mark to u32 | 27,882 | 16,315 |
| Toggle mark low bit | 41,787 | 26,948 |
| Saturate count sum | 247 | 247 |
| Narrow base count to u32 | 247 | 247 |
| Add tail byte count | 707 | 702 |
| Shift inline slot | 1,460 | 253 |
| Shift tail slot | 152 | 68 |
| Process only first entry | 1,580 | 178 |
| Use link ID as payload ID | 83,618 | 68,118 |
| Refuse cycle before stamp gate | 6,328 | 6,260 |
| Precheck unread successors | 37,803 | 29,161 |

Actual mutation texts, source/binary/output hashes and first mismatches are in
`observed/results.json`; `selected-success-controls.json` retains successful
original-case witnesses. A deliberately corrupted expectation produces exactly
one mismatch without modifying the frozen archive. Twenty-three downstream
static controls, bypassing only the full-file SHA gate, reject changes to the
mark, count, sentinel, selector, load/store, branch, FDE/CIE, padding, four
caller edges and relocation facts. No instruction emulator is run.

## Reproduction and retained evidence

```sh
python3 -O research/work-items/RE-004-node94-pointer-mark-walk-rust/validate.py \
  --output work/node94-pointer-mark-walk/recheck
python3 -O research/work-items/RE-004-node94-pointer-mark-walk-rust/verify_recorded.py
python3 -m unittest discover -s tests -p test_foundation_pointer_mark_walk.py -v
/opt/homebrew/opt/rustup/bin/rustfmt +1.94.1 --edition 2021 --check \
  src/node94-pointer-mark-walk/lib.rs src/node94-pointer-mark-walk/input_only_driver.rs
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH \
  make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-pointer-mark-walk-rust/MANIFEST.sha256
```

Observed host: macOS 27.0.1 arm64, Python 3.14.3, Capstone 5.0.7, GNU objdump
2.47.20260726. `validate.py` and the stored-stream audit were run with Python
`-O`; all evidence gates use explicit exceptions. The existing focused tests
passed **9/9**; those tests include their prior Python decoded-rule checks.
Rustfmt, doctor, verify, catalogue-check and reproduce all passed. No new full
repository sweep, hosted CI, Docker build, or x86 binary match is claimed.
The parent's shared full sweep remains separate from this packet.

`observed/commands.json` records native and disassembler commands and return
codes. `raw-streams.json.gz` losslessly archives the 116 stdout/stderr streams
with base64 bytes, labels and hashes. Full leaf/caller GNU disassemblies are
also retained as readable files with trailing whitespace removed; exact bytes
remain in the raw archive. This presentation cleanup is not a target-byte
normalization mask. GNU's very large whole-ELF frame stdout is
explicitly excerpted to the two CIEs and six FDEs in `target.frames.txt`; it is
not represented as fully retained. `verify_recorded.py` audits every stream,
all 17 native runs, source bindings, mismatch counts and selected witnesses.
`repository-checks.json.gz` retains focused/global logs with only repository
root and home-path redactions, recording original and retained hashes.

Initial live scope check: 84 open PRs, zero open issues, 20 recent merges;
precommit refresh: 93 open PRs, zero open issues, 20 recent merges. No address
or semantic overlap was found, including separately reserved work at
`0x54ccfb0`, `0x3c1d690`, and `0x3818d40`. `overlap-inventory.json.gz` keeps the
read-only public inventory, timestamps and hashes. Base `src/` and RE-004
packets contain no implementation of this leaf; catalogue seed searches do
not establish any additional ownership or function scope.

No external package was installed, no captured binary or emulator was run,
and no unlicensed inferred implementation was read or copied for this work.
New source and documents are independently authored under the repository MIT
license; retained binary facts remain evidence about the pinned artifact.
Provider/client disclosure: OpenAI / Codex; the exact model identifier is not
exposed in this session. Parent handles publication. No acceptance gate is
advanced. The review handoff is this stated finite snapshot domain; arbitrary
aliasing, complete caller semantics, the original ABI and whole-node closure
remain open.
