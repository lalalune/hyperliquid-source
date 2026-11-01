# RE-006: pending-removal row key collector, node #94

- Component: `orderbook`; bounded RE-006 follow-up to the pending-removal edge
  left stubbed in `RE-006-perp-order-insert-94`.
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Research base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin: `can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No reference implementation was used or copied. Existing project packets
  supplied the helper address and the pending-removal interpretation.
- Claim: static observations and a conditional projection proof. No Rust
  reconstruction, captured instruction evaluation, runtime result, new matched
  bytes, or component gate is claimed. RE-004 quantity semantics are not used.

The new result is the contract up to the set-builder boundary of
`0x4450210`, previously a stub: on a valid contiguous span of 32-byte rows, it
projects the first unsigned qword of every row, then sorts up to twenty keys
locally. At twenty-one keys it calls a separate sort. It supplies an iterator
over the keys to the already studied set builder. This establishes which
pending-row words reach the relation-cleanup key collection, including
duplicates and the high bit; it does not repeat the surrounding insert or
removal semantics.

## Reproduce

From the repository root, with GNU Binutils 2.44 and LLVM 19.1.7 available:

```sh
python3 -B research/work-items/RE-006-pending-removal-key-collector-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump
python3 -O -B research/work-items/RE-006-pending-removal-key-collector-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump
python3 -m unittest discover -s tests -p test_pending_removal_key_collector94.py -v
```

`--llvm` accepts another installed path. Native output is retained exactly
apart from replacing the absolute target filename with
`<authenticated-node94>`; rendering with different native versions can differ
and is not silently accepted. `--write` regenerates this packet's derived
exports for review. The collector never executes or evaluates target
instructions. It uses the existing section and FDE parsers plus two native
static disassemblers. The projection model operates on independent synthetic
byte arrays and does not load captured code.

Author environment: Linux x86-64, glibc 2.41, Python 3.12.14, Git 2.52.0,
Git LFS 3.6.1. Ghidra is absent and no Ghidra profile or snapshot is used.
No model-backed behavior is claimed. Authoring provider: OpenAI; model:
`gpt-6.1-sol`; reasoning effort: `xhigh`; UI: `GPT-6.1 Sol Extra High`;
client: Codex cloud. Attribution follows the parent-supplied spawn identity
and user-confirmed UI selection, rather than an independent metadata read.

## Boundaries and prior work

All addresses are linked ELF virtual addresses. Every window in `records.json`
also records its section-derived file offset and exact bytes. `.text` offsets
in this target equal VA minus `0x1000`. FDEs are unwind extents, not recovered
Rust symbols.

| Role | FDE, half-open | Bytes | Native instructions | New claim |
| --- | --- | ---: | ---: | --- |
| Key collector | `0x4450210..0x44503d3` | 451 | 127 | Projection, local ordering, external boundaries |
| Selected insertion caller | `0x4311140..0x4314d9f` | 15,455 | 55 in corridor | Only corridor `0x4312aa1..0x4312bae` |
| Credited set builder | `0x49273c0..0x49274a4` | 228 | 52 | No new set/deduplication semantics |

GNU and LLVM partitions agree on the complete collector and credited builder
plus the 269-byte selected caller corridor, without byte masks. Counts are in
`records.json`: 234 exported instruction rows / 948 bytes. This is a
disassembler cross-check, not source or target
equivalence. The full caller digest and unwind bounds supply context; only
its corridor is exported. Builder behavior is credited existing work.

The collector FDE at `0x1246b78`, CIE at `0xfbdc2c`, and LSDA pointer
`0xb3f580` are recorded. Its thirteen following `INT3` bytes precede the next
indexed start `0x44503e0` and are outside the FDE. Exact FDE/CIE records for all
three bodies are retained. The selected caller's true FDE end is
`0x4314d9f`; its next indexed start is `0x4314da0`. No existing packet or index
is edited to conflate those coordinates.

`RE-006-perp-order-insert-94` owns the insertion, pending-row creation, reasons
and removal behavior. Its `on_collect` stub merely reads row qwords at stride
32 and supplies a synthetic set marker. This packet qualifies that edge from
the collector's full native body. `RE-006-user-book-cancel-94` already studies
`0x49273c0` and the lower builder `0x4298270`; set construction/deduplication
is credited there. The unchanged `src/node94-orderbook` implementation does
not consume this new packet yet.

The live open-PR body scan in `overlap.json` found no mention of the four
selected addresses. The first 55-open-PR inventory, recent sixty merged PRs,
and existing RE-006 packets were also inspected. Address absence is not a
proof of semantic nonoverlap; the distinct stub-to-body scope above is the
ownership basis. No external claim or publication was made.

## Observed selected caller

At `0x4312aa1..0x4312ab8`, the caller loads the row pointer from stack `+0x298`
and count from `+0x2a0`, shifts the count left five bits, and adds the pointer
to form `rdx`; `rsi` retains the first row. `rdi` points to stack `+0x320` and
`0x4312ac8` calls `0x4450210`. The corridor's exact 269 bytes are recorded
separately from the full caller hash.

On normal return, `0x4312aed` and `0x4312af5` load the first two output words.
The caller still walks the original rows with a 32-byte increment at
`0x4312b2f`. It loads a key from row `+0`, copies twenty bytes from `+8`, and
passes the collected two words in `rcx/r8` to relation delegate `0x43051f0`
at `0x4312b8f`, before its reason dispatch. Those are byte observations.
Calling the row words order identifiers and the twenty bytes users is an
inference credited to the existing perp insertion packet. This does not
establish other call sites, externally reachable inputs, or the delegate's
transitive effects.

## Collector proof and premises

Premises: `rdx-rsi = 32*n` without address wrap; all source rows are readable;
`8*n` allocation succeeds; the source remains stable during the operation;
the output buffer and allocator result do not alias the source; and called
helpers return normally on the claimed path. In particular the caller's
shift alone does not prove its count cannot overflow. No contract for invalid
pointers, partial rows, allocation failure, or aliasing is invented.

1. `0x4450227..0x445022f` tests the source byte span. Zero span writes only
   output qwords `+0` and `+0x10` to zero and returns. Output `+8` is not
   initialized on this path and must not be read as an established zero.
2. For nonempty valid input, `0x4450232..0x4450239` requests span/4 = `8*n`
   bytes. The small-allocation branch at span `<=28` is unreachable under
   these premises; it is retained as an unknown branch for invalid spans.
3. `0x4450275` obtains `n = span >> 5`. `0x445027d..0x4450287` obtains
   `n mod 4` and selects the four-row loop only for `n >=4`. Each pass at
   `0x44502a0..0x44502cd` reads qwords at source offsets `0,32,64,96` and
   writes destination offsets `0,8,16,24`; source advances 128 bytes and
   destination index advances four. It runs `(n - n mod 4)/4` times.
4. The tail at `0x44502d4..0x4450300` starts at source row `n - n mod 4`
   and copies `n mod 4` qwords. Its byte counter advances eight while the
   source operand scales that counter by four. Thus it reads only row `+0`,
   once for every row. No user/reason/tail field affects the projected words.
5. Span 32 skips sorting. Otherwise span `<0x2a0` selects the inline sort:
   with `span=32*n`, this means `2 <= n <=20`. At `0x4450371` an unsigned
   `jae` keeps an ordered adjacent pair; at `0x445038c` an unsigned `jb`
   continues shifting larger predecessors. This is ascending unsigned
   insertion sort. The bound at offset eight stops before the array start.
   Equal words remain present in the buffer; the collector does not dedupe.
6. Span `>=0x2a0`, hence `n >=21`, passes buffer pointer, `n`, and a scratch
   pointer to the indirect call at `0x44503af`. The precise RELATIVE record
   binds slot `0x5774f50` to `0x4486d10`. This packet proves delegation, and
   makes no claim about the large-sort implementation or its comparator.
7. `0x4450308..0x4450328` builds four qwords: allocation base, current base,
   allocated word count, and end pointer. It calls `0x49273c0` with that
   descriptor and the original output pointer. The set builder's root/height
   interpretation and key deduplication remain credited prior work.

`normal_cfg` records all 127 collector instruction nodes. All nineteen
explicit branch sites target validated instruction starts inside its FDE.
Call fallthrough edges are conditional on normal return; the final unwind
call's nominal continuation equals the FDE end and is not a recovered return
path. The LSDA exception edges are not decoded. Raw native exports retain
the allocation-failure call, cleanup/free call and unwind call as well as the
normal return. Five exact RELATIVE relocation records bind all collector
indirect slots. Allocator internals, failure behavior, long sort, complete set
builder helper closure and relation delegate remain outside this claim.

## Controls, actual results and limits

- Normal and optimized Python replay both pass, reproducing eight exports
  from the authenticated ELF and two installed disassemblers.
- Twenty-two operand/control corruptions fail at their named local
  obligation below the target SHA admission check. A changed FDE range is
  rejected by the same endpoint qualifier used on the actual input. These
  controls prove static admission rejects those changes; they are not
  behavior-differential runs of the target.
- Synthetic projection checks cover 35 row counts, including every count
  from zero through 24 and larger four-way/tail boundaries through 4,096,
  all 720 permutations of six unsigned boundary words, repeated high-bit
  words, and changes to every unprojected row tail. A separate list oracle
  checks the group/tail projection, multiplicities and inline ordering.
  Signed-comparator and wrong-stride alternatives are distinguishable.
- Six focused unittest methods pass, including all 22 operand/control
  corruptions below the digest gate in ordinary test discovery. The model
  rejects partial rows as an API choice; target behavior on partial rows is
  unproved. For counts above
  twenty the model exposes the unsorted projected buffer and the delegate
  selection, preserving the external-helper gap.
- `make doctor`, `make verify`, `make catalogue-check` and `make reproduce`
  pass locally. The initial verify failed on unmaterialized submodules, then
  a fresh-clone LFS stat discrepancy. Exact local source pins and LFS
  SHA/size were checked, inputs were materialized from existing local
  authenticated sources, and invocation-local standard LFS filters refreshed
  the unchanged index entry. No persistent configuration or imported bytes
  changed. Commands and results are in `checks.json`; complete local streams
  remain under ignored `work/re006-pending-removal/`.
- The repository-wide `make test` sweep is deferred to the coordinating
  integration run. The six focused tests are in the normal flat `tests/`
  discovery path. No full-suite, hosted-CI, Rust build, target execution or
  binary-equivalence result is claimed here. All progress gates remain
  unchanged.

The synthetic model is a consequence check for the addressed manual proof;
passing it cannot establish runtime reachability or target equivalence.
The collector does not establish economic quantity units, crossing rules,
concurrency, transaction rollback, caller-wide alias closure, or a complete
insert/cancel/match implementation. No code-window denominator or coverage
registry is advanced.

Next question: establish the comparator and failure contract behind
`0x5774f50 ->0x4486d10` for the already qualified contiguous qword buffer,
without re-claiming the existing generic set builder or insert path.
