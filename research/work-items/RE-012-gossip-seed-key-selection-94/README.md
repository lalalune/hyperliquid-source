# RE-012: raw selector to compiled 20-byte identifier inputs in node94 gossip configuration

- Task/component: RE-012 / `node-runtime`, bounded static continuation of the
  gossip configuration inventory. No acceptance gate is requested or changed.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred
  reference implementation, labels or tests are copied. New analysis is
  independently authored under the project MIT license. Captured bytes retain
  upstream rights.
- Question: which compiled 20-byte identifier inputs does the raw selector at
  input RSI `+0x8f2` choose before the following configuration lookup?
- Observations are instruction/data facts below. Calling the sequence a
  "seed" or its container a "set" is an inference from placement, equality
  handling and the 20-byte comparison. Concrete identifier type, chain names,
  external addresses and runtime validity are unknown.

## Reproduce and input identity

From the repository root, with the pinned artifact materialized:

```sh
python3.11 -B research/work-items/RE-012-gossip-seed-key-selection-94/collect.py
```

Observed environment: CPython 3.11.15, Darwin arm64, Apple LLVM 21.0.0.
The collector uses installed LLVM objdump/dwarfdump and the reviewed
`tools/elf_index.py` and `tools/fde_extents.py` parsers. Parser hashes, versions,
the full image digest, FDE/code identities and exact commands are retained.
LLVM paths select the installed Apple command-line tools; other platforms
require equivalent static LLVM commands. There is no package installation,
network access, captured executable run, instruction evaluator, signing or
runtime fixture. Only packet files are written.

Both complete owners are decoded linearly from their FDE entries; every byte
must match the authenticated image and every row must be contiguous. Unknown
instructions, gaps and an incorrect end fail collection. LLVM dwarfdump
independently confirms the FDE range derived from actual CIE/FDE records and
cross-checked against the unwind index. No native-analysis profile is used.

| Owner | Exclusive end | Bytes | LLVM instruction rows |
| --- | --- | ---: | ---: |
| `0x4743490` | `0x4744152` | 3,266 | 584 |
| `0x4941fe0` | `0x4942203` | 547 | 129 |

These **713 rows / 3,813 bytes** are a static export population, not matched
implementation bytes or whole-node coverage. FDEs are unwind ranges, not a
complete source-level function census. All coordinates are linked ELF virtual
addresses. File offsets are explicitly mapped from the authenticated sections.
The `.text` offsets here are VA minus `0x1000`; `.rodata` offsets equal VA.
Retained LLVM text ends in one newline; only surplus trailing newlines are
removed. No instruction, operand, relocation or data normalization is used.

## Selector and construction observations

The entry saves input RSI in R15. At `0x47434c4`, `MOVZX EAX, byte [RSI+0x8f2]`
reads an unsigned byte. The following LEA names `0x6f9ac4`; `MOVSXD` loads its
signed dword at `table + 4*RAX`, adds the table base, and jumps indirectly.
There is **no local selector upper-bound check** between this read and jump.
This packet interprets only raw selectors 0, 1, 2 and 3, without asserting that
they exhaust the source type or are reachable runtime inputs.

| Raw byte | Computed arm | Constructed 20-byte inputs, in call order |
| ---: | --- | --- |
| 0 | `0x4743ffb` | No identifier call in this arm; see below |
| 1 | `0x47434db` | pool `0x6fb559`, then `0x6fb56d` |
| 2 | `0x474361a` | pool `0x6fb581`, then `0x6fb595` |
| 3 | `0x474354e` | pool `0x6fb5a9`, `0x6fb5bd`, `0x6fb5d1`, `0x6fb5e5` |

Each nonzero arm first zeroes qwords at stack `+0x10` and `+0x20`. For each
input, an eight-byte RIP-relative MOVDQU loads the first 16 material bytes,
which are stored at stack `+0x90`; a separate immediate dword store writes
the remaining four at `+0xa0`. The collector resolves the load displacement,
retains its pool bytes, extracts the immediate tail and verifies the assembled
20 bytes against the contiguous pool record. Every LEA/call sequence passes
RDI = `&stack[0x10]` and RSI = `&stack[0x90]` to direct target `0x4941fe0`.
The eight original 20-byte material values are public bytes from the retained
binary, recorded as hex in `records.json`; no external identity is assigned.

All three arms join at `0x4743688`. That block copies the three-word state
`[rsp+0x10..+0x28)` into `[rsp+0x120..+0x138)` before the next lookup starts
with a pointer load from saved input RSI `+0x3870`. This establishes the
construction and local handoff, **not** the eventual selected peers, union/
filter meaning, network destinations or a completed gossip configuration.
Downstream lookup, comparison thresholds, iterator and selection helpers are
outside this packet's interpreted scope, though their owner bytes are exported.

At `0x4743ffb`, selector 0 prepares pointer `0x6fb542`, length operand 47 and
Location pointer `0x572ece0`, calls through slot `0x576e098`, then reaches UD2
if that call returns. The 47 bytes and operands are retained without treating
them as a clean 47-character diagnostic: the visible ASCII fragment is
`non-testing local chain`, followed by nontext identifier bytes. The indirect
helper's behavior and the actual source-level panic/format contract are unknown.

The adjacent table-sized words at `0x6f9ad4` and `0x6f9ad8`, if interpreted
using the same relative-base rule, point to `0x47441ae` and `0x4744af7`, outside
this owner. They are retained as **adjacent word probes**, not declared extra
entries. No table extent, complete valid-tag set, behavior for 4..255 or
cross-owner CFG is inferred from pooled-data adjacency.

## Selected helper observations and limits

The helper at `0x4941fe0` is previously studied context: the existing
`RE-006-perp-order-insert-94` packet and open PR #1896 discuss it on the
fill-user path. Its 547-byte export here freshly qualifies the argument
interface used by the gossip caller; it is not claimed as newly recovered
helper coverage. This contribution adds the `0x4743490` selector, original
material construction sites and local handoff. The combined export count
above is an analysis population, not a new-code or reconstruction credit.

The complete `0x4941fe0..0x4942203` export provides these local checks:

- It retains the input pointer in R14. Its comparison loop passes length
  `0x14` and calls the pointer loaded through slot `0x576e488`. The unique
  `R_X86_64_GLOB_DAT` relocation names dynamic symbol `memcmp`; original
  relocation and symbol records are retained. This is a static import binding,
  not an observed dynamic-loader result or an invocation of the library.
- A zero comparator result takes `0x49420a4`, sets AL to 1 and returns without
  the later count increment. The comparator's nonzero-sign paths can traverse
  pointer-linked nodes. Imported function behavior, memory validity and
  transitive helper effects remain assumptions, not tested execution.
- The nonmatch path loads 8+8+4 bytes from the input. It has allocation and
  generic insertion-helper boundaries; the selected small-node store arm
  writes 16+4 bytes, increments a node count and finally increments the
  container word at `+0x10`, returning AL 0. This supports the inferred
  set-insertion reading, but no complete allocator/tree/split correctness,
  error behavior or full helper closure is claimed. AL is not checked between
  these eight caller construction sites.

## Validation and prior work

The collector checks 16 pinned instruction spans, the first four relative
table destinations, all eight material loads/tail stores/argument setups and
direct call targets, and both complete LLVM exports. Eight corruption controls
privately alter the selector-field displacement, a table entry, a material-load
displacement, a tail immediate, a pool byte, a call displacement, the comparison
width and the equality branch. Each executes the same local validator against
a patched read view, bypassing only the outer image digest, and must reject.
These are evidence-admission controls, **not** behavior or reconstruction tests.
`validation.json` records two byte-identical collections of generated evidence.

Before: `gossip-config-inventory-94` / merged #1075 binds Locations and literals
to this owner but leaves behavior and numeric roles open. After: this packet
connects the selected byte dispatch to the 2/2/4 original 20-byte construction
calls and the following handoff, with a limited helper argument check.
`local-abci-gates-94` / #430 and open #1851 concern loader `0x4741dc0`, while
#502/#517 concern other peer-cap/timing questions. Their behavior is not
re-derived. The open PR inventory was checked for these exact code/data
addresses and identifier-selection scope; unrelated keyword matches are not
treated as ownership. No existing packet or shared tooling is changed.

No Rust implementation, source build, differential execution, byte-match
credit, complete peer policy, source-type recovery, chain-name mapping or
acceptance gate is claimed. The input selector producer, valid input domain,
transitive alias effects, downstream selection, all exceptional exits and
whole-ELF identity remain open.

Next question: establish the exact record/layout returned by the following
configuration lookup and how it is combined with these constructed inputs,
before assigning a peer-selection policy or configuration field name.
