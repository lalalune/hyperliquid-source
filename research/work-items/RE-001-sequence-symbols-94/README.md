# RE-001: packed record to symbol streams at 0x555f240 (node #94)

Task: RE-001. Component allocation: foundation; source ownership unresolved.
Bounded question: how does this leaf convert a packed record span into byte
symbol streams, including its exceptional-position override?

**Answer.** With valid, disjoint object, input and output storage, let
`n = low32(asr64(wrapping_u64(end-begin), 3))` and iterate the packed records at the begin pointer with
stride 8. For each record, C receives `floor(log2(word_u32)); unspecified for zero` from its
first dword; A receives `table_a[x] if x <= 63; floor(log2(x)) + 19 otherwise` from its following word; B receives
`table_b[x] if x <= 127; floor(log2(x)) + 36 otherwise` from its final word. After the loop, `tag == 1: A[position]=35; tag == 2: B[position]=52`;
other tags leave the streams as computed. The override runs even for an empty
span and is not checked against the record count. The return value is
0 whenever the function returns. It has no callee-dependent behavior.

## Binding and scope

- Target: `artifacts/node/94/hl-node`, size 91774280, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; authenticated before parsing or output writes.
- ELF VA window: `0x555f240..0x555f319` (exclusive end),
  file offset `0x555e240`, body SHA-256 `3346eb8e78da732005e6105fb970c427edaecdea1cc407b9397ad97ac9707f83`.
- FDE: `.eh_frame+0x2cfe64`, VA `0xfb137c`;
  CIE: `.eh_frame+0x0`, VA `0xce1518`.
  [frames.txt](frames.txt) retains exact records and decoded associations.
- External padding is `cccccccccccccc`, up to the next FDE at
  `0x555f320`. The internal unreachable NOP is inside the FDE
  and included in the body hash. The entry marker, complete instruction
  tiling, closed branch graph, return and padding support the function bind;
  an unwind start alone would not.
- Base repository revision: `e5c9b6436876b2a4a39daef813171f9879317699`.
  No inferred reference source was copied or used to supply a function name.
- Tool: `tools/sequence_symbol_streams.py`, restricted pure-Python decoder
  with ModRM/SIB, operand widths, signed branch and RIP-relative displacements;
  Python >=3.10, exercised with Python 3.13.5. The initial exploratory
  inspection used GNU binutils 2.44; regeneration and verification do not.

| Metric (derived from records.json) | Count |
| --- | ---: |
| Function bytes | 217 |
| External INT3 padding bytes | 7 |
| Decoded instructions | 66 |
| Reachable instructions | 65 |
| Unreachable internal NOP bytes | 7 |
| Direct or indirect callees | 0 |
| Full .text bytes scanned | 70370352 |
| E8 call candidates | 2 |
| E9 jump candidates | 0 |
| Lookup tables | 2 |
| Table A bytes | 64 |
| Table B bytes | 128 |
| Recorded model vectors | 9 |
| Focused tests passed | 31 |
| Novelty searches with empty output | 4 |

## Instruction proof and memory layout

[disassembly.txt](disassembly.txt) is a complete byte-decoded instruction walk,
including internal fill and separately identified caller contexts. No instruction
bytes are normalized or masked. [records.json](records.json) contains semantic
records, data tables, extents and branch/caller relationships, not an instruction
inventory.

The argument is the object pointer in RDI. Its qwords at
`+0x0` and `+0x8` are begin/end; qwords at
`+0x20`, `+0x28`, `+0x30` are A/B/C pointers.
Dwords at `+0x48` and `+0x4c` supply tag and
position. These are observed machine widths and offsets, not recovered types.

The entry saves R12/RBP/RBX and caches pointers. `sub rcx,rsi; sar rcx,3;
mov ebx,ecx` subtracts with wrapping machine arithmetic, shifts arithmetically,
then zero-extends the low dword into RBX. It does not validate ordering,
alignment or capacity. The loop compares its qword index against that narrowed
count. The early empty check enters the override code rather than returning.

At the loop head, `bsr edi,[rsi+rdx*8]` supplies a highest-set-bit index for a
nonzero first field. The XOR against the all-ones index mask followed by
subtraction from the same mask reduces back to that index. A zero operand
leaves the BSR destination architecturally unspecified; this packet does not
invent a zero code. The following word fields are zero-extended before their
unsigned threshold comparisons. Small values use the exact read-only table
bytes retained in records; larger values use BSR plus the recorded biases.
The RIP-relative LEAs resolve directly to `0x8015c0`
and `0x801540`. No relocation-slot dereference or helper
is needed to reach these tables.

Both paths store A, then C, then B for each record. The large-A path rejoins
the appropriate B path; both B paths advance the index and loop or enter the
override. Tag selects the output to overwrite; after the A override the tag
is loaded again. All outputs are byte stores. The epilogue restores the saved
registers, clears EAX and returns. Input buffers, table data and object fields
are only read on the stated disjoint-buffer domain; stack saves are balanced.

| Branch site | Instruction | Target |
| --- | --- | --- |
| `0x555f271` | je | `0x555f2ba` |
| `0x555f28c` | ja | `0x555f2e8` |
| `0x555f2a5` | jbe | `0x555f2fb` |
| `0x555f2b8` | jne | `0x555f273` |
| `0x555f2c0` | jne | `0x555f2cd` |
| `0x555f2d0` | jne | `0x555f2da` |
| `0x555f2f9` | ja | `0x555f2a7` |
| `0x555f311` | jne | `0x555f273` |
| `0x555f317` | jmp | `0x555f2ba` |

## Callees and incoming references

`callees` is empty: full instruction decoding and CFG closure find no call,
indirect transfer or external tail jump. Callee identity/extent closure is
therefore vacuous, rather than deferred to an unbound helper.

The census examines every byte position in the entire file-backed `.text`
for `e8` and `e9`, adding signed rel32 to the end of the candidate encoding.
Raw candidate bytes and targets are retained. It does not mistake matching
operand bytes for independently established instruction boundaries.

| Candidate site | Enclosing decoded FDE range | Boundary evidence |
| --- | --- | --- |
| `0x555f385` | `0x555f320..0x555f76d` | decoded from FDE start |
| `0x55f7a07` | `0x55f7570..0x55f853c` | local decode only |

The first call is decoded continuously from its FDE start. The second is a
locally decoded context inside its enclosing FDE, not a complete decode from
that caller's entry. Thus the census count is a direct-transfer byte-pattern
count; the second candidate's full CFG boundary remains a limitation. Neither
caller is behavior-bound here, and no caller/callee closure beyond this leaf
is claimed. Pointer references, relocations, vtables and indirect calls remain
outside this census.

## Target-grounded model and controls

The independent Python model expresses the table steps as arithmetic intervals,
not copied implementation source. Tests compare these intervals against every
retained table entry and compare all word inputs against table-or-BSR rules.
Separate tests lock threshold neighbors, powers of two, count truncation,
ignored tags, override position and untouched allocation bytes. The following
vectors are derived from the decoded operations and data, not native executions.
All vector returns are the recorded constant return value; untouched allocation
bytes retain the synthetic fill marker.

| Vector | A hex | B hex | C hex |
| --- | --- | --- | --- |
| empty | `` | `` | `` |
| low edges | `000f10` | `001f20` | `000101` |
| table ends and fallback | `181922` | `2a2b33` | `02031f` |
| A override | `23` | `33` | `1f` |
| B override | `22` | `34` | `1f` |
| other tag | `13` | `23` | `02` |
| empty A override | `a523a5` | `a5a5a5` | `a5a5a5` |
| empty B override | `a5a5a5` | `a534a5` | `a5a5a5` |
| override beyond record count | `01a523` | `01a5a5` | `00a5a5` |

A zero first field is rejected by the value model because its C result is
unspecified; this is a model-domain check, not a branch in the target. The
model requires disjoint storage. Aliasing can affect subsequent reads, including
the tag reload, and only the retained instruction order describes those cases.
An empty span with an override still needs an allocated destination. Invalid
pointers, insufficient buffers and nonsensical spans have no target guard;
this is not a memory-safe parser claim.

Corruption controls cover the pinned digest, body mutations, unsupported and
truncated instructions, altered branch/caller/table targets, changed table
bytes, shifted FDE ranges and CIE links, padding, census records, packet bytes
and manifest membership. The manifest verifier uses an exact filename whitelist,
rejects symlinks/extra files, rejects duplicate or traversal entries and compares
all generated bytes again with the authenticated target.

## Novelty before writing this packet

The following commands were run at the base revision above before creating
this packet. Each returned exit code `1`, empty stdout and empty stderr.
`PR_LIST_DIR` denotes the supplied sibling title-list directory; its local
absolute spelling is deliberately not retained.

```sh
rg -i '555f240' research/
rg -i '89518656' research/
rg -i '555f240' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
rg -i '89518656' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
```

No callee is behavior-bound, so there is no additional callee address to test.
The list snapshots were:

- `open_prs.txt`: `9e6a8c69d7e6cfe350157045fbe69718186847f8a26854c4d9b79690dbb7a962`
- `merged_prs.txt`: `c291aef81f04946a0e6594630e2a5538052c57d12bc79580150555ee0d89ac6d`
- `closed_unmerged_prs.txt`: `7ffc9b73e46cf197874fe3cc691a8c8380e5ef8139dc4d23d90ff7db86819406`

These are historical empty results, not a promise that searching after adding
this packet remains empty. The seed catalogue supplied no band candidate;
a bounded search for first-party panic Locations did not identify this leaf.
Its packed symbol conversion is established, while compression-library
ownership is only an inference. No first-party credit is requested.

## Reproduction and validation scope

From the repository root, without network, installs or target execution:

```sh
python3 tools/sequence_symbol_streams.py --out research/work-items/RE-001-sequence-symbols-94/
python3 -m unittest tests.test_sequence_symbol_streams -v
python3 research/work-items/RE-001-sequence-symbols-94/verify.py
make verify
make catalogue-check
```

The tool memory-maps the target and scans the text in place, keeping only small
windows and metadata. Output is deterministic and includes no machine-local
paths or timestamps. The recorded local validation outcomes are:

- `focused_suite`: passed
- `packet_verifier`: passed; byte-identical reproduction and whitelist
- `doctor`: analysis_ready=true; exact_rebuild_ready=false; no native REA provider available
- `artifact_recovery`: Initial LFS pointer failure; explicitly requested git lfs pull succeeded.
- `make_verify`: Artifact hashes/signatures pass; fails at missing pinned reference binary.
- `make_catalogue_check`: Fails: stale research/catalogue/components.json; left unchanged.
- `make_reproduce`: Fails at artifact verifier because pinned reference checkout is missing.
- `make_test`: Incomplete: interrupted after an existing missing-reference error in test_abci_state_inventory.TargetTests; subsequent files were running.

These are historical outcomes from the contribution environment, not claims
that every future environment has those failures. The missing reference binary
is `references/can1357-hl/bin/hl-node-mainnet-new`; the broad suite also lacks
`references/can1357-hl/l1/abci/state.rs`. No submodule, generated catalogue or
existing evidence was changed to work around these failures. Passing model
tests is not differential validation against a running node.

## Non-claims, unknowns and next step

- No recovered source name, first-party ownership or exact library version.
- No native execution, Rust build, byte-equivalence or component gate.
- No specified BSR destination for zero first fields.
- Caller containers are not behavior-bound; second site has only a local boundary check.
- No indirect/pointer/vtable or whole-ELF reference closure.

There is no implementation-byte comparison; helper, relocation, vtable/data
and whole-ELF equivalence are not asserted. The tables are bound as data read
by this function, not as a complete library data map. No catalogue, progress
or acceptance gate is changed. The next bounded question is to validate the
second candidate caller's entry-to-call CFG and show how its consumer uses
the symbol streams, without assuming a compression format from familiar
constants. Verdict: strong for the complete local conversion rule, limited
for source attribution and integration.
