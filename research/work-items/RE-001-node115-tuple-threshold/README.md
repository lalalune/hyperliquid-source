# RE-001: node #115 tuple-gated saturating threshold

Component: l1-shared: source-associated scalar comparison, ownership not proven. Target: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base/reference revision:
`8fd8db680ec4bfef40996e5616bce3d5156d0b86`. All results below are bound to that digest.
New code and prose are independently authored under the repository MIT license;
no inferred source, public implementation or reference source was copied.
Claim status: observed bytes and metadata; proved conditional scalar rule;
inferred first-party association; unresolved original name and field identities.

## Bounded question and answer

What does the complete function at `0x2c6f290` return in AL, including
mixed signedness, equality and overflow boundaries?

Given valid, stable input memory based at RDI and a valid return stack, define
tuples A and B from the
raw dwords at offsets `0x60/0x64/0x68`
and `0x4294/0x4298/0x429c`.
Compare them lexicographically with a signed first `32`-bit field
and unsigned remaining fields. Let C, R and T be the unsigned `64`-bit
words at `0x28`, `0x4228` and `0x10`.
The rule is **AL = 2 if A >= B and C >= R; otherwise AL =
int(C >= min(UINT64_MAX, T + 5000))**. Equality passes each
non-strict gate. The saturation branch prevents wraparound; its maximum threshold
is still attainable when C is UINT64_MAX. The function reads memory and writes
registers only. All paths terminate at its RET, with no callees or indirect dispatch.
Only AL is the scalar result claimed; upper RAX bits vary by path.

## Extent and raw evidence

Addresses are linked ELF VAs, half-open ranges, without a runtime load bias.
The body is `0x2c6f290..0x2c6f2f4`, file offset `0x2c6e290`,
size **100 bytes**, body SHA-256 `c7eae84020e629ae599eb400ad0d31b78d3a037651d47d2cdc3ce4a83995acf0`.
Its actual FDE is at file offset/VA `0xd86a0c` and names
CIE `0xca6ed8` (`zR`), with no LSDA.
Raw FDE/CIE records and the independently cross-checked unwind index row are in
`records.json`. Full entry-to-RET decoding, forward-only local control flow and
INT3 gaps support the extent beyond mere unwind-table membership. The preceding
gap is 13 bytes; the following gap is 12
bytes. Padding is recorded separately and excluded from the body.

| Metric (derived from records.json) | Value |
| --- | ---: |
| functions_bound | 1 |
| body_bytes | 100 |
| instructions | 28 |
| callees | 0 |
| direct_call_candidates | 4 |
| direct_jump_candidates | 0 |
| caller_fdes | 4 |
| vectors | 28 |

Every instruction is decoded by the strict Python subset decoder; unsupported
opcodes, ModRM/SIB values, prefixes, truncated operands or altered contracts fail.
No instruction bytes or operands are normalized or masked.

| VA | Raw bytes | Decoded instruction |
| --- | --- | --- |
| `0x2c6f290` | `8b4760` | `mov eax, mem32[rdi+0x60]` |
| `0x2c6f293` | `488b4f28` | `mov rcx, mem64[rdi+0x28]` |
| `0x2c6f297` | `3b8794420000` | `cmp eax, mem32[rdi+0x4294]` |
| `0x2c6f29d` | `0f9cc0` | `setl al` |
| `0x2c6f2a0` | `751b` | `jne 0x2c6f2bd` |
| `0x2c6f2a2` | `8b4764` | `mov eax, mem32[rdi+0x64]` |
| `0x2c6f2a5` | `3b8798420000` | `cmp eax, mem32[rdi+0x4298]` |
| `0x2c6f2ab` | `0f92c0` | `setb al` |
| `0x2c6f2ae` | `750d` | `jne 0x2c6f2bd` |
| `0x2c6f2b0` | `8b4768` | `mov eax, mem32[rdi+0x68]` |
| `0x2c6f2b3` | `3b879c420000` | `cmp eax, mem32[rdi+0x429c]` |
| `0x2c6f2b9` | `7306` | `jae 0x2c6f2c1` |
| `0x2c6f2bb` | `eb0f` | `jmp 0x2c6f2cc` |
| `0x2c6f2bd` | `84c0` | `test al, al` |
| `0x2c6f2bf` | `750b` | `jne 0x2c6f2cc` |
| `0x2c6f2c1` | `b002` | `mov al, 0x2` |
| `0x2c6f2c3` | `483b8f28420000` | `cmp rcx, mem64[rdi+0x4228]` |
| `0x2c6f2ca` | `7327` | `jae 0x2c6f2f3` |
| `0x2c6f2cc` | `488b4710` | `mov rax, mem64[rdi+0x10]` |
| `0x2c6f2d0` | `4889c2` | `mov rdx, rax` |
| `0x2c6f2d3` | `4881ea78ecffff` | `sub rdx, -5000` |
| `0x2c6f2da` | `7211` | `jb 0x2c6f2ed` |
| `0x2c6f2dc` | `480588130000` | `add rax, 5000` |
| `0x2c6f2e2` | `48c7c2ffffffff` | `mov rdx, -1` |
| `0x2c6f2e9` | `480f43d0` | `cmovae rdx, rax` |
| `0x2c6f2ed` | `4839d1` | `cmp rcx, rdx` |
| `0x2c6f2f0` | `0f93c0` | `setae al` |
| `0x2c6f2f3` | `c3` | `ret ` |

## Why the rule follows

The first CMP feeds SETL, which uses signed ordering. SETL leaves flags intact,
so JNE still tests the CMP's equality result. For unequal first fields, TEST AL
selects either the threshold path or the C-versus-R gate. Equal first fields
reach the next CMP/SETB/JNE, using unsigned ordering; equal second fields reach
an unsigned JAE on the last dword. Thus the gate is reached exactly when A >= B.
MOV AL,2 precedes the unsigned C-versus-R comparison and its JAE
to RET. Failure of that comparison also falls through to the threshold calculation.

Put M = 2^64 and d = 5000. SUB uses the sign-extended
immediate -d, whose unsigned value is M-d. For T < M-d, it sets borrow, and its
result modulo M is T+d without overflow; JB selects that value directly. For
T >= M-d, ADD T,d carries. MOV RDX,-1 preserves carry, and CMOVAE cannot replace
that maximum word on this arm. Therefore RDX is min(M-1,T+d) over the full word
domain. The final unsigned CMP/SETAE gives the stated threshold predicate.
This is an algebraic proof over all input words, not an exhaustive execution test.
The independent scalar Python model and frozen target-grounded vectors exercise
signedness, lexicographic priority, equality, both gates and saturation neighbors.
They do not execute captured instructions or establish an original Rust API.

## First-party association and caller census

The direct-call site `0x2894df8` lies in the FDE
`0x28946b0..0x2894f94`. That same FDE contains
LEA `0x2894cd0` to Location `0x64768a8`. Its unique
R_X86_64_RELATIVE relocation binds the file string `l1/src/perp_meta.rs`,
line 163, column 38. The encoded path length and all bytes are
preserved. This is first-party caller
association, not proof of the leaf's original name, owner or field types. The
binary uses a relative source path here; no build-machine path is invented.

The entire `.text` interval `0x1419300..0x63f0a00`
(83719936 bytes) is scanned at every possible byte offset for
complete E8/E9 signed-rel32 encodings that resolve to the leaf's entry. This yields
4 E8 candidates and 0 E9
candidates in 4 containing FDEs. Local argument-load/call contexts
are decoded, and the available immediate CMP AL,2 uses are retained.

| Candidate site | Raw transfer | Containing FDE |
| --- | --- | --- |
| `0x22e5bbb` | `e8d0969800` | `0x22e56a0..0x22e5c8e` |
| `0x22e60d0` | `e8bb919800` | `0x22e5c90..0x22e617a` |
| `0x2894df8` | `e893a43d00` | `0x28946b0..0x2894f94` |
| `0x289566d` | `e81e9c3d00` | `0x2894fa0..0x28957ad` |

This is a complete byte-pattern census for those opcodes and that destination,
not a full caller CFG or reachability proof. Local context decoding alone cannot
exclude an encoding embedded in a longer instruction. Indirect references,
interior-entry transfers, other executable sections, data pointers and dynamic
callers remain unmeasured. No caller's complete behavior is bound here.
Callee identities/extents are an empty set: the fully decoded leaf has none.

## Novelty and scope

Before creating this packet, the following commands each produced empty stdout
and stderr with rg exit status 1 (no matches):

```sh
rg -i '2c6f290' research/
rg -i '46592656' research/
rg -i '2c6f290' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '46592656' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

These are historical pre-addition checks; this packet now contains the address.
There are no callee addresses requiring a separate novelty check. The function
is inside the assigned address band and outside the excluded band. Work is
limited to RE-001 and the new tool, targeted tests and this packet. Existing
work items, imports, submodules, catalogue and acceptance gates are unchanged.
The generator is packet-specific evidence reproduction requested by this task,
not a standalone infrastructure change.

## Reproduction and validation scope

From the repository root, with the authenticated capture materialized:

```sh
python3 tools/node115_tuple_threshold.py --out research/work-items/RE-001-node115-tuple-threshold/
python3 -m unittest tests.test_node115_tuple_threshold -v
python3 research/work-items/RE-001-node115-tuple-threshold/verify.py
make verify
make catalogue-check
```

Python 3.10+ stdlib only; developed with Python 3.13.5 on Linux x86-64.
GNU objdump 2.44 was used for initial manual reconnaissance only; no generator,
verifier or test calls it or parses its output. No REA provider was connected.
The generator authenticates the whole image before interpretation or output,
uses a read-only mmap, and regenerates records and this README byte-identically.
The static verifier is copied unchanged into an alternate output directory;
the manifest binds its exact whitelist plus the generator, tests and shared
stdlib-only ELF/FDE parsers. It rejects unknown/duplicate/missing manifest entries,
path escapes, changed files and discrepancies with regenerated evidence.
No absolute local paths, host state or generation times enter the evidence.

Negative controls cover wrong/truncated input, a one-bit corruption at every
body-byte position,
unknown/truncated decoding, altered signedness and threshold predicates, paired
arithmetic constants, shifted FDEs, duplicate FDE identity, caller retargeting,
source relocation duplication/corruption and changed Location metadata/padding.
The README equality test checks all displayed counts against JSON, and JSON
counts are separately checked against their underlying semantic arrays.
Below-digest mutations are private component tests, never alternate admitted
captures. Static generation and local targeted checks are the validation scope;
repository-wide tests and hosted CI are not claimed here.

## Non-claims, unresolved questions and next step

Before: the leaf had no retained behavioral bind. After: the complete bytes,
control flow, scalar return rule and helper-free closure are reproducible.
Rust implementation, source-build identity, compiler flags/dependency versions,
whole ELF equality, Rust type/ABI recovery and component completion remain
not yet implemented or measured. There is no source-versus-binary comparison
and no normalization mask. The source Location association does not identify
units, timestamps, business meaning or an enum/Option representation. Concurrent
mutation, invalid pointers and fault behavior are excluded by the stable valid
memory precondition; native target execution has not occurred.

No progress gate is requested. The next bounded question is to establish the
provenance of the caller's RDI object and its compared fields before assigning
protocol, time or trading meaning to the raw return values.
