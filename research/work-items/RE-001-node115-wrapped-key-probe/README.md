# RE-001: node #115 wrapped key probe

This packet binds the complete computation at `0x2ee0640` for node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Component: foundation, first-party map-associated search.
Base/reference revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New analysis, code and tests are independently
authored under the repository MIT license. No source implementation was copied.

Bounded question: given a valid circular storage descriptor and a sorted sequence
of unsigned keys, which status and logical position does this function return,
including equality at the wrap boundary?

Answer: it returns `(RAX,RDX) = (0,index)` for a matching key and `(1,index)`
for a missing key's insertion position. The search compares unsigned qword keys
at the start of each record. Empty input returns missing at the beginning.
Ordinary search paths choose the last equal key. The exception is a wrapped
sequence whose first physically stored key equals the query: the function
immediately returns that key's logical position at the seam, even if later
duplicates exist. It performs no explicit memory writes and has no callees.

## Scope, bytes and measured counts

All addresses are original ELF virtual addresses, all intervals half-open.
The function is `[0x2ee0640,0x2ee0761)`, file offset `0x2edf640`.
Its body SHA-256 is `1efd73cd0cb516ac291a6d28230f91c441e5953af233dd06c3d4f176560b91fa`. Actual FDE `0xda2e70`, CIE `0xca6ed8`
(`zR`, no personality or LSDA) supplies the same extent. The strict decoder
covers its entire body and every branch lands on an internal instruction boundary.
All exits are local returns; the next FDE starts at `0x2ee0770`. The intervening
bytes are INT3 fill, excluded from the body. FDE/CIE raw bytes, file offsets,
header-index binding, body bytes and complete instruction walks are retained.
The FDE alone is not used to infer a boundary; the return-closed control flow
and external padding supply additional evidence.

These are local evidence counts, not node-wide coverage or accepted gates:

| JSON count key | Value |
| --- | ---: |
| bound_functions | 1 |
| body_bytes | 289 |
| body_instructions | 92 |
| return_sites | 3 |
| conditional_branches | 12 |
| padding_bytes | 15 |
| callees | 0 |
| direct_call_sites | 1 |
| direct_caller_functions | 1 |
| tail_jump_sites | 0 |
| caller_context_bytes | 1152 |
| caller_context_instructions | 266 |
| frozen_vectors | 21 |

`records.json` carries the semantic facts, original operands, source association,
caller evidence and instruction-derived vectors. `instructions.txt` is the
complete strict decode of the leaf and its caller context. No instruction,
operand, relocation or raw body byte is normalized or masked.

## Instruction proof and raw layout

Let `C = qword[RDI+0]`, `P = qword[RDI+8]`, `H = qword[RDI+0x10]`,
`N = qword[RDI+0x18]`, and `K = qword[RSI]`. The observed stride is `0x20`;
only the initial qword of each record is compared. Capacity, head, length and
circular storage are descriptive inferences from these operations, not recovered
Rust field names or ABI types.

For nonempty input, assume `C>0`, `N<=C`, `H<2*C`, readable storage and query,
nonwrapping address calculations, and logical keys sorted in nondecreasing
unsigned order. Memory must remain stable during the call. Empty input skips
the key load and storage dereferences, though it still reads the descriptor's
pointer word. Invalid pointers, unsorted keys and malformed geometry have no
search-contract guarantee; the machine contains no corresponding validation.

* `0x2ee0640..0x2ee066a`: load N; empty branches to zero positions. Otherwise
  normalize `h = H - (H>=C ? C : 0)` using unsigned CMOVAE, compute
  `t=C-h`, and select wrapped storage exactly when `N>t` through SUB/JBE.
* `0x2ee066c..0x2ee068e`: load `qword[P]` and K. CMP/SETA/SBB yields the
  ordering byte: below, equal or above. MOVZX makes this an exact full-word
  value. Equality returns immediately at `0x2ee074c` with RAX zero and RDX=t.
  A smaller physical-first key selects the wrapped second span; a larger key
  selects the tail span. These comparisons are unsigned.
* `0x2ee0694..0x2ee06e3`: search the second span, with length `N-t` and a
  logical index bias t. Maintain cursor b and span s. Each iteration computes
  `half=floor(s/2)`, tentatively advances b, restores the old b only when
  `key[b+half]>K` (CMOVA), and sets `s=s-half`. Thus ties advance. SHR and
  SHL encode the midpoint and record stride. Span strictly decreases until
  its final record is tested. Equality returns found; otherwise ADC adds
  the unsigned less-than carry to produce the insertion position. SETNE
  supplies missing/found status and ADD applies the logical bias.
* `0x2ee06e4..0x2ee0703`: the empty route forms a zero-length span; the
  nonwrapped route forms `[P+h*stride, N]`. Neither wrap branch means a
  second-span search is needed. EAX is initialized to the missing status.
* `0x2ee0705..0x2ee074c`: the tail/nonwrapped loop uses the same midpoint,
  unsigned CMOVA and decreasing-span recurrence. The final equal path
  clears EAX; the unequal path uses carry-preserving JNE and ADC to produce
  insertion position. RDX receives the position without a seam bias.
* `0x2ee074d..0x2ee0760`: a wrapped query below the physical-first key
  enters the tail search; the empty route returns missing at the beginning.

For any nonempty sorted chosen span, the recurrence retains the final key
less than or equal to K, or its initial key if every key is greater. The final
comparison distinguishes equality from the insertion gap. When the ring wraps,
comparing K with the first key of the second span selects the only possible
span, except for immediate seam equality. This proves the stated duplicate
exception rather than assuming a unique-key invariant from the caller.

The independently authored `rule_model` uses `bisect_right` on logical keys
plus the seam rule. A separate `instruction_relation` implements the extracted
value recurrence. Frozen vectors cover empty/singleton inputs, both spans,
exact-end geometry, gaps, repeated keys, head normalization and unsigned
extremes. The tests also compare both formulations over exhaustive small sorted
rings. These are static model checks, not execution or emulation of the capture.

## Callees, caller census and first-party association

The leaf's callee set is empty: the complete decode contains no CALL or indirect
transfer and no branch leaves its extent. There is no helper behavior to assume.

The census scans every possible E8/E9 rel32 start in the complete `.text`
interval `[0x1419300,0x63f0a00)`, including bytes that might be inside another
instruction. The retained hit is E8 at `0x2eedcf9`, targeting this leaf, inside
the actual caller FDE `[0x2eedb70,0x2eedff0)`. The complete caller is strictly
decoded from its FDE start and its local branch targets align, so this hit is
an instruction boundary rather than an unaligned byte-pattern coincidence.
Indirect references, other executable sections and runtime reachability are
outside this direct census. Caller metadata and full decode are context only;
the caller's other callees, exception paths and whole behavior are unbound.

At `0x2eedcee` the caller passes a stack query address in RSI, and at
`0x2eedcf6` it passes its retained descriptor pointer in RDI. The source LEA at
`0x2eedfa1` addresses Location `0x6461510`. An actual R_X86_64_RELATIVE entry
at file offset `0x8cb68` binds that Location's path pointer to `0x4402cd`,
the captured relative path `base/src/l1_map/entry.rs`, line `0x40`, column `0x11`.
The path, length, line/column, LEA displacement and relocation are all checked.
This establishes association with first-party map code; it does not prove the
leaf's original symbol, concrete collection type, or a standard-library origin.

## Novelty and reproduction

Before creating this packet, the following commands each exited with status 1
and empty stdout/stderr. No function callee required a separate address check.
The slug was also absent from the research, tool/test and supplied PR lists.
These are pre-change checks; the address is expected to occur in this packet
after creation. The PR-list snapshot is supplied input, not a live upstream query.

```sh
rg -i '2ee0640' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '49153600' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'wrapped.key.probe' research/ tools/ tests/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

Run from repository root using Python 3.10+ standard library only. Development
used Python 3.13.5 on Linux x86-64; GNU objdump 2.44 was used for initial bounded
inspection (`-d -Mintel --start-address=0x2ee0640 --stop-address=0x2ee0761`).
Neither the generator, verifier nor tests invoke or import a native decoder.
No package installation, network, target execution or environment capture occurs.
Input identity is checked before decoding or creating output. The target is
memory-mapped; the tool does not create full-size binary copies.

```sh
python3 tools/node115_wrapped_key_probe.py --out research/work-items/RE-001-node115-wrapped-key-probe/
python3 -m unittest tests.test_node115_wrapped_key_probe -v
python3 research/work-items/RE-001-node115-wrapped-key-probe/verify.py
make verify
make catalogue-check
make reproduce
```

The generator rewrites only the deterministic records, instruction walk and this
README. The independently reviewed verifier and manifest are packet source files.
The manifest binds all packet payloads plus the new tool and test. Verification
requires an exact path whitelist, checks every hash and regenerates evidence
byte-identically in a temporary directory. The test suite checks README metrics
against JSON and attacks the whole-image digest, operative bytes, actual FDE
start/range, caller target, source relocation and manifest whitelist. The private
structural checks are deliberately callable beneath authentication for corruption
tests; the public generator always authenticates first.

## Results, non-claims and next step

Before this work the selected address had no retained behavioral bind. This
packet establishes its search rule, including the seam equality exception,
complete local instruction/branch closure and a source-associated direct caller.
The models are small value specifications, not reconstructed Rust or original
source. A compiler build, two-build reproducibility, binary comparison and ABI
equivalence have not been implemented or measured. No normalization masks apply.
Source-level relocation/vtable integration, whole-ELF equivalence, dynamic caller
coverage, protocol meaning and hosted CI remain unproved. All component and
full-scope RE-001 gates remain unchanged and incomplete.

Local validation passed: targeted unittests, byte-identical regeneration and
packet verification, `make verify`, `make catalogue-check`, and `make reproduce`.
The repository-wide `make test` was not run; no hosted or container result is
claimed. An initial development run caught misplaced CMOV mutation offsets and
an incorrect model-case count in the test fixtures. Those fixtures were corrected;
the operative CMOV change now demonstrably changes duplicate selection before
the semantic checker rejects it. No binary mismatch or model disagreement was
suppressed.

Next question: establish the caller's key-uniqueness and storage-transition
invariants before assigning a concrete map API or using this rule in Rust.
