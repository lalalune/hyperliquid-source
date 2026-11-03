# RE-001: indirect triplet insertion at 0x26d4280

- Component: foundation function mapping, with a direct consensus-state caller (RE-008 context).
- Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository/reference revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No external implementation source is used.
- Status: bytes, extents, transfers and key comparisons are observations; insertion-sort role and argument names are inferences proved below. Original Rust names/types remain unresolved.
- Bounded question: what does this complete leaf compute, including its entry guard, record movement, signedness and ties?

Given RDI pointing to writable records, RSI = n and RDX = k, the leaf traps with
UD2 unless `1 <= k <= n`; at `k == n` it returns without reading the records.
Otherwise it performs stable insertion of each record in the suffix beginning
at k into the preceding prefix. Each record consists of a payload word and a
key pointer. Keys compare lexicographically as `(i32, u32, u32)` loaded from
that pointer. Both words of each moved record are preserved, equal keys do not
cross, and an initially sorted prefix yields a fully sorted result. No scalar
return value is assigned a meaning. This is a complete local memory-transform
contract under the memory preconditions below, not a recovered consensus policy.

## Scope and measurements

All addresses are original ELF virtual addresses; ranges are half-open.
The selected window is `[0x26d4280, 0x26d4376)`, file offset `0x26d3280`.
Actual FDE `0xd44330` (same file offset) references CIE `0xca6ed8`;
the CIE uses zR/pcrel-sdata4 and the FDE has no LSDA. The selected unwind-header
entry independently points to that FDE. The FDE, terminal RET/UD2, internal
branch boundaries and following INT3 fill jointly support this body extent;
the start table alone is not the boundary argument.

Body SHA-256: `96b785127b56f7b4af1568aa67d397f88564ace441aff825c905cbc1cfc44531`. Raw instruction, FDE and CIE bytes are in
`records.json`. Internal `0x26d42f6..0x26d4300` is an unreachable decoded NOP;
`0x26d4376..0x26d4380` is INT3 padding outside the body, up to the next FDE.

<!-- metrics derived from records.json; checked by the targeted tests -->
| Measurement | Count |
| --- | ---: |
| Bound function bodies | 1 |
| Function bytes (including internal NOP) | 246 |
| Decoded function instructions (including internal NOP) | 74 |
| Reachable function instructions | 73 |
| Internal unreachable NOP bytes | 10 |
| Post-FDE INT3 bytes (excluded from body) | 10 |
| Callees | 0 |
| Indirect transfers | 0 |
| Raw full-text E8/E9 matches | 1 |
| Distinct direct caller FDEs | 1 |
| Frozen semantic vectors | 25 |
<!-- end metrics -->

The leaf's callee list is empty: there is no call, tail transfer, indirect
dispatch, RIP data access, allocation or external arithmetic helper to close.
All branches stay within the decoded body. Stack PUSH/POP saves RBX/RBP on the
insertion route; the early return and entry trap precede those saves.

## Rule proof from the instruction walk

`0x26d4280..0x26d4296` forms `(k-1) mod 2^64`, compares it unsigned to n, and
branches to UD2 on greater-or-equal. Thus zero k traps even for maximum n;
k greater than n also traps. Equality k=n is tested only after this guard.
No object/key memory is read on either of these entry exits. On the early
return, RAX retains `k-1`; after a completed insertion route it equals the
computed end pointer `base + 16*n`. These are observed register residues,
not an inferred Rust return type.

The shifts at `0x26d4298` and `0x26d429f` multiply the count and index by the
record width `16`. RAX becomes the current record pointer and
RSI the end pointer; RDX is the previous-record byte offset. The initial
comparison loads the previous key pointer at current-minus-8
and the current key pointer at current-plus-8.
The key loads at offsets `[0, 4, 8]` have widths
`[32, 32, 32]`. SETL at `0x26d42d6` and `0x26d434f` implements signed
comparison of the first word. SETB at `0x26d42e4` and `0x26d435b` implements
unsigned comparison of the second. The first unequal word decides; when both
tie, JAE at `0x26d42f2` skips movement for unsigned greater-or-equal third words,
and JB at `0x26d4367` continues shifting only for unsigned strictly smaller ones.
SETcc does not overwrite comparison flags, so the following JNE still tests
the associated CMP equality, not the SETcc result.

When a record belongs earlier, `0x26d4305..0x26d4313` saves its payload in R8
and retains its key pointer in RCX, then copies the preceding entire record
rightward using MOVUPS. R9 tracks the hole, R11 the hole's byte offset, and
R10 the eventual store address. The inner loop compares the saved key against
the record before the hole and shifts that record only when the saved key is
strictly smaller. At the left edge it stores at the base; otherwise it stores
at the first hole whose predecessor is less-or-equal. `0x26d42b0..0x26d42b7`
restores both saved words. The outer step advances the current position and
previous-record offset equally, stopping at the end pointer.

Invariant: processed records are a permutation of their initial records, with
the current record temporarily held in R8/RCX during shifts. With an initially
sorted prefix, each insertion preserves prefix order. The inner hole moves
strictly toward the base and the outer cursor moves strictly toward the end,
so valid finite input terminates. Strict comparisons preserve equal-key order.
An unsorted initial prefix is not promised to become sorted; frozen vectors
explicitly retain that distinction. The model is an independent value-level
Python implementation, not execution or emulation of captured instructions.

Required memory assumptions: the record range is writable, its keys are
readable for the complete key width, key storage stays unchanged by row
movement, stack storage is valid and disjoint, and shifted sizes/pointer
arithmetic do not wrap or leave the allocation. Key pointers may be shared
when their pointees remain immutable. Invalid addresses, concurrent mutation,
hardware exceptions during memory access and writable-key aliasing are outside
this normal-transform contract. Guard behavior itself needs no record memory.

### Complete byte-decoded walk

```text
026d4280  488d42ff               lea rax, [rdx-1]
026d4284  4839f0                 cmp rax, rsi
026d4287  0f83e7000000           jae 0x26d4374
026d428d  4839f2                 cmp rdx, rsi
026d4290  0f84dd000000           je 0x26d4373
026d4296  55                     push rbp
026d4297  53                     push rbx
026d4298  48c1e604               shl rsi, 4
026d429c  4801fe                 add rsi, rdi
026d429f  48c1e204               shl rdx, 4
026d42a3  488d0417               lea rax, [rdi+rdx*1]
026d42a7  4883c2f0               add rdx, -16
026d42ab  eb1b                   jmp 0x26d42c8
026d42ad  4989fa                 mov r10, rdi
026d42b0  4d8902                 mov 64-bit [r10], r8
026d42b3  49894a08               mov 64-bit [r10+8], rcx
026d42b7  4883c010               add rax, 16
026d42bb  4883c210               add rdx, 16
026d42bf  4839f0                 cmp rax, rsi
026d42c2  0f84a9000000           je 0x26d4371
026d42c8  4c8b40f8               mov r8, 64-bit [rax-8]
026d42cc  488b4808               mov rcx, 64-bit [rax+8]
026d42d0  448b09                 mov r9d, 32-bit [rcx]
026d42d3  453b08                 cmp r9d, 32-bit [r8]
026d42d6  410f9cc1               setl r9b
026d42da  7524                   jne 0x26d4300
026d42dc  448b4904               mov r9d, 32-bit [rcx+4]
026d42e0  453b4804               cmp r9d, 32-bit [r8+4]
026d42e4  410f92c1               setb r9b
026d42e8  7516                   jne 0x26d4300
026d42ea  448b4908               mov r9d, 32-bit [rcx+8]
026d42ee  453b4808               cmp r9d, 32-bit [r8+8]
026d42f2  73c3                   jae 0x26d42b7
026d42f4  eb0f                   jmp 0x26d4305
026d42f6  662e0f1f840000000000   nop
026d4300  4584c9                 test r9b, r9b
026d4303  74b2                   je 0x26d42b7
026d4305  4c8d48f0               lea r9, [rax-16]
026d4309  4c8b00                 mov r8, 64-bit [rax]
026d430c  410f1001               movups xmm0, 128-bit [r9]
026d4310  0f1100                 movups 128-bit [rax], xmm0
026d4313  4989fa                 mov r10, rdi
026d4316  4939f9                 cmp r9, rdi
026d4319  7495                   je 0x26d42b0
026d431b  4989d3                 mov r11, rdx
026d431e  eb22                   jmp 0x26d4342
026d4320  4084ed                 test bpl, bpl
026d4323  748b                   je 0x26d42b0
026d4325  4983c1f0               add r9, -16
026d4329  4a8d1c1f               lea rbx, [rdi+r11*1]
026d432d  4883c3f0               add rbx, -16
026d4331  0f1003                 movups xmm0, 128-bit [rbx]
026d4334  410f1102               movups 128-bit [r10], xmm0
026d4338  4983c3f0               add r11, -16
026d433c  0f846bffffff           je 0x26d42ad
026d4342  4e8d141f               lea r10, [rdi+r11*1]
026d4346  4a8b5c1ff8             mov rbx, 64-bit [rdi+r11*1-8]
026d434b  8b29                   mov ebp, 32-bit [rcx]
026d434d  3b2b                   cmp ebp, 32-bit [rbx]
026d434f  400f9cc5               setl bpl
026d4353  75cb                   jne 0x26d4320
026d4355  8b6904                 mov ebp, 32-bit [rcx+4]
026d4358  3b6b04                 cmp ebp, 32-bit [rbx+4]
026d435b  400f92c5               setb bpl
026d435f  75bf                   jne 0x26d4320
026d4361  8b6908                 mov ebp, 32-bit [rcx+8]
026d4364  3b6b08                 cmp ebp, 32-bit [rbx+8]
026d4367  72bc                   jb 0x26d4325
026d4369  4d89ca                 mov r10, r9
026d436c  e93fffffff             jmp 0x26d42b0
026d4371  5b                     pop rbx
026d4372  5d                     pop rbp
026d4373  c3                     ret
026d4374  0f0b                   ud2
```

## Caller census and first-party association

The producer scans every possible byte start of E8/E9 rel32 encodings in
`.text [0x1419300, 0x63f0a00)`, including overlapping candidates. The only hit is
CALL `0x2e10682` in actual FDE `0x2e098e0..0x2e11140`. The selected context
`0x2e1066e..0x2e1068c` decodes the call and its immediate setup:
the fallthrough branch requires `n < 21`,
and EDX is `1`. This establishes a use of the leaf
as a small-range sort, conditional on reaching that block with valid memory;
the whole caller's reachability and collection identity are not proved.

In the same caller FDE, LEA `0x2e0ab42` names Location `0x6451b88`.
Its checked R_X86_64_RELATIVE relocation at file offset `0x77f58`
names `node/src/consensus/state.rs:550:17`; pointer, length, line, column and literal
bytes are regenerated. This is direct first-party caller evidence, not an
original symbol or proof that the leaf was authored in that source file.
No behavior is bound for the caller's other callees. The caller FDE/CIE bytes
are retained only to support ownership of these selected sites.

The raw scan is not a whole-text instruction decoder. Its hit is corroborated
by the strict caller-context decode and by exploratory GNU decoding from the
caller's FDE entry. No additional raw hit was discarded. Address-taken uses,
indirect callers, alternate entrypoints, short branches into the body and
references outside .text are not covered by this direct-reference census.

## Novelty before packet creation

At the repository/reference revision above, each command below produced empty
stdout and exit status 1 (no matches). The hexadecimal and decimal checks cover
the function start; there are no behavior-bound callees to check. These are
historical pre-addition observations, not commands expected to stay empty after
this packet is added. PR lists are the provided local snapshots, not live data.

```sh
rg -i '26d4280' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '40714880' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'indirect-triplet-insertion|indirect_triplet_insertion' research/work-items/ tools/ tests/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Reproduce and controls

From the repository root, with the authenticated artifact materialized:

```sh
python3 tools/node115_indirect_triplet_insertion.py --out research/work-items/RE-001-node115-indirect-triplet-insertion/
python3 -m unittest tests.test_node115_indirect_triplet_insertion -v
python3 research/work-items/RE-001-node115-indirect-triplet-insertion/verify.py
make verify
make catalogue-check
```

Python 3.10+ standard library is sufficient; local validation used Python 3.13.5
on Linux x86-64. The narrow instruction decoder, selected FDE checks, source
relocation and full-text scan use bytes only. Existing `elf_index.py` and
`fde_extents.py` supply section/FDE parsing and are included in the manifest.
Exploration used GNU objdump 2.44 with `-d -Mintel --insn-width=16` and bounded
`--start-address`/`--stop-address` for the selected and caller FDEs; its transient
output is under ignored work/. Producer, verifier and tests never invoke it.

The producer authenticates size and the full target digest before parsing or
creating output. It memory-maps the binary, materializing only small evidence
windows. It regenerates `records.json` and this README from authenticated bytes
and independently authored rule/proof text; it copies the verifier source and
hashes exactly its named source/evidence dependencies into MANIFEST.sha256.
The verifier rejects missing, extra, duplicate, changed or symlinked whitelist
entries, then requires byte-identical regeneration of JSON and README.

Controls exercise wrong identity, actual instruction and signedness changes,
shifted FDE, CIE corruption, wrong incoming call destination, changed padding,
source Location/relocation corruption, section geometry and scanner boundaries.
All binary mutations are private static mappings; none is executed. Frozen
vectors cover entry traps, signed/unsigned extremes, each tie-break, left-edge
and inner-loop shifts, equality stability and the sorted-prefix precondition.
Additional independent Python sorting checks exercise the model, not the node.
README measurement counts are computed from JSON and checked against that JSON.

## Results, non-claims and next step

Before this packet, the selected function had no binding in the checked research
tree or provided PR-title snapshots. This packet closes its complete local
record-movement rule, the mixed signedness and tie handling, and entry trap.
The required targeted checks are recorded in the accompanying submission body;
no repository-wide test completion, hosted CI or container result is claimed.

No Rust implementation, compiled comparison, normalization mask, original
function/type name, original crate ownership, consensus policy, whole-caller
contract, full ABI recovery, runtime differential result or whole-ELF identity
is claimed. The abstract Python model is not reconstruction credit. No progress
gate is requested or changed. Source pins and imported evidence are untouched.
The leaf has no static-data/callee closure gap; broader caller, allocation,
key-layout provenance and integration gaps remain outside its bounded contract.

Next question: trace the caller's record construction and key-pointer provenance
to assign meanings to the key words, and prove the caller's positive-length and
valid-memory conditions before using this ordering in reconstructed consensus.
