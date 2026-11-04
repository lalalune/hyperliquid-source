# RE-001: two-span address projection at 0x152e360

- Component: unassigned collection/iteration helper; RE-001 function map. Target node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base/source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no upstream source used.
- Question: what four words does this complete function produce from the four input words, and how does it handle a wrap across the capacity-like boundary?
- Answer: with unsigned 64-bit modular arithmetic, let C, B, H, N be the input words at offsets 0, 8, 16 and 24. If N is zero, the four outputs are all B. Otherwise set A = H-C if H >= C, else H; let R = C-A (modulo 2^64). If N > R unsigned, output `(B+80*A, B+80*C, B, B+80*(N-R))`; otherwise output `(B+80*A, B+80*(A+N), B, B)`. All output arithmetic is modulo 2^64. RAX returns the supplied output pointer. Under the usual ring preconditions C > 0, H < 2*C and N <= C, these are the endpoints of up to two contiguous 80-byte-stride spans; that interpretation and the word names are inferred, not original types.

## Evidence and procedure

The original ELF VA range is `0x152e360..0x152e3d2` (114 bytes), file offset `0x152d360`. Body SHA-256 is `03498aac7c2644baab2ce7d76e131d62319f0ef9c5526c628aecf00d16f63666`. The FDE is at `.eh_frame+0xd470` (file `0xcb4348`), CIE at `.eh_frame+0x0`; raw records and decoded endpoints are in JSON. The FDE ends at RET; the next 14 bytes are `cc` padding. This establishes this window, not a whole-function census. The output buffer must be writable for 32 bytes; the accessed input words must be readable and disjoint from output. Arbitrary pointers, object invariants, aliasing, concurrency and unwinding are outside the claim.

The complete byte walk has 37 instructions; branch destinations are computed from signed encoded displacements. The subtract at `0x152e388` sets flags for unsigned `ja`: equality belongs to the nonwrap arm. The single conditional subtraction at `0x152e378` does not perform a general modulo. The three LEA/shift sequences multiply by 80 modulo 2^64. The zero-count arm skips loading C and H. There are 0 callees, including tail transfers, and no indirect dispatch in this body.

| ELF VA | Bytes | Decoded operation |
| --- | --- | --- |
| `0x152e360` | `4889f8` | `mov rax,rdi` |
| `0x152e363` | `4c8b4618` | `mov r8,[rsi+0x18]` |
| `0x152e367` | `4d85c0` | `test r8,r8` |
| `0x152e36a` | `742b` | `je` → `0x152e397` |
| `0x152e36c` | `488b16` | `mov rdx,[rsi]` |
| `0x152e36f` | `488b4e10` | `mov rcx,[rsi+0x10]` |
| `0x152e373` | `31ff` | `xor edi,edi` |
| `0x152e375` | `4839d1` | `cmp rcx,rdx` |
| `0x152e378` | `480f43fa` | `cmovae rdi,rdx` |
| `0x152e37c` | `4829f9` | `sub rcx,rdi` |
| `0x152e37f` | `4989d1` | `mov r9,rdx` |
| `0x152e382` | `4929c9` | `sub r9,rcx` |
| `0x152e385` | `4c89c7` | `mov rdi,r8` |
| `0x152e388` | `4c29cf` | `sub rdi,r9` |
| `0x152e38b` | `7710` | `ja` → `0x152e39d` |
| `0x152e38d` | `4901c8` | `add r8,rcx` |
| `0x152e390` | `31ff` | `xor edi,edi` |
| `0x152e392` | `4c89c2` | `mov rdx,r8` |
| `0x152e395` | `eb06` | `jmp` → `0x152e39d` |
| `0x152e397` | `31c9` | `xor ecx,ecx` |
| `0x152e399` | `31d2` | `xor edx,edx` |
| `0x152e39b` | `31ff` | `xor edi,edi` |
| `0x152e39d` | `488b7608` | `mov rsi,[rsi+8]` |
| `0x152e3a1` | `488d0c89` | `lea rcx,[rcx+rcx*4]` |
| `0x152e3a5` | `48c1e104` | `shl rcx,4` |
| `0x152e3a9` | `4801f1` | `add rcx,rsi` |
| `0x152e3ac` | `488d1492` | `lea rdx,[rdx+rdx*4]` |
| `0x152e3b0` | `48c1e204` | `shl rdx,4` |
| `0x152e3b4` | `4801f2` | `add rdx,rsi` |
| `0x152e3b7` | `488d3cbf` | `lea rdi,[rdi+rdi*4]` |
| `0x152e3bb` | `48c1e704` | `shl rdi,4` |
| `0x152e3bf` | `4801f7` | `add rdi,rsi` |
| `0x152e3c2` | `488908` | `mov [rax],rcx` |
| `0x152e3c5` | `48895008` | `mov [rax+8],rdx` |
| `0x152e3c9` | `48897010` | `mov [rax+0x10],rsi` |
| `0x152e3cd` | `48897818` | `mov [rax+0x18],rdi` |
| `0x152e3d1` | `c3` | `ret` |

A full `.text` byte scan for `e8` and `e9` plus signed rel32 yields 2 candidate sites: `0x14f7fdc`, `0x14fa686`. Both are direct call opcodes, in FDEs `0x14f7200..0x14f8469` and `0x14f9dd0..0x14fabb0` respectively, with local disassembly confirming instruction starts. This byte scan includes possible embedded-data/overlapping false positives and excludes indirect calls and transfers into the body; it is not reachability or a complete call graph. Caller ownership is not identified. No callee behavior is bound.

## Reproduce and controls

Static only; Python 3.10+ stdlib, run from repository root. The producer authenticates the whole artifact before extraction and scans the specified complete `.text` byte interval, without executing it. GNU readelf/objdump 2.44 were used independently for focused FDE/caller inspection, not by the producer or tests. Analysis is complete only for this body and the specified byte scan; no normalization masks or binary comparisons were applied.

```sh
python3 tools/node115_two_span_projection.py --out research/work-items/RE-001-node115-two-span-projection/
python3 -m unittest tests.test_node115_two_span_projection -v
python3 research/work-items/RE-001-node115-two-span-projection/verify.py
make verify
make catalogue-check
```

Novelty before analysis: `rg -i '152e360|22209376' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt` returned no matches (exit 1). This includes both hex and decimal start; there are no callees to check. The catalogue seed record contains no inferred node #115 reference-address seeds. `make doctor` and `make verify` passed before selection.

The tests exercise instruction and FDE corruption, wrong full-file digest, a redirected direct call, the README counts against JSON, and boundary vectors based on the decoded operations. The independent model is a statement of the byte-level relation, not target execution or evidence of a recovered original API.

## Limits and next step

Original name, owner, collection type, allocation validity, callers' full behavior and first-party attribution remain unknown. No Rust implementation, source build, byte comparison, whole-node behavior or progress gate is claimed. Next, trace the two caller FDEs and their input construction to establish whether the four addresses actually delimit ring segments in a first-party path.
