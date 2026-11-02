# RE-001: bind node #115 twenty-byte sequence equality

- Component: foundation / raw-signature-tracker caller association. Bounded function mapping only.
- Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New producer, model, tests and prose are independently authored under the root MIT license; no private source was copied.
- Bounded question: what does the entire function at `0x5436860` return for the pointer/count pairs in RDI/RSI and RDX/RCX?

**Answer (observed instruction rule):** AL is 1 exactly when the counts agree and all corresponding bytes in all 20-byte records agree; otherwise AL is zero. Unequal counts return without reading either sequence. Equal empty sequences return true without reading either sequence. For a nonempty equal-count pair, the function reads each record as an unaligned 16-byte head and a 4-byte tail, stops at the first differing record, and returns true after the last matching record. It does not write input memory. Only AL is the result contract; the other bits of RAX and the modified argument registers are not a boolean return contract.

## Extent and instruction evidence

All addresses are original ELF virtual addresses, with half-open ranges. The body is `[0x5436860, 0x54368b6)`, file offset `0x5435860`, SHA-256 `a1578fc383b85292cf51fb5c366c98373cbe1a98b10b0c8bdfbd3fe8e19556e5`. Its actual FDE is at VA/file offset `0xf7e004`, referencing CIE `0xca6ed8`; the augmentation has no LSDA. FDE/CIE bytes, all body bytes, instruction operands and caller slices are retained in `records.json`. The complete entry-to-return CFG agrees with this FDE, with no outgoing call or tail jump. The trailing INT3 bytes end at the next FDE start `0x54368c0`; they are outside the body. No input byte, address, displacement or operand is normalized.

Every metric below is computed from the JSON evidence; the targeted test checks this table and the complete generated README.

| JSON metric | Value |
| --- | ---: |
| `body_bytes` | 86 |
| `instructions` | 28 |
| `padding_bytes` | 10 |
| `callees` | 0 |
| `indirect_transfers` | 0 |
| `direct_call_sites` | 2 |
| `direct_caller_fdes` | 1 |
| `direct_tail_sites` | 0 |
| `semantic_vectors` | 69 |

The finite Python decoder accepts exact opcode/ModRM forms, parses relative displacements and immediates, covers the complete body, and rejects unknown or truncated encodings. It also decodes every instruction used in the selected caller/source slices. These slices do not imply a complete caller CFG. The generator and verifier use no native disassembler.

| VA | Raw bytes | Decoded instruction |
| --- | --- | --- |
| `0x5436860` | `4839ce` | cmp rsi, rcx |
| `0x5436863` | `754b` | jne  `0x54368b0` |
| `0x5436865` | `4885f6` | test rsi, rsi |
| `0x5436868` | `7449` | je  `0x54368b3` |
| `0x543686a` | `48ffce` | dec rsi |
| `0x543686d` | `0f1f00` | nop dword [rax] |
| `0x5436870` | `f30f6f07` | movdqu xmm0, xmmword [rdi] |
| `0x5436874` | `f30f6f0a` | movdqu xmm1, xmmword [rdx] |
| `0x5436878` | `660f74c8` | pcmpeqb xmm1, xmm0 |
| `0x543687c` | `660f6e4710` | movd xmm0, dword memory [rdi+16] |
| `0x5436881` | `660f6e5210` | movd xmm2, dword memory [rdx+16] |
| `0x5436886` | `660f74d0` | pcmpeqb xmm2, xmm0 |
| `0x543688a` | `660fdbd1` | pand xmm2, xmm1 |
| `0x543688e` | `660fd7c2` | pmovmskb eax, xmm2 |
| `0x5436892` | `4883c6ff` | add rsi -1 |
| `0x5436896` | `0f92c1` | setb cl |
| `0x5436899` | `3dffff0000` | cmp eax 65535 |
| `0x543689e` | `0f94c0` | sete al |
| `0x54368a1` | `750c` | jne  `0x54368af` |
| `0x54368a3` | `4883c214` | add rdx 20 |
| `0x54368a7` | `4883c714` | add rdi 20 |
| `0x54368ab` | `84c9` | test cl, cl |
| `0x54368ad` | `75c1` | jne  `0x5436870` |
| `0x54368af` | `c3` | ret  |
| `0x54368b0` | `31c0` | xor eax, eax |
| `0x54368b2` | `c3` | ret  |
| `0x54368b3` | `b001` | mov al 1 |
| `0x54368b5` | `c3` | ret  |

## Why the SIMD comparison covers every byte

MOVDQU loads the heads. PCMPEQB produces an all-one byte for each matching head lane. Each MOVD loads the tail into the low lanes and zeroes the upper lanes of its XMM destination. The tail PCMPEQB therefore yields tail equality in the low lanes and all-one bytes in the upper lanes. PAND combines the head and tail equalities: low lanes require both their head byte and corresponding tail byte to agree; other lanes require their head byte to agree. PMOVMSKB yields mask `0xffff` exactly when every head and tail byte agrees. This is conjunction, so no difference can cancel another difference. `lane_mask()` models this lane equation independently of the scalar `sequence_equal()` specification.

For equal positive counts n, DEC sets RSI to n-1 before the loop. In iteration j, RSI before ADD is n-1-j. Adding the sign-extended immediate -1 raises unsigned carry exactly when that old value is nonzero. SETB saves carry into CL before the mask CMP overwrites flags. On a matching record, TEST CL / JNE loops iff another record remains; on the final record the old value is zero, the addition wraps to the maximum word, carry is clear and the function returns. This proves the loop bound for every representable valid slice length; large lengths are an algebraic claim under valid memory geometry, not huge allocated test fixtures. The instruction-derived vectors cover empty/unequal/equal lengths and a mismatch at every byte position of the first, middle and final record. Counter-boundary records separately cover unsigned extremes.

Preconditions: readable stable byte sequences for all reads actually reached, nonwrapping address geometry, a valid call/return stack, and the target ISA. Overlapping inputs are allowed because the body only reads them. A mismatching length or equal zero length does not require dereferenceable input pointers. Invalid pointers, data races and faults are outside the rule. The loop exits early; this is not a constant-time comparison claim.

## Caller census and first-party association

The producer scans every eligible byte position in the full `.text` range `[0x1419300, 0x63f0a00)` for E8/E9 plus signed rel32. All hits are preserved, including their raw bytes and containing FDE. No E9 hit or unexplained opcode hit names this entry. E8 sites `0x53791b1` and `0x53791d0` belong to `[0x5378220, 0x537aa59)` and agree with the explicitly decoded argument/call slice.

The first call loads RDI/RSI from R13-relative pointer/count slots and RDX/RCX from stack slots. Its zero AL branches to `0x5379d60`; nonzero reaches the second call with the next pointer/count pairs. The second call jumps to `0x5379d53`, whose TEST AL / JNE sends nonzero to `0x53786c0` and zero falls through toward `0x5379d60`. These are local consumer observations, not a recovered surrounding type or protocol decision. Complete caller behavior, entry reachability of these slices and all its other callees remain outside scope. Byte scanning over-approximates instruction starts in general; bounded slice decoding supports these particular hits. Indirect/data references, alternate entry points and missing-FDE callers are not a whole-program census.

Within that same caller FDE, LEA at `0x53788f2` addresses Location `0x64a7f08`. Its R_X86_64_RELATIVE relocation has addend `0x44e7fd`; the pointer-length bytes and line/column bind `l1/src/raw_signature_tracker.rs:231:9`. This is a first-party caller association. The leaf has no source string itself; a monomorphized dependency equality helper is possible. Original leaf ownership/name and whether the records represent addresses, signers or something else are unresolved.

## Novelty before selection

At the recorded base, before creating this packet, each command below produced empty stdout and exit status one:

```sh
rg -i '5436860' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '88303712' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The hexadecimal and decimal start were absent from every searched file. There are no callee behaviors to bind or additional callee starts to check. The new packet necessarily makes a later unfiltered search nonempty. PR lists are the supplied offline snapshots; newer upstream activity was not queried. The selected start is within the assigned band and outside the excluded sub-band and claimed-address list.

## Reproduce and verification scope

Run from the repository root with the authenticated artifact materialized. Python 3.10+ stdlib is sufficient; development used Python 3.13.5 on Linux x86-64. Existing `elf_index.py` and `fde_extents.py` supply ELF/unwind parsing and are manifest-bound. Native GNU objdump 2.44 was used only for exploratory inspection; no committed script or test invokes it. Neither captured executable was run. No network, installation, signing, chain state or live fixture was used.

```sh
python3 tools/node115_slice20_equal.py --out research/work-items/RE-001-node115-slice20-equal/
python3 -m unittest tests.test_node115_slice20_equal -v
python3 research/work-items/RE-001-node115-slice20-equal/verify.py
make verify
make catalogue-check
```

`--out` derives `records.json` and this README from the authenticated bytes, copies the packet verifier into a new output directory when needed, and writes the manifest. `verify.py` requires an exact manifest whitelist (including the producer, tests and parser dependencies), authenticates the target, and compares regenerated JSON and README bytes. Records contain semantic evidence, not local paths, native tool banners or run times. The wrong-digest and modified-input controls fail before output creation; lower-level controls also alter the actual body, FDE, relative call operand, source binding and padding. The manifest is an integrity check, not a signature or an independent proof.

Before this packet the selected address had no retained binding in the searched research or PR titles. After it, the complete leaf rule, loop bound, lane relation, extent, callee closure and direct-call sites are reproducible from the pinned target. This is static evidence and an independently authored Python model; no Rust implementation, Cargo graph, compiled-byte comparison, normalization mask or runtime differential result is claimed. Helper closure is empty for the leaf; caller/data/protocol closure and whole-ELF equivalence remain unmeasured. All component gates remain unchanged and false. Hosted CI and container execution are not claimed.

Next bounded question: identify the original types and construction of the caller's pointer/count pairs before assigning protocol meaning to the equal records.
