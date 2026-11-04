# RE-001: node #115 lexicographic and saturating threshold

- Component: RE-001 function map; candidate first-party context, not a subsystem claim.
- Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; source baseline `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No upstream source revision is asserted.
- Bounded question: what does the complete leaf at `0x55ff9e0` return from its input fields?
- Scope: one function, no execution of the captured executable; observation and arithmetic inference only. No progress gate requested.

**Answer.** Read 32-bit fields A at offsets `+0x60,+0x64,+0x68` and B at `+0x4294,+0x4298,+0x429c`. Compare their triples lexicographically, treating the first field as signed and the other two as unsigned. Let T, X and C be unsigned 64-bit fields at `+0x28`, `+0x10` and `+0x4228`. If A is greater than or equal to B and T >= C, AL is 2. Otherwise AL is 1 if T >= min(X + 5000, 2^64 - 1), and 0 otherwise. This is conditional on valid readable input memory. Only AL is claimed; upper return-register bits are not uniformly defined.

## Evidence and interpretation

All addresses are original ELF virtual addresses, half-open. The window `0x55ff9e0..0x55ffa44` is 100 bytes, file offset `0x55fe9e0`, SHA-256 `c7eae84020e629ae599eb400ad0d31b78d3a037651d47d2cdc3ce4a83995acf0`. Its FDE at VA/file offset `0xf86fb8` references CIE `0xca6ed8` (`zR`, no LSDA). FDE and CIE bytes are in records.json. The following 12 bytes are INT3 padding; this and the terminating return support the FDE extent, but unwind information alone is not a proof of universal function boundaries.

The 28 instructions below cover every body byte. SETL uses signed flags from the first comparison; SETB and JAE use unsigned flags for the remaining fields. The first two JNEs consume the flags of CMP because SETcc does not modify flags. For X below `2^64-5000`, subtracting sign-extended -5000 wraps to X+5000 and sets borrow; at or above that boundary, the ADD/CMOVAE pair selects the sum if no carry, otherwise `UINT64_MAX`. The final unsigned comparison includes equality. No call or indirect transfer occurs inside the body: callee count 0.

| VA | Bytes | Strict decoded instruction |
| --- | --- | --- |
| `0x55ff9e0` | `8b4760` | mov eax, dword [rdi+0x60] |
| `0x55ff9e3` | `488b4f28` | mov rcx, qword [rdi+0x28] |
| `0x55ff9e7` | `3b8794420000` | cmp eax, dword [rdi+0x4294] |
| `0x55ff9ed` | `0f9cc0` | setl al (signed less) |
| `0x55ff9f0` | `751b` | jne 0x55ffa0d |
| `0x55ff9f2` | `8b4764` | mov eax, dword [rdi+0x64] |
| `0x55ff9f5` | `3b8798420000` | cmp eax, dword [rdi+0x4298] |
| `0x55ff9fb` | `0f92c0` | setb al (unsigned less) |
| `0x55ff9fe` | `750d` | jne 0x55ffa0d |
| `0x55ffa00` | `8b4768` | mov eax, dword [rdi+0x68] |
| `0x55ffa03` | `3b879c420000` | cmp eax, dword [rdi+0x429c] |
| `0x55ffa09` | `7306` | jae 0x55ffa11 |
| `0x55ffa0b` | `eb0f` | jmp 0x55ffa1c |
| `0x55ffa0d` | `84c0` | test al, al |
| `0x55ffa0f` | `750b` | jne 0x55ffa1c |
| `0x55ffa11` | `b002` | mov al, 2 |
| `0x55ffa13` | `483b8f28420000` | cmp rcx, qword [rdi+0x4228] |
| `0x55ffa1a` | `7327` | jae 0x55ffa43 |
| `0x55ffa1c` | `488b4710` | mov rax, qword [rdi+0x10] |
| `0x55ffa20` | `4889c2` | mov rdx, rax |
| `0x55ffa23` | `4881ea78ecffff` | sub rdx, sign-extended -5000 |
| `0x55ffa2a` | `7211` | jb 0x55ffa3d |
| `0x55ffa2c` | `480588130000` | add rax, 5000 |
| `0x55ffa32` | `48c7c2ffffffff` | mov rdx, -1 |
| `0x55ffa39` | `480f43d0` | cmovae rdx, rax |
| `0x55ffa3d` | `4839d1` | cmp rcx, rdx |
| `0x55ffa40` | `0f93c0` | setae al (unsigned greater or equal) |
| `0x55ffa43` | `c3` | ret |

The complete `.text` byte-offset scan for `e8`/`e9` followed by signed rel32 finds 4 candidate sites: `0x517adc5`, `0x517b61d`, `0x57ca47b`, `0x57ca990`; all 4 have opcode `e8`. Strictly decoded adjacent instructions support instruction boundaries, but the scan can include incidental byte patterns and cannot find indirect calls, alternate encodings, or prove reachability. The site `0x517adc5` lies in the FDE beginning `0x517a670`, whose LEA at `0x517ac9f` references Location `0x64768a8`; its relative relocation points to `l1/src/perp_meta.rs`, line 163, column 38. The LEA, metadata and relocation bytes are validated and recorded in JSON. This caller association does not name this leaf or prove ownership. The remaining sites' context is not semantically closed. No call-target normalization was applied.

## Reproduce and controls

From the repository root, Python 3.10+ stdlib and the authenticated artifact are required. This run used Python 3.13.5 on Linux x86-64; GNU objdump 2.44 was used only for exploratory cross-checking. REA was unavailable because the pinned local package was absent; no installation was attempted. Generation is deterministic, static, and validates the full artifact digest before analysis or writing. `records.json` stores semantic instruction and caller records. `verify.py` checks an exact packet-file whitelist and SHA-256 manifest. The model is independently authored from this walk, not recovered source.

```sh
python3 tools/node115_saturating_threshold.py --out research/work-items/RE-001-node115-saturating-threshold/
python3 -m unittest tests.test_node115_saturating_threshold -v
python3 research/work-items/RE-001-node115-saturating-threshold/verify.py
make verify
make catalogue-check
```

Novelty check before development: the combined hexadecimal and decimal search returned no matches (ripgrep exit 1):

```sh
rg -i '55ff9e0|90175968' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

Negative controls reject a wrong digest, altered instruction, changed branch, shifted FDE and changed direct-call target. Boundary vectors check signed versus unsigned ordering, equality, and saturation. These tests establish the local rule against decoded bytes, not a native execution comparison.

## Limitations and next step

No original Rust type, field name, units, protocol meaning, caller argument provenance, full caller behavior, relocation/data closure, ABI beyond the observed input register and AL, native behavior under invalid pointers, compiler provenance, independently built Rust or whole-node equivalence is claimed. There is no before/after binary comparison or normalization mask. The first-party path is a caller-context lead only. Next, trace the four callers' input construction to establish field meaning and whether the return values have a common protocol interpretation.
