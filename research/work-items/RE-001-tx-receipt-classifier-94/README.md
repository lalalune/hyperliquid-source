# RE-001: node #94 tx / receipt classifier

Task RE-001, component: serialization / function map. **Question:** what does the
function at `0x1e72770` compute from a byte slice? **Answer:** for a readable
slice `(rsi, rdx)`, it writes two bytes to `rdi`: marker 9 followed by tag 0
for exactly `tx`, tag 1 for exactly `receipt`, and tag 2 for all other byte
strings. It returns the output pointer in `rax`. This is a byte-level rule;
no source type or enclosing protocol is assumed.

## Target and boundaries

Node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; source baseline commit
`e5c9b6436876b2a4a39daef813171f9879317699`, reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23` (reference not consulted for the
rule). ELF virtual-address window `0x1e72770..0x1e727b4` is 68
bytes, file offset `0x1e71770`, body SHA-256 `213c01340f32ae87e79642007c421dbc12076300d668be28d065bf5bafd6b937`.
The `.eh_frame` FDE at section offset `0x3d07c` has
length 16 and CIE offset `0x0`. The
next FDE starts at `0x1e727c0`; the intervening
12 bytes are `cc` padding. The full `.eh_frame_hdr` search table confirms those adjacent starts. The FDE
and complete control flow support this extent; it is not inferred merely from a seed.

## Instruction walk

All bytes and instructions below are decoded by the strict Python decoder; no
external disassembler is used to generate or check the packet. Branches land on
instruction boundaries within the window. The 2 overlapping dword reads on
the 7-byte path compare bytes 0..3 and 3..6, so the whole string must match.

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x1e72770` | `48 89 f8` | `mov rax, rdi` |
| `0x1e72773` | `48 83 fa 07` | `cmp rdx, 7` |
| `0x1e72777` | `74 16` | `je 0x1e7278f` |
| `0x1e72779` | `48 83 fa 02` | `cmp rdx, 2` |
| `0x1e7277d` | `75 23` | `jne 0x1e727a2` |
| `0x1e7277f` | `66 81 3e 74 78` | `cmp word [rsi], 0x7874` |
| `0x1e72784` | `75 1c` | `jne 0x1e727a2` |
| `0x1e72786` | `31 c9` | `xor ecx, ecx` |
| `0x1e72788` | `88 48 01` | `mov [rax+1], cl` |
| `0x1e7278b` | `c6 00 09` | `mov byte [rax], 9` |
| `0x1e7278e` | `c3` | `ret` |
| `0x1e7278f` | `b9 72 65 63 65` | `mov ecx, 0x65636572` |
| `0x1e72794` | `33 0e` | `xor ecx, dword [rsi]` |
| `0x1e72796` | `ba 65 69 70 74` | `mov edx, 0x74706965` |
| `0x1e7279b` | `33 56 03` | `xor edx, dword [rsi+3]` |
| `0x1e7279e` | `09 ca` | `or edx, ecx` |
| `0x1e727a0` | `74 09` | `je 0x1e727ab` |
| `0x1e727a2` | `b1 02` | `mov cl, 2` |
| `0x1e727a4` | `88 48 01` | `mov [rax+1], cl` |
| `0x1e727a7` | `c6 00 09` | `mov byte [rax], 9` |
| `0x1e727aa` | `c3` | `ret` |
| `0x1e727ab` | `b1 01` | `mov cl, 1` |
| `0x1e727ad` | `88 48 01` | `mov [rax+1], cl` |
| `0x1e727b0` | `c6 00 09` | `mov byte [rax], 9` |
| `0x1e727b3` | `c3` | `ret` |

## Calls, inference, and limits

The body has 0 callees and no indirect transfer. A full `.text`
byte scan for `e8` and `e9` rel32 encodings produces 1 call
candidate(s) (`0x1a66898`) and
0 jump candidate(s). The call encoding at that site resolves
to this entry. A byte-pattern census can include opcode-like bytes inside other
instructions; it does not cover indirect calls, pointers, other sections, or
prefixed encodings. Input and output must be valid for the actual reads/writes;
behavior for invalid pointers is outside the rule. No Rust type, source owner,
message schema, protocol semantics, compilation equivalence, or execution result
is claimed. `records.json` includes 10 static model vectors;
they are derived from the instructions, not target executions. No full-scope
gate is advanced. Next, trace the caller's enclosing decode path and identify
what consumes the resulting tag using separate evidence.

## Novelty

Before creating this packet, the following command returned no matches (exit 1):

```sh
rg -i '1e72770|31926128' research/ ../../hl-re1-base/open_prs.txt ../../hl-re1-base/merged_prs.txt ../../hl-re1-base/closed_unmerged_prs.txt
```

There are no behavior-bound callees to check. The PR lists are external static
snapshots; the result does not assert that later work has not claimed the address.

## Reproduction

From the repository root, with Python 3.10+ standard library and the authenticated
artifact (static reads only):

```sh
python3 tools/node94_tx_receipt.py --out research/work-items/RE-001-tx-receipt-classifier-94/
python3 -m unittest tests.test_node94_tx_receipt -v
python3 research/work-items/RE-001-tx-receipt-classifier-94/verify.py
```

The collector checks the full target digest, ELF section coordinates, both FDE
associations, body hash, every instruction, padding, and full-section incoming
scan. `verify.py` enforces the packet file whitelist and manifest and regenerates
all generated files for byte comparison. No target binary is executed. Compiler,
linker, helper/data/relocation closure and whole-ELF reconstruction remain open.
