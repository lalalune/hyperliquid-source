# RE-001: bind node #94 field-name dispatch at 0x42c5340

Task/component: RE-001 function map, serialization-related field-name dispatch;
component ownership is unproven. Bounded question: given an output pointer in
`rdi`, byte pointer in `rsi` and length in `rdx`, what does this leaf write and
return? On valid readable input, it returns the output pointer in `rax`, writes
`09 00` for exactly `order_sz`, `09 01` for exactly `points`, and `09 02`
for every other length or byte string. The length gates all reads: length 8
reads eight bytes, length 6 reads six bytes, and other lengths read no input.
The two output stores happen in the order `[out+1]`, then `[out]`. These are
raw tags; their source-level enum or protocol meaning is not established.

## Identity and scope

Node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
from `provenance/artifacts.json`. Repository starting commit
`e5c9b6436876b2a4a39daef813171f9879317699`; reference submodule pinned at
`999556f6e0a474b8312db96ec3149e1c44e97c23` was not used to infer semantics.
ELF VA window `0x42c5340..0x42c538e` (exclusive), file offset `0x42c4340`;
body SHA-256 `de7739862640e67242ed231fb437a48881b3f0fea327a69059735275ea78b7a8`.
The `.eh_frame` FDE at section offset `0x1de34c` references the CIE at offset
`0x0`, gives that start and extent, and is followed by the FDE starting at
`0x42c5390`. The gap is `cc cc`. The decoded control flow has only internal
conditional branches and returns, with no direct or indirect callee. This
supports the selected extent but unwind ranges alone are not a complete function
map. No bytes are masked or normalized.

| Metric | Count |
| --- | ---: |
| window_bytes | 78 |
| padding_bytes | 2 |
| branches | 4 |
| direct_callees | 0 |
| indirect_callees | 0 |
| direct_call_candidates | 1 |
| direct_jump_candidates | 0 |
| vectors | 7 |

## Byte-decoded instruction walk

The tool decodes the complete FDE window with an exact opcode/operand whitelist
and checks every relative branch destination. Constants are little-endian. The
`xor`/`or` chain tests equality of all six bytes of `points`; it is not a
case-insensitive or prefix comparison.

| ELF VA | Bytes | Instruction |
| --- | --- | --- |
| `0x42c5340` | `4889f8` | `mov rax, rdi` |
| `0x42c5343` | `4883fa06` | `cmp rdx, 6` |
| `0x42c5347` | `741e` | `je 0x42c5367` |
| `0x42c5349` | `4883fa08` | `cmp rdx, 8` |
| `0x42c534d` | `752d` | `jne 0x42c537c` |
| `0x42c534f` | `48b96f726465725f737a` | `mov rcx, 0x7a735f726564726f` |
| `0x42c5359` | `48390e` | `cmp qword [rsi], rcx` |
| `0x42c535c` | `751e` | `jne 0x42c537c` |
| `0x42c535e` | `31c9` | `xor ecx, ecx` |
| `0x42c5360` | `884801` | `mov byte [rax+1], cl` |
| `0x42c5363` | `c60009` | `mov byte [rax], 9` |
| `0x42c5366` | `c3` | `ret` |
| `0x42c5367` | `b9706f696e` | `mov ecx, 0x6e696f70` |
| `0x42c536c` | `330e` | `xor ecx, dword [rsi]` |
| `0x42c536e` | `0fb75604` | `movzx edx, word [rsi+4]` |
| `0x42c5372` | `81f274730000` | `xor edx, 0x7374` |
| `0x42c5378` | `09ca` | `or edx, ecx` |
| `0x42c537a` | `7409` | `je 0x42c5385` |
| `0x42c537c` | `b102` | `mov cl, 2` |
| `0x42c537e` | `884801` | `mov byte [rax+1], cl` |
| `0x42c5381` | `c60009` | `mov byte [rax], 9` |
| `0x42c5384` | `c3` | `ret` |
| `0x42c5385` | `b101` | `mov cl, 1` |
| `0x42c5387` | `884801` | `mov byte [rax+1], cl` |
| `0x42c538a` | `c60009` | `mov byte [rax], 9` |
| `0x42c538d` | `c3` | `ret` |

## Callers and interpretation

A full `.text` scan of every byte position for `e8` and `e9` with rel32
resolved to the entry reports the call candidate `0x40e8ef8` and no jump
candidates. At that site, bytes `e8 43 c4 1d 00` decode as a direct call to
this entry. The containing unwind range is `0x40e7d50..0x40e9421`; this is
context, not a complete reconstruction of that caller. A byte-pattern census
may include opcode-like bytes within other instructions or data; the confirmed
site was checked in its local instruction context. It does not include indirect
calls, data pointers, other executable sections, or every way to reach the
entry. No first-party source attribution is claimed from proximity alone.

The independent Python model checks the byte-string rule and the JSON vectors
against target-decoded constants. These are static model vectors, not target
executions. Reads require their indicated memory to be valid and the output
requires writable memory. Invalid pointers, fault behavior, concurrency,
caller's larger state, input provenance, and actual wire format remain outside
this packet. Return and output claims assume ordinary execution and no fault.
There is no Rust implementation, compiled-source comparison, function coverage
or component gate claim. A useful next question is how the containing caller
uses the tag and whether its surrounding field schema is first-party.

## Novelty check

Before selection, both commands returned no matches (exit status 1):

```
rg -i '42c5340|70013760' research/
rg -i '42c5340|70013760' ../../hl-re1-base/{open_prs,merged_prs,closed_unmerged_prs}.txt
```

There are no callee behavior bindings to check. The externally supplied PR title
lists are a snapshot, so this check cannot rule out later work.

## Reproduce and validate

Run from the repository root using Python 3.10+ stdlib; the recorded run used
Python 3.13.5. The binary is read statically and never executed. `records.json`
contains semantic records; no disassembler output or external Python package is
required. The generator authenticates the entire target, checks exact section,
FDE/CIE, body, branches, padding, and caller bytes, then scans `.text`. The
packet verifier enforces its file whitelist, manifest, records, instruction walk
and count consistency. No Ghidra analysis or runtime trace is claimed.

```
python3 tools/field_name_dispatch_94.py --out research/work-items/RE-001-field-name-dispatch-94/
python3 -m unittest tests.test_field_name_dispatch_94 -v
python3 research/work-items/RE-001-field-name-dispatch-94/verify.py
make verify
make catalogue-check
```

The checker uses strict, task-specific decoding and rejects modified inputs;
tests include digest, body byte, FDE offset and rel32 target corruption controls.
Full-ELF equivalence, helper/data/relocation closure and source build provenance
remain unmeasured. No target or visor execution, networking, or secrets are used.
