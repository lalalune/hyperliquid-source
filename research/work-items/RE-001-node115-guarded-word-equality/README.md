# RE-001: guarded word equality in node #115

- Component: `l1-shared`; function-map work associated with the raw-signature tracker.
- Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No external inferred source was copied.
- Bounded question: exactly which raw words determine AL at `0x542f290`, including mixed-width tag tests?
- Status: complete local instruction relation observed; source/type names remain inferred.
- Intended new files: this packet, `tools/node115_guarded_word_equality.py`, and `tests/test_node115_guarded_word_equality.py`.

For readable, stable records with raw words A and B, AL is false if exactly one
full-width tag equals the sentinel. Otherwise AL is true immediately if either
low-width tag equals the sentinel. On the remaining path, words at the required
payload offsets must match. If A's low tag equals the payload tag,
B's low tag bit must be set and the conditional payload word must also match;
otherwise B's low tag bit must be clear. The constants and offsets are extracted
below. The leaf reads memory and returns AL; it has no writes or opaque helper
effects. It does not promise a canonical boolean in the whole RAX register.

## Measured extent and counts

Original ELF VA window: `0x542f290..0x542f31b`;
file offset `0x542e290`; body SHA-256 `03cdac3c0ab0bf56c2619e06eefd37b6696bbc508c948b14d06b459d073bc39e`.
Actual FDE at `0xf7d758` (file offset `0xf7d758`),
CIE at `0xca6ed8` (file offset `0xca6ed8`),
augmentation `zR`, no LSDA.
The neighboring gaps are all INT3. Padding is excluded from the body hash.
The FDE, complete instruction walk, internal branch destinations, entry-reachable
CFG and terminal RETs agree on the bounded extent. This is not a whole-node
function denominator. Callee identities/extents are the empty set: every
transfer in this leaf is an internal conditional/unconditional branch or RET.

All measured counts in this README come from `records.json`:

| Metric | Count |
| --- | ---: |
| bound_functions | 1 |
| body_bytes | 139 |
| instructions | 49 |
| callee_count | 0 |
| indirect_transfer_count | 0 |
| caller_sites | 1 |
| caller_fdes | 1 |
| tail_call_sites | 0 |
| text_bytes_scanned | 83719936 |
| padding_before | 13 |
| padding_after | 5 |
| return_sites | 2 |
| vectors | 23 |

## Rule and byte proof

Let `A[i]` and `B[i]` be unsigned 64-bit words and
`a = A[0] & 0xffffffff`, `b = B[0] & 0xffffffff`.
The sentinel is 2; the payload tag and right-tag
mask are 1 and 1.
The required equal payload offsets after the low-tag gate are
`[16, 24, 32]`;
the conditional payload offset is `8`.

```
if (A[0] == 2) != (B[0] == 2): return AL=0
if a == 2 or b == 2: return AL=1
if A[2] != B[2]: return AL=0
if a == 1:
    if (b & 1) == 0 or A[1] != B[1]: return AL=0
else:
    if (b & 1) != 0: return AL=0
return AL = (A[3] == B[3] and A[4] == B[4])
```

The initial RDX/RCX comparisons and SETNE/XOR detect whether exactly one raw
tag is the sentinel. Later EDX/ECX comparisons truncate the tags before
SETNE/TEST. MOV AL does not change flags. At each payload word with an explicit
zero branch, the zero and nonzero routes together implement full-width equality.
The last CMP/SETE supplies AL on the surviving path. Loads of later words are
skipped on earlier failures; there is no assumption that ignored payload is
initialized or dereferenced. A valid stack for RET and memory for each actual
load, with no concurrent mutation, are preconditions. Aliasing of the records
does not add a write hazard.

On conventional tag values `0`, `1`, `2`, this is equality with an ignored
payload for tag `2`, an ignored conditional word for tag `0`, and a compared
conditional word for tag `1`. Those are a useful restricted-domain interpretation,
not recovered enum names. For arbitrary raw tags the relation can be asymmetric:
the recorded asymmetric-forward/reverse witnesses demonstrate this. High tag
bits also distinguish the full sentinel gate from the low-tag shortcut. The
independent Python model preserves these details; the retained vectors are
manually derived from these branches, not observations of target execution.

## Complete instruction walk

The strict Python decoder consumes all body bytes. It resolves signed relative
branches, decodes immediate widths and memory displacements, and rejects unknown
opcode/register forms. The body digest and frame bytes additionally pin the
accepted operands. No normalization masks are applied.

| ELF VA | Raw bytes | Decoded instruction |
| --- | --- | --- |
| 0x542f290 | `488b17` | `mov rdx, qword [rdi]` |
| 0x542f293 | `4883fa02` | `cmp rdx, 2` |
| 0x542f297 | `0f95c0` | `setne al` |
| 0x542f29a | `488b0e` | `mov rcx, qword [rsi]` |
| 0x542f29d | `4883f902` | `cmp rcx, 2` |
| 0x542f2a1 | `410f95c0` | `setne r8b` |
| 0x542f2a5 | `4130c0` | `xor r8b, al` |
| 0x542f2a8 | `7403` | `je 0x542f2ad` |
| 0x542f2aa | `31c0` | `xor eax, eax` |
| 0x542f2ac | `c3` | `ret ` |
| 0x542f2ad | `83f902` | `cmp ecx, 2` |
| 0x542f2b0 | `410f95c0` | `setne r8b` |
| 0x542f2b4 | `83fa02` | `cmp edx, 2` |
| 0x542f2b7 | `410f95c1` | `setne r9b` |
| 0x542f2bb | `b001` | `mov al, 1` |
| 0x542f2bd | `4584c1` | `test r9b, r8b` |
| 0x542f2c0 | `7458` | `je 0x542f31a` |
| 0x542f2c2 | `488b4710` | `mov rax, [rdi+0x10]` |
| 0x542f2c6 | `4c8b4610` | `mov r8, [rsi+0x10]` |
| 0x542f2ca | `4885c0` | `test rax, rax` |
| 0x542f2cd | `7407` | `je 0x542f2d6` |
| 0x542f2cf | `4c39c0` | `cmp rax, r8` |
| 0x542f2d2 | `7407` | `je 0x542f2db` |
| 0x542f2d4 | `ebd4` | `jmp 0x542f2aa` |
| 0x542f2d6 | `4d85c0` | `test r8, r8` |
| 0x542f2d9 | `75cf` | `jne 0x542f2aa` |
| 0x542f2db | `83fa01` | `cmp edx, 1` |
| 0x542f2de | `7511` | `jne 0x542f2f1` |
| 0x542f2e0 | `f6c101` | `test cl, 1` |
| 0x542f2e3 | `74c5` | `je 0x542f2aa` |
| 0x542f2e5 | `488b4708` | `mov rax, [rdi+0x8]` |
| 0x542f2e9 | `483b4608` | `cmp rax, [rsi+0x8]` |
| 0x542f2ed | `75bb` | `jne 0x542f2aa` |
| 0x542f2ef | `eb05` | `jmp 0x542f2f6` |
| 0x542f2f1 | `f6c101` | `test cl, 1` |
| 0x542f2f4 | `75b4` | `jne 0x542f2aa` |
| 0x542f2f6 | `488b4718` | `mov rax, [rdi+0x18]` |
| 0x542f2fa | `488b4e18` | `mov rcx, [rsi+0x18]` |
| 0x542f2fe | `4885c0` | `test rax, rax` |
| 0x542f301 | `7407` | `je 0x542f30a` |
| 0x542f303 | `4839c8` | `cmp rax, rcx` |
| 0x542f306 | `75a2` | `jne 0x542f2aa` |
| 0x542f308 | `eb05` | `jmp 0x542f30f` |
| 0x542f30a | `4885c9` | `test rcx, rcx` |
| 0x542f30d | `759b` | `jne 0x542f2aa` |
| 0x542f30f | `488b4720` | `mov rax, [rdi+0x20]` |
| 0x542f313 | `483b4620` | `cmp rax, [rsi+0x20]` |
| 0x542f317 | `0f94c0` | `sete al` |
| 0x542f31a | `c3` | `ret ` |

## Caller census and source association

The producer scans every byte position that can hold a complete E8 or E9 rel32
in `.text` (`0x1419300..0x63f0a00`). It retains every hit in JSON,
including its raw bytes, then separately decodes the matching caller excerpt.
CALL at `0x53794cc` belongs to FDE `0x5378220..0x537aa59`.
The excerpt sets RDI to `r13+0x8` and RSI to `rsp+0x10` before the call, after
a separate outer byte comparison. The subsequent jump preserves the returned
AL. The complete caller's behavior and stack/type construction are not bound.
Raw scanning is an exhaustive direct-encoding census, not a proof about indirect
calls, pointers, alternate entrypoints, or a whole-section instruction decode.
The original focused GNU disassembly agreed with this local CALL boundary;
regeneration relies only on Python and the pinned excerpt bytes.

Within that same caller FDE, RIP-relative LEA at `0x53788f2` references
Location `0x64a7f08`. Its actual R_X86_64_RELATIVE relocation resolves
the on-disk null pointer to path bytes at `0x44e7fd`. The location reads
`l1/src/raw_signature_tracker.rs:231:9`. The retained path is relative in the ELF.
This associates the caller with first-party code. It does not prove the leaf's
original source name, enum type, or first-party authorship; compiler-generated
equality remains a plausible inference. No behavior of the caller's other
callees is bound or included in the leaf's empty callee set.

## Novelty, provenance and reproduction

Before packet creation, these exact searches returned empty stdout, empty
stderr and exit status `1` for each command:

```sh
rg -i '542f290' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '88273552' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'guarded-word-equality|guarded_word_equality' research/work-items tools tests ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no bound callees requiring additional address novelty searches.
These are historical pre-addition checks at the recorded base revision; running
them after adding this packet will find this packet. The selected start is in
the assigned band and outside the excluded band and claimed-address list.
Existing merged tagged-count, u8-rejection, numeric-selector and
weighted-comparison packets were reviewed; no existing packet/tool/test is edited.

From repository root, with the authenticated artifact present:

```sh
python3 tools/node115_guarded_word_equality.py --out research/work-items/RE-001-node115-guarded-word-equality/
python3 -m unittest tests.test_node115_guarded_word_equality -v
python3 research/work-items/RE-001-node115-guarded-word-equality/verify.py
make verify
make catalogue-check
```

The generator authenticates the complete input before parsing or output creation
and uses a read-only mapping rather than copying the full binary. The semantic
JSON and this README regenerate deterministically; authored verifier/code/tests
are covered by the exact manifest whitelist, including the shared ELF/FDE readers.
The generator requires Python 3.10+ stdlib only. Discovery used Linux x86-64,
Python 3.13.5 and GNU binutils 2.44. No connected REA tools were exposed;
doctor reported Ghidra and Java unavailable. Native
tools were used only for discovery and a cross-check, not by generator, verifier
or tests. The focused discovery command was:

```sh
objdump -d -M intel --start-address=0x542f290 --stop-address=0x542f31b artifacts/node/115/hl-node
```

The retained raw instruction/frame/relocation bytes preserve the evidence
without depending on native text rendering. Wrong digest, modified leaf bytes,
branch/displacement changes, shifted FDE, changed caller target, malformed
decoder inputs and manifest/record corruption are negative controls. Tests
also require README metrics to equal JSON and exact regeneration of the README.
The leaf has no callee target to mutate; the actual incoming CALL target is
corrupted instead. No captured node/visor, emulator, network or install is used.

## Results, non-claims and next step

Before: this address had no retained bind in the checked research and PR lists.
After: the complete local read/branch/AL relation and a caller association are
reproducible from the pinned target. This is a static function bind with a small
independent Python value model. It is not a recovered Rust implementation,
source-build comparison, target execution, full caller bind, or original ABI/type
recovery. No compiler/linker equivalence, Cargo graph, whole-ELF/data/vtable
closure, signature-validation policy or protocol behavior is claimed. Runtime
faults from unreadable memory, stack faults, asynchronous mutation and alternate
entry into the body are outside the normal-return theorem. No progress gate is
requested; all full-scope gates remain unchanged.

Next: establish how the caller constructs the compared records and constrains
their tags before assigning source-level type or signature-tracking meaning.
