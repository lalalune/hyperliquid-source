# RE-001: node #115 stable record insertion

- Component: foundation, with a direct caller associated with clearinghouse source Locations.
- Target: node #115 Linux x86-64, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New code and prose are independently authored under the repository MIT license; no inferred source was copied.
- Claim status: observed instructions and an inferred record-level algorithm, proved below. Original function/type names are unresolved.
- Scope: the complete leaf and its local array effect; caller/source association only. No progress or catalogue gate requested.

## Question and answer

What does `0x26cf370` do to its array, and what is the entry-index guard?

It processes contiguous **40-byte records**, comparing the first **8-byte word as unsigned**. RDI is the base, RSI is the record count n, and RDX is the first index k. The entry traps with UD2 exactly when `((k - 1) mod 2^64) >= n`; passing is equivalent to `1 <= k <= n`. For each index from k to n excluded, the function saves that record and shifts preceding records with strictly larger keys right, then inserts the saved record. Equal keys never cross, so this is stable insertion. A sorted prefix `[0,k)` yields a sorted whole array; k=1 supplies that precondition for every admissible nonempty array. k=n returns without touching the array. An unsorted longer prefix is not repaired in general.

## Evidence geometry and measured counts

All addresses are original ELF virtual addresses, with no rebase or operand normalization. The file offset differs from VA and is recorded explicitly. The extent uses the actual FDE, complete decode, closed local branches, RET/UD2 terminals and adjacent padding, rather than a next-start estimate.

| Measurement | Value |
| --- | --- |
| Leaf half-open window | `0x26cf370..0x26cf42f` |
| Leaf file offset | `0x26ce370` |
| Complete leaf bytes | 191 |
| Decoded leaf instructions, including in-body NOPs | 47 |
| FDE VA / file offset | `0xd43644` / `0xd43644` |
| CIE VA / file offset | `0xca6ed8` / `0xca6ed8` |
| INT3 bytes before / after, outside the body | 5 / 1 |
| Direct callees / indirect transfers | 0 / 0 |
| Direct call sites / owning FDEs / tail-jump sites | 1 / 1 / 0 |
| Caller instructions decoded for boundary validation | 839 |
| First-party Location bindings in that caller | 2 |
| Instruction-grounded vectors / trap vectors | 14 / 5 |

Body SHA-256: `ea15bcdcf54fee271b20f8bfb7246bed1d6ea8c1c651c18b8ac70a7ee48081df`. Raw body, FDE/CIE bytes and properties, padding, typed decoded operands, source relocations, caller scan hits and vectors are in `records.json`. The leaf CIE has no LSDA/personality; no exception handler or helper implementation is needed to establish its local normal path. The padding is excluded from the body digest.

## Instruction walk and proof

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x26cf370` | `488d42ff` | `lea rax, [rdx-1]` |
| `0x26cf374` | `4839f0` | `cmp rax, rsi` |
| `0x26cf377` | `0f83b0000000` | `jae 0x26cf42d` |
| `0x26cf37d` | `4839f2` | `cmp rdx, rsi` |
| `0x26cf380` | `7501` | `jne 0x26cf383` |
| `0x26cf382` | `c3` | `ret` |
| `0x26cf383` | `488d04b6` | `lea rax, [rsi+rsi*4]` |
| `0x26cf387` | `488d04c7` | `lea rax, [rdi+rax*8]` |
| `0x26cf38b` | `48c1e203` | `shl rdx, 3` |
| `0x26cf38f` | `488d0c92` | `lea rcx, [rdx+rdx*4]` |
| `0x26cf393` | `488d140f` | `lea rdx, [rdi+rcx*1]` |
| `0x26cf397` | `eb2e` | `jmp 0x26cf3c7` |
| `0x26cf399` | `0f1f8000000000` | `nop` |
| `0x26cf3a0` | `4989f8` | `mov r8, rdi` |
| `0x26cf3a3` | `498930` | `mov [r8], rsi` |
| `0x26cf3a6` | `0f284424d8` | `movaps xmm0, [rsp-40]` |
| `0x26cf3ab` | `0f284c24e8` | `movaps xmm1, [rsp-24]` |
| `0x26cf3b0` | `410f114008` | `movups [r8+8], xmm0` |
| `0x26cf3b5` | `410f114818` | `movups [r8+24], xmm1` |
| `0x26cf3ba` | `4883c228` | `add rdx, 40` |
| `0x26cf3be` | `4883c128` | `add rcx, 40` |
| `0x26cf3c2` | `4839c2` | `cmp rdx, rax` |
| `0x26cf3c5` | `74bb` | `je 0x26cf382` |
| `0x26cf3c7` | `488b32` | `mov rsi, [rdx]` |
| `0x26cf3ca` | `483b72d8` | `cmp rsi, [rdx-40]` |
| `0x26cf3ce` | `73ea` | `jae 0x26cf3ba` |
| `0x26cf3d0` | `0f104208` | `movups xmm0, [rdx+8]` |
| `0x26cf3d4` | `0f104a18` | `movups xmm1, [rdx+24]` |
| `0x26cf3d8` | `0f294c24e8` | `movaps [rsp-24], xmm1` |
| `0x26cf3dd` | `0f294424d8` | `movaps [rsp-40], xmm0` |
| `0x26cf3e2` | `4989c9` | `mov r9, rcx` |
| `0x26cf3e5` | `66662e0f1f840000000000` | `nop` |
| `0x26cf3f0` | `4e8b440ff8` | `mov r8, [rdi+r9*1-8]` |
| `0x26cf3f5` | `4e89440f20` | `mov [rdi+r9*1+32], r8` |
| `0x26cf3fa` | `420f10440fd8` | `movups xmm0, [rdi+r9*1-40]` |
| `0x26cf400` | `420f104c0fe8` | `movups xmm1, [rdi+r9*1-24]` |
| `0x26cf406` | `420f114c0f10` | `movups [rdi+r9*1+16], xmm1` |
| `0x26cf40c` | `420f11040f` | `movups [rdi+r9*1], xmm0` |
| `0x26cf411` | `4983f928` | `cmp r9, 40` |
| `0x26cf415` | `7489` | `je 0x26cf3a0` |
| `0x26cf417` | `4d8d41d8` | `lea r8, [r9-40]` |
| `0x26cf41b` | `4a3b740fb0` | `cmp rsi, [rdi+r9*1-80]` |
| `0x26cf420` | `4d89c1` | `mov r9, r8` |
| `0x26cf423` | `72cb` | `jb 0x26cf3f0` |
| `0x26cf425` | `4901f8` | `add r8, rdi` |
| `0x26cf428` | `e976ffffff` | `jmp 0x26cf3a3` |
| `0x26cf42d` | `0f0b` | `ud2` |

The entry LEA forms k-1 with machine-word wrap. CMP/JAE sends an out-of-range value to the final UD2; CMP/JNE then returns immediately for k=n. Otherwise the LEAs and shift establish RAX=base+n*stride, RDX=base+k*stride and RCX=k*stride. Address multiplication must be representable under the memory preconditions below.

At `0x26cf3c7`, RSI holds the current key. CMP/JAE skips moving a record when its unsigned key is at least its predecessor's key, including equality. Otherwise MOVUPS saves its payload in XMM registers and MOVAPS spills it to the red zone. R9 tracks the hole offset. The backward loop copies the complete preceding record into the hole: its final word is loaded before the vector stores, and the vector loads preserve the remaining bytes before overwrite. These moves cover the entire record with no missing payload bytes.

The R9 comparison stops at the beginning; otherwise the CMP/JB at `0x26cf41b`/`0x26cf423` continues only while the saved key is unsigned-less than the earlier key. The common insertion block writes the saved key and payload to the hole. RDX and RCX advance by the decoded stride and the end-pointer test closes the outer loop. The hole moves strictly toward the beginning and the outer index strictly toward n, proving termination for valid finite arrays. If the prefix was sorted, each insertion extends that sorted prefix; strict comparisons preserve the original order of equal keys. The `unprocessed-prefix` vector prevents claiming that an arbitrary prefix is sorted automatically.

The output contract is the array mutation. No Rust return type is assigned. Incidentally, the raw RAX return is k-1 on the k=n shortcut and the end pointer after a nonempty insertion pass. No globals, constant tables, calls, tail transfers or indirect dispatch participate in this leaf.

## Direct caller and first-party association

The census examines every possible E8/E9 opcode byte in `.text` over `0x1419300..0x63f0a00`, a **83719936-byte** domain, applies signed rel32, and retains every hit to the leaf. It then checks each hit against a complete linear decode from its containing FDE entry. This avoids counting an E8/E9 embedded in another instruction as a caller.

The retained CALL is at `0x23fe91f` inside `0x23fdb60..0x23fea14`. The immediately preceding MOV EDX sets k to `1`. That FDE contains authenticated RIP-relative LEAs and R_X86_64_RELATIVE bindings for `l1/src/dex_registry/clearinghouses.rs:11:29` and `l1/src/clearinghouse/oracle/oracle.rs:433:18`. These are relative first-party paths present in this target; no source pathname is invented. The source association is an observation about the caller, not proof of the leaf's original source module or concrete collection/record type. The caller's other behavior and callees are not bound here.

The census is complete for these opcodes in the stated section, not for indirect references, other executable sections or reachable execution paths. No target callees exist to identify or bind; the wrong-callee negative control is therefore inapplicable. Tests instead corrupt the actual incoming CALL target and require the caller binding to fail.

## Novelty before investment

These commands ran against the base tree before adding this packet or its tool. Each returned exit status 1, with empty stdout/stderr (no matches):

```sh
rg -i '26cf370' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg '40694640' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callee addresses requiring additional novelty checks. The chosen start lies in the assigned band and outside the excluded crowding interval. The PR-title files are local collision hints, not proof that all unpublished work is absent.

## Reproduce and validation

From the repository root, use Python 3.10+ and only its standard library. The evidence producer uses the existing ELF/FDE parsers and the existing Python instruction decoder for caller boundaries; its new narrow decoder handles every leaf instruction and rejects unsupported forms. It authenticates the entire target before interpretation or output creation. Generation and verification use mmap and small slices, never multiple whole-file byte copies. GNU objdump 2.44 was used for initial manual inspection only; the producer, tests and verifier do not invoke or require it. Python 3.13.5 was used for the local validation.

```sh
python3 tools/node115_record_insertion.py --out research/work-items/RE-001-node115-record-insertion/
python3 -m unittest tests.test_node115_record_insertion -v
python3 research/work-items/RE-001-node115-record-insertion/verify.py
make verify
make catalogue-check
```

`make doctor` and the initial `make verify` passed before selection. The packet verifier rejects missing, extra, duplicated or traversal manifest entries and compares freshly regenerated records and README byte-for-byte. Every quantitative table entry is interpolated from JSON; a targeted test checks the complete README against that rendering. The task-specific producer closes the otherwise missing reproducible byte-to-rule check for this leaf; no surrounding infrastructure, imported evidence or existing work item was modified.

Controls cover wrong digest and truncated input before output; every leaf byte below the public hash gate; decoded unsigned-comparison/stride counterfacts; non-boundary branches; shifted FDE start/extent/CIE; padding; the incoming CALL displacement; Location bytes and relocation addend; malformed manifest entries; and payload/stability/unsigned-boundary model vectors. The model is independently authored at record level and checked against explicit instruction-grounded identity permutations and Python's stable sorting. It does not execute or emulate the captured code.

## Preconditions, non-claims and next step

Normal-array semantics require a valid writable contiguous array, representable address/stride arithmetic, ordinary readable instruction memory, a valid return stack, SysV-compatible stack alignment and red-zone storage, and no array overlap with that stack scratch space. The trap guard and k=n shortcut occur before any array dereference. Empty arrays always fail this entry guard. Invalid pointers, unaligned stack, aliased scratch memory, hardware faults, concurrent mutation and nonstandard caller ABIs are outside the normal-array theorem.

No captured executable, emulator, network, install, signing, chain action or external service is used. Rust reconstruction, source-build comparison, compiler flags/lockfiles, original symbol/type/ABI recovery, whole-caller semantics, whole-node equivalence, hosted CI and a completed component gate are not claimed. Rust implementation and binary comparison are not yet implemented/measured; there are no normalization masks or copied machine-code implementation artifacts. This packet resolves the previously unbound leaf's complete local algorithm and failure guard; it is not a whole-node reconstruction claim.

Next: establish the caller's record construction and key meaning before assigning a domain name to this stable ordering operation.
