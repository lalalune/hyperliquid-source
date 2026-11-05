# RE-010: reconstruct the node #115 `Action` type-name matcher (wire `type` string to variant index)

With this packet the whole `type` string to `Action` variant step of action decoding can be rebuilt: the matcher accepts exactly the 92 wire names of the `VARIANTS` slice (exact bytes, case-sensitive, whole string, no aliases), maps name `i` to variant index `i`, and sends every other string to serde `unknown_variant(value, VARIANTS)` with length 92. A pure Python reconstruction (`reconstructed_match`, and the Rust-shaped `type_matcher.rs.txt`) agrees with an interpretation of the original bytes on 6,864/6,864 cases over two unowned copies, every one of the 826 instructions of each copy is executed, and 10/10 wrong reconstructions plus 12/12 single-byte image corruptions are caught.

- Component ID: `action-dispatch` (task RE-010); the inverse of the `Action` serializer tag dispatch.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked by the tool before any read).
- Source commit / reference commit: repository main `05bc2de303c05525b71e7e257426e741bc66a390`. No reference source text is copied; `references/can1357-hl` was not needed.
- Claim status: observation (bytes, tables, interpreted outcomes) plus inference (the serde role of the function, the meaning of result byte `0x09`). Unresolved items are listed under Results.
- Scope included: two same-shape matcher copies, `0x2ba1af0..0x2ba2bde` (copy A, `VARIANTS` at `0x644cc40`) and `0x3662730..0x366381e` (copy B, `VARIANTS` at `0x6467f98`), their length switch tables, every compare arm, the `bcmp` arm, the unknown-variant failure path and the success stores.
- Scope excluded: the same-shape copies `0x2ba0a70`, `0x36616b0` and `0x4d67530`, whose single arms are read by the merged packets `RE-010-gov-vote-path-115`, `RE-010-set-referrer-path-115` and `RE-010-claim-rewards-path-115` (this tool never decodes them); the 15.5 KB functions that also load the slice (`0x2b99100`, `0x2b9cdb0`, `0x3659d20`, `0x365d9d0`, `0x4d63870`); the payload deserializers chosen after the index is known; `unknown_variant` itself (`0x17fbba0`, `0x2f7fef0`).

## Reproduce

From the repository root, Python 3 standard library only, no binutils and no subprocess:

```
python3 tools/re010_action_type_matcher_115.py --out research/work-items/RE-010-action-type-matcher-115
python3 tests/test_re010_action_type_matcher_115.py
```

The tool checks the input SHA-256, reads `.rela.dyn`, `.dynsym`, `.dynstr` and section bytes through `tools/elf_index.py` (`sections`; NOBITS sections are excluded from VA reads), and rewrites the seven generated files. It runs in about 7 s. Two runs into different folders, and runs with a different `PYTHONHASHSEED` and `TZ`, give byte-identical files. The binary is never executed: the matcher bytes are interpreted by a fixed-pattern x86-64 subset interpreter inside the tool.

Generated files (all listed in `MANIFEST.sha256`):

| File | Rows | Content |
| --- | ---: | --- |
| `summary.json` | 1 object | counts, switch tables, coverage, mutant results |
| `names.tsv` | 184 | per copy and variant: wire name, length, switch arm, success store VA, stored word, step count |
| `length-switch.tsv` | 74 | per copy and length 4..40: table target and whether it is a compare arm or the failure path |
| `cases.tsv` | 6,864 | per copy and case: input hex, interpreted outcome, reconstructed outcome, calls, steps |
| `insns.tsv` | 1,652 | per copy: every instruction of the FDE extent with its bytes, decoded operation and the number of cases that executed it |
| `mutants.tsv` | 10 | wrong reconstructions and the first case that kills each |
| `type_matcher.rs.txt` | 98 | the reconstruction as a Rust `match` |

## Evidence

Coordinates are virtual addresses of the PIE image; file offset = VA - 0x1000 in `.text` and VA - 0x2000 in `.data.rel.ro`, as resolved from the section table.

**The name slice.** `VARIANTS` is a `&[&str]` of 92 entries, 16 bytes each. Each pointer slot carries an `R_X86_64_RELATIVE` relocation whose addend points into `.rodata`; the length word sits beside it. Entry 0 is `noop`, entry 91 is `cDeposit2`. The two copies' slices (`0x644cc40`, `0x6467f98`) give the same 92 byte strings, which are also the serializer wire names (same order as the serializer tag words `0x86..0xe1`).

**Function boundaries.** Both copies are whole FDE extents (`0x2ba1af0..0x2ba2bde`, `0x3662730..0x366381e`, 4,334 bytes). A linear sweep with the tool decoder ends exactly at the FDE end with 826 instructions per copy, so there is no undecoded data between instructions.

**Shape (human-read excerpt of copy A, objdump, not a generated file).**

```
2ba1af9  mov rax,rdi            ; out pointer
2ba1afc  lea rcx,[rdx-0x4]      ; len - 4
2ba1b00  cmp rcx,0x24           ; 37 entries, lengths 4..40
2ba1b04  ja  2ba294b            ; failure path
2ba1b0a  lea rdi,[rip+...]      ; table 0x6085d4
2ba1b11  movsxd rcx,[rdi+rcx*4]
2ba1b18  jmp rcx
2ba1b1a  cmp dword [rsi],0x706f6f6e   ; "noop"
2ba1b26  mov word [rax],0x9            ; Ok, index 0
2ba294b  lea rcx,[VARIANTS]; mov r8d,0x5c; call 17fbba0   ; unknown_variant(value, VARIANTS)
```

**Length switch.** `lea rcx,[rdx-4]; cmp rcx,0x24; ja` then a 37-entry relative jump table (copy A `0x6085d4`, copy B `0x7993a4`). Twenty-seven entries are compare arms: lengths 4-25, 28, 29, 30, 32 and 40, which is exactly the set of wire-name lengths. The other ten entries (26, 27, 31, 33-39) and every length outside 4..40 go to the failure path (`0x2ba294b`, `0x366358b`).

**Compare arms.** Inside an arm the candidates of that length are tested one after another with immediate compares (`cmp` of a byte, word, dword or qword at `[rsi+k]`), overlapping 32-bit or 64-bit `xor`/`or` pairs (for example `scheduleCancel` as qwords at offsets 0 and 6), or SSE `pcmpeqb`/`pand`/`pmovmskb == 0xffff` against 16-byte `.rodata` constants for longer names. The single length-40 name `VoteEthFinalizedValidatorSetUpdateAction` is compared by an indirect call through the GOT slot `0x64df9f8`, whose dynamic relocation names `bcmp`, followed by `test ecx,ecx`.

**Success store.** Each name ends in `mov word [rax], 0x??09`: byte 0 is `0x09`, byte 1 is the variant index. There are 92 distinct success stores per copy and each is reached by exactly one name (`success_stores_one_to_one`).

**Failure path.** `unknown_variant(out=rsp, value=(rsi, rdx), expected=(VARIANTS, 92))`, then the 32-byte error is copied to `[rax]`. The interpreter checks these four arguments on every failing case. Copy A calls `0x17fbba0`, copy B calls `0x2f7fef0`; their bodies are not read.

## Implementation and comparison

Independent Rust path: not yet implemented in a crate; `type_matcher.rs.txt` is the reconstruction in Rust form (a 92-arm `match` with the `unknown_variant` fallback), generated from the slice bytes.

Comparison method (`tools/re010_action_type_matcher_115.py`):

1. `decode` recognises a fixed byte-pattern subset (prefixes `66`/`f3`/REX, ModRM with SIB, disp8/disp32 and RIP-relative forms; ALU `01 03 09 0b 31 33 39 3b 85 89 8b 8d 63 80 81 83 c7 b8+r`, `push`/`pop`, `jcc`/`jmp` rel8/rel32, `jmp reg`, `call rel32`, `call [rip+d]`, `ret`, `movzx`, `movdqu` load/store, `movq`, `movd`, `pcmpeqb`, `pand`, `pmovmskb`). Anything else raises `Fault`.
2. `Machine.run` executes from the function start with the input in a private buffer of exactly `len` bytes (any read past it raises `Fault`), the output in a 32-byte buffer and a private stack. Static reads go through the section table. `bcmp` is modelled as byte equality; `unknown_variant` stores a fixed 32-byte marker. `ret` with an unbalanced stack raises `Fault`.
3. `reconstructed_match(name)` returns `('ok', i)` for `name == VARIANTS[i]`, else `('unknown', None)`.
4. Cases per copy (3,432): the 92 names; every single-position ASCII case flip (1,457) and +1 byte change (1,467); each name truncated by one byte (91), extended by `s` (92) and by NUL (92), and with an `Action` suffix added or removed (92); and `a` repeated 0..48 times (49), which drives every switch entry and both out-of-range sides.

Corruption controls: the tool rejects a changed digest; `mutants.tsv` lists 10 wrong reconstructions (case-insensitive, prefix match, Pascal alias, Rust `Action` suffix alias, last variant dropped, index off by one, two indices swapped, length plus first four bytes only, last byte ignored, trailing NUL accepted), each killed by at least one case; `summary.json` `image_mutants` flips the last byte of 12 sampled compare instructions (including the switch bound) in a private copy and requires a divergence on the names or filler inputs (12/12). The tests also corrupt the `noop` compare constant and start the interpreter in the middle of the function.

## Results and limitations

| Metric | Copy A `0x2ba1af0` | Copy B `0x3662730` |
| --- | ---: | ---: |
| cases | 3,432 | 3,432 |
| interpreted = reconstructed | 3,432 | 3,432 |
| accepted / unknown_variant | 92 / 3,340 | 92 / 3,340 |
| instructions executed / in extent | 826 / 826 | 826 / 826 |
| success stores, one name each | 92 / 92 | 92 / 92 |
| switch entries (compare arms / failure) | 37 (27 / 10) | 37 (27 / 10) |

Reconstruction mutants 10/10 killed; image mutants 12/12 killed; unit tests 10/10 pass.

Limits:

- The interpreter models only the instructions present in these two extents and only the flags they use; it is not a general x86 model. The parity condition is rejected rather than modelled.
- The meaning of result byte `0x09` (the Ok niche of the visitor's `Result`) is inferred from the store pattern, not from the caller.
- Callers of the two copies, and which deserializer path (borrowed string, owned string or `Content`) uses each, are not traced here.
- The three excluded same-shape copies are assumed equal only by their shape; this packet does not decode them.
- No progress gate is requested. `action-dispatch` stays at its current gate.

Next question: which payload deserializer does each index select after this matcher, starting with the 15.5 KB functions `0x2b99100`/`0x2b9cdb0` that load the same slice?
