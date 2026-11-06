# RE-006: reconstruct the node #115 order time-in-force (Tif) name codec: 3 msgpack writers, 10 str/bytes visitors

This packet makes the five-name order time-in-force enum of node #115 (`Alo`, `Ioc`, `Gtc`, `FrontendMarket`, `LiquidationMarket` = tags 0..4) rebuildable as executable code in both directions, including the failure paths. A book or order-state reconstruction can now decode a stored Tif tag byte to its wire name and back, and can reproduce how an unknown wire name is reported. Three serializer copies dispatch the tag byte through a five-row jump table and write one msgpack fixstr (`0xa3` + 3 bytes, `0xae` + `FrontendMarket`, `0xb1` + `LiquidationMarket`) into a `Vec<u8>` with two capacity checks per arm. Ten visitors in three copy families accept only an exact, case-sensitive, full-length name, in two output forms: a one-byte Result (tag at +1) or a tagged word `0x09 | tag << 8`. The `&[u8]` visitors pass unknown input through a lossy UTF-8 conversion before reporting it, and free the converted copy only when the conversion had to allocate. Interpreting the original machine code byte by byte, the reconstruction agrees on all 1,260 serializer cases and all 23,520 visitor cases, and each of the ten deliberately wrong reconstructions is caught.

- Component ID: `orderbook` (task `RE-006`, book transitions). The packet uses the RE-001 unwind index (`tools/fde_extents.py`) and the shared section parser (`tools/elf_index.py`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No inferred reference source was read or copied, and no file under `research/` contains `FrontendMarket` or `LiquidationMarket`. #94 material is not used.
- Claim status:
  - **Observation:** FDE extents, decoded instruction bytes, jump-table rows, immediates and SSE constants, length gates, RELATIVE relocations, and the interpreted results of the original bytes on the listed inputs.
  - **Inference:** the serde/rmp roles (a `Serialize` that writes a unit variant name as a msgpack string, field-identifier `visit_str`/`visit_bytes`), that the five names are the order time-in-force (in `.rodata` the name strings sit beside order-wire text such as `tif`, `enum Tpsl` and `variant index 0 <= i < 5`), that slot `0x64df640` is `String::from_utf8_lossy` and slot `0x64df4a0` frees its owned buffer, and that the direct callees build `unknown_variant` errors.
  - **Unresolved:** the callers of the thirteen bodies, the internals of the grow, conversion, free and error callees, and which structures own each copy family.
- Scope:
  - Included: thirteen complete bodies, with every byte of each FDE extent decoded and only `int3` fill after the last instruction: serializers `0x25da5c0`, `0x4497590`, `0x5192420`; visitors `0x25ce8d0`, `0x25ceb10`, `0x25ced60`, `0x25cee60` (family 1), `0x4446ea0`, `0x44470f0`, `0x4447330`, `0x4447430` (family 2), `0x5171010`, `0x5171260` (family 3); jump tables `0x5f0024`, `0x7cf604`, `0x91d250`; variant-name pools `0x6432898`, `0x648a608`, `0x64a2b28`.
  - Excluded: the callee bodies listed in `callees.tsv`, all callers, and any progress gate.
  - None of the thirteen entries, three tables or three pools appears in any file under `research/work-items` or in any open PR file list at the time of writing.
  - A development byte scan (not part of the generated evidence) found the `Fron` bytes in `.text` in exactly eight FDEs: the three serializers and the five `&str` visitors. A rip-relative `lea` scan found the three pools loaded only by the ten visitors.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3. Only the standard library is needed, plus `tools/elf_index.py` and `tools/fde_extents.py`.

- The producer checks the full SHA-256 of the input before it parses anything.
- It never executes the capture, starts no process and makes no network access. It interprets the selected machine code in Python.
- Its output contains no time, randomness, absolute path or unordered-dict iteration.

```sh
python3 tools/re006_tif_codec_115.py --out research/work-items/RE-006-tif-codec-115
python3 -m unittest tests.test_re006_tif_codec_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Determinism check (two independent outputs, different hash seed and time zone):

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re006_tif_codec_115.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re006_tif_codec_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes exactly the thirteen generated files below. `README.md` and `MANIFEST.sha256` are maintained separately. A full run takes about 12 s.

The producer exits non-zero and writes nothing if any of these holds:
- the digest differs;
- an entry is not an FDE start;
- any byte in a body falls outside the supported instruction subset;
- a call reaches an unmodelled target, a callee would have two roles, or a call's arguments differ from the expected ones;
- a visitor's call sequence is not `[lossy] unknown [free]`, it reports text other than the converted text, or it frees a buffer other than the owned copy;
- a store leaves scratch memory;
- a jump-table row does not land on an instruction start of its serializer;
- a visitor loads a pool other than the three listed, or a pool slot lacks a RELATIVE relocation or differs from the tag order;
- any case disagrees with the reconstruction;
- any negative control is not caught.

| Generated evidence | Contents |
| --- | --- |
| `functions.tsv` | 13 bodies: role, entry, FDE end, size, decoded instruction count and bytes (equal to the FDE size), LSDA, body SHA-256, direct and slot callees |
| `instructions.tsv` | 1,720 decoded instructions (VA, length, raw bytes, operation, branch/call target) |
| `callees.tsv` | 11 callees and the role each one is bound to from the body shapes |
| `serializer-jump-tables.tsv` | 15 rows: per serializer, table base, tag, row VA, signed rel32, arm VA, name |
| `serializer-arms.tsv` | per serializer, every marker store, name-bytes store (imm, movabs, rip `movups`), reserve bound, grow `additional` and result-word load, in body order |
| `visitor-literals.tsv` | per visitor, the length gates, per-byte compares, xor immediates, movabs words, `pcmpeqb` constants and result stores |
| `variant-refs.tsv` | per visitor: family, input kind, output form, the rip-relative `lea` of its error arm and the pool it loads |
| `variant-pool.tsv` | 15 rows: the three `&[&str; 5]` pools, slot VA, `.rela.dyn` file offset of the RELATIVE relocation, string VA, length, text |
| `serializer-cases.tsv` | 1,260 cases: serializer × (5 tags × length {0,1,7,64} × spare capacity 0..20); appended bytes, grow calls (`length+additional`), final length, result word, arm, verdict |
| `visitor-cases.tsv` | 2,352 inputs × 10 visitors: outcome per copy (`ok:<value>`, `err`, `err:lossy`, `err:lossy:free`), reconstruction, verdict |
| `paths.tsv` | per body, the number of inputs ending after each interpreted step count and outcome (path classes) |
| `negative-controls.tsv` | ten wrong reconstructions and how many cases each fails |
| `summary.json` | totals, callee roles, pools and pass flags |

## Evidence

Coordinates are linked virtual addresses (VA). Section membership and file offsets come from `elf_index.sections`, with SHT_NOBITS sections excluded. Body extents come from `fde_extents.fde_extents`. The four `&[u8]` visitors have an LSDA (their landing pads free the converted copy and call `_Unwind_Resume` `0x63f0a50`); the other nine have none.

**Serializers** (`0x25da5c0`, `0x4497590`, `0x5192420`; 863 bytes and 211 instructions each, differing only in their jump table and grow callee). Human-readable excerpt of `0x25da5c0` (GNU objdump 2.42, not used by the tool):

```
25da5c7: movzbl (%rsi),%ecx ; lea 0x5f0024,%rsi ; movslq (%rsi,%rcx,4),%rcx ; add %rsi,%rcx ; jmp *%rcx
25da5da: (Alo) mov (%rdx),%rcx ; mov 0x10(%rdx),%rsi ; cmp %rsi,%rcx ; je grow(len,1)
25da5ee:       movb $0xa3,(%rdi,%rsi,1) ; inc %rsi ; mov %rsi,0x10(%rdx)
25da5f9:       sub %rsi,%rcx ; cmp $0x2,%rcx ; jbe grow(len,3)
25da606:       movb $0x6f,0x2(..) ; movw $0x6c41,(..)                 ; "Al" "o"
25da62a: (LiquidationMarket) movb $0xb1 ; cmp $0x10,%rcx ; jbe grow(len,17)
25da642:       movups 0x5f1475(%rip),%xmm0 ; movups %xmm0,(..) ; movb $0x74,0x10(..)   ; 16 bytes + "t"
25da6ab: (FrontendMarket) movb $0xae ; cmp $0xd,%rdi ; jbe grow(len,14)
25da6c3:       movabs "ndMarket" -> +6 ; movabs "Frontend" -> +0               ; overlapping qwords
25da721: mov %rsi,0x10(%rdx) ; movabs $0x8000000000000004,%rcx ; mov %rcx,(%rax) ; ret
```

- **Tag selection.** A five-row table of signed rel32 offsets from the table base (`serializer-jump-tables.tsv`) selects the arm. Tags 0..4 select `Alo`, `Ioc`, `Gtc`, `FrontendMarket`, `LiquidationMarket`, matching the pool order. There is no range check before the indexed load, so the compiled code relies on the enum invariant (tag <= 4).
- **Growth calls.** Every growth call passes `(vec, len, additional, 1, 1)`. `additional` is 1 before the marker when `cap == len`. After the marker it is the name length (3, 14 or 17) when the remaining capacity is `<= len(name) - 1`, that is, strictly less than the name length.
- **Name bytes.** The 17-byte name comes from a rip-relative `movups` of `LiquidationMarke` at `0x5f1475` (the family-1 pool's own string) plus a `t` byte. The 14-byte name is two overlapping qword stores (`Frontend` at +0, `ndMarket` at +6).
- **Result.** Every path stores the word `0x8000000000000004` to `[rdi]` and returns `rdi`. No path returns an error.

**`&str` visitors.** Result form (`0x25ced60`, `0x4447330`; 255 bytes, 75 instructions) and tagged form (`0x25cee60`, `0x4447430`, `0x5171260`; 229 bytes, 62 instructions):

```
25ced63: cmp $0x3,%rdx ; je len3 ; cmp $0xe,%rdx ; jne len17
25ced6f: movabs "Frontend",%rcx ; xor (%rsi),%rcx ; movabs "ndMarket",%rdi ; xor 0x6(%rsi),%rdi ; or ; jne error
25ced9c: (len3) movzwl (%rsi),%ecx ; xor $0x6c41 ; movzbl 0x2(%rsi),%edi ; xor $0x6f ; or %cx,%di ; je Alo   ; then Ioc, Gtc
25cede4: (len17) cmp $0x11,%rdx ; jne error ; movdqu (%rsi),%xmm0 ; movzbl 0x10(%rsi),%ecx ; movd %ecx,%xmm1
25cedf6:        pcmpeqb 0x456b00,%xmm0 ; pcmpeqb 0x4566f0,%xmm1 ; pand ; pmovmskb ; cmp $0xffff ; jne error
25ced93: movb $tag,0x1(%rax) ; xor %ecx,%ecx ; mov %cl,(%rax) ; ret         ; result form: Ok(tag)
25cee31: push %rbx ; lea pool,%r8 ; mov $5,%ecx ; ... call unknown(ptr,len,pool,5) ; mov %rax,0x8(%rbx) ; movb $1,(%rbx)
```

- **Length gates.** Lengths 3, 14 and 17 are the only ones that reach a compare; any other length goes to the error arm.
- **17-byte compare.** `0x456b00` holds `LiquidationMarke` and `0x4566f0` holds `t` followed by 15 zero bytes, so `pand`/`pmovmskb` equals `0xffff` exactly when all 17 bytes match (`visitor-literals.tsv` lists both constants from the file bytes).
- **Outputs.** The result form writes byte 0 = 0 and byte 1 = tag, or byte 0 = 1 and the error pointer at +8. The tagged form writes `0x09 | tag << 8`, or lets the error callee fill the 32-byte output with `(out, ptr, len, pool, 5)`.

**`&[u8]` visitors.** Result form (`0x25ce8d0`, `0x44470f0`; 565 bytes) and tagged form (`0x25ceb10`, `0x4446ea0`, `0x5171010`; 579 bytes). These compare byte by byte (`cmpb $imm,k(%rsi)`), with a first-byte switch (`A`, `G`, `I`) for the three-letter names. On any mismatch:

```
25cea8b: mov %rax,%r14 ; mov %rsp,%rdi ; call *0x64df640    ; Cow<str> = lossy(ptr,len) at [rsp]
25cea97: mov 0x8(%rsp),%rbx ; mov 0x10(%rsp),%rsi ; lea pool,%rdx ; mov $5,%ecx ; mov %rbx,%rdi ; call unknown
25ceabb: mov %rcx,0x8(%r14) ; movb $1,(%r14)
25ceac3: mov (%rsp),%rsi ; test %rsi,%rsi ; jle done ; mov %rbx,%rdi ; xor %edx,%edx ; call *0x64df4a0   ; free owned copy
```

- The first word of the conversion result is the capacity of an owned `String` or the borrowed niche `0x8000000000000000`, so the signed `jle` skips the free for borrowed text. The tool's conversion stub follows `from_utf8_lossy`: valid UTF-8 is borrowed, and any invalid sequence produces an owned copy with U+FFFD replacements.
- The tagged form copies the 32-byte error built on the stack (`movups` x2) into the output before freeing.

**Variant pools** (`0x6432898`, `0x648a608`, `0x64a2b28`). Each pool is five `(ptr, len)` slots, one pool per copy family, and each slot pointer is a `.rela.dyn` R_X86_64_RELATIVE addend read by the tool. The texts are `Alo`, `Ioc`, `Gtc`, `FrontendMarket`, `LiquidationMarket` in tag order, and each pool points into its own contiguous copy of the concatenated names (`0x5f145e`, `0x7d0c45`, `0x91e4f1`).

**Interpreter.**
- The interpreter is a fixed x86-64 subset decoder and machine contained in the tool itself, so the packet stands alone. It covers the general ALU forms, accumulator immediates, byte compares, `movzx` 8/16, jump-table dispatch (`movslq` + `jmp *reg`), rip-slot calls and the SSE2 forms used (`movups`, `movdqu`, `movd`, `pcmpeqb`, `pand`, `pmovmskb`). ZF, CF, SF and OF are kept; `jle` uses `ZF or SF != OF`.
- Writes go only to scratch memory above the image. Reads below it come from file-backed sections.
- Calls go only to the bound callees, modelled as stubs that record their arguments. After a call, the interpreter overwrites the caller-saved registers, so the bodies cannot depend on their old values.

`paths.tsv` gives the path classes. For example, `0x25ced60` has 9 classes (five success step counts, then errors after 22, 26, 31 or 36 steps); each `&[u8]` visitor splits its errors into `err` and `err+free` classes over many step counts, since its byte-by-byte compare exits at the first mismatching byte; each serializer has 10 classes (no grow, one grow, or two grows for the long names).

## Implementation and comparison

The reconstruction lives in `tools/re006_tif_codec_115.py` as pure functions. There is no Rust implementation yet.

- `recon_serialize(tag, cap, len)` appends `0xa0 | len(name)` followed by `NAMES[tag]`. It reserves 1 when `cap == len`, then reserves `len(name)` when `cap - len < len(name)`, and returns `0x8000000000000004`.
- `recon_classify(text)` returns the index of `text` in `NAMES` only for an exact, full-length, case-sensitive match.
- `recon_visitor(kind, form, text)` gives `('ok', tag)` for the result form or `('ok', 0x09 | tag << 8)` for the tagged form. For a non-name, `&str` visitors report the text unchanged, and `&[u8]` visitors report `from_utf8_lossy(text)` and free the copy exactly when the input is not valid UTF-8.

Comparison inputs:
- **Serializer:** 3 copies × 5 tags × 4 starting lengths × 21 spare capacities = 1,260 cases. Each case compares the appended bytes, the exact sequence of growth calls `(len, additional)`, the final length and the result word.
- **Visitors:** 2,352 distinct inputs × 10 copies = 23,520 cases. Each case compares status, value, the reported text and whether a copy was freed. The inputs are:
  - the empty string and every prefix of each name;
  - each name plus one byte, plus a doubled last byte, and plus a NUL; with the last byte replaced by `0xff`; with a two-byte UTF-8 sequence spliced in;
  - each name in lower and in upper case;
  - every single-byte substitution of every position with 55 values (`0x00`, `0x09`, `0x0a`, `0x80`, `0xc3`, `0xe2`, `0xff` and every second printable ASCII byte), plus the case flip of that byte;
  - cross-name half splices and concatenations;
  - `A` and `0x80` repeated 0..19 times.

  179 of the inputs are invalid UTF-8; 895 visitor cases (179 × 5 `&[u8]` copies) take the owned-copy free.

Result: 1,260/1,260 serializer cases and 23,520/23,520 visitor cases match.

Negative controls (`negative-controls.tsv`). Each count must be above 0, or the producer fails:

| Wrong reconstruction | Failing cases |
| --- | --- |
| serializer in alphabetical tag order | 504 / 1,260 |
| serializer without the second (name-length) reserve | 498 / 1,260 |
| serializer reserving when spare equals the name length | 60 / 1,260 |
| serializer using a str8 marker (`0xd9 len`) | 1,260 / 1,260 |
| visitor folding case | 470 / 23,520 |
| visitor checking only the first 16 bytes of `LiquidationMarket` | 540 / 23,520 |
| visitor selecting a three-letter name by its first byte | 3,440 / 23,520 |
| visitor accepting a name prefix | 350 / 23,520 |
| visitor reporting raw bytes without lossy conversion or free | 895 / 23,520 |
| visitor with `Alo` and `Ioc` swapped | 20 / 23,520 |

The unit test also mutates the target bytes and checks that each change is detected:
- swapping jump-table rows 0 and 2 of `0x5f0024`: tag 0 now writes `Gtc`;
- the `F` compare at `0x25ce8f0`: `FrontendMarket` is now rejected;
- the `t` byte of the SSE constant at `0x4566f0`: `LiquidationMarket` is now rejected;
- the reserve bound at `0x25da5ff`: the growth sequence changes;
- a `ud2` at a body entry: rejected as an unsupported instruction.

It also checks that each of these is rejected: an unmodelled call, an error call that loads a different pool, an out-of-scratch store, a read outside every section, and a wrong input digest.

## Results and limitations

- All 13 selected bodies are fully decoded: 1,720 instructions, with decoded bytes equal to FDE bytes.
- 1,260/1,260 serializer cases and 23,520/23,520 visitor cases match the reconstruction.
- 10/10 negative controls are caught.
- The callees are stubs, not reconstructions. The growth policy, the conversion internals, the free and the error value are outside the claim; only the callees' arguments, their call order and how the bodies use their results are compared. The conversion stub's lossy output is the Python `errors='replace'` UTF-8 decode, which follows the same maximal-subpart replacement rule as Rust; the comparison of reported text depends on that stub.
- Tag bytes above 4 are not driven through the serializers: the jump table has no bound check, so such bytes would index past the table. A valid Rust value of the enum never has those tags.
- The Tif reading of the five names and the serde/rmp roles are inferences. No caller was traced.
- No progress gate is requested. This packet covers one enum codec, not the `orderbook` component.

Next question: which order-wire and resting-order struct serializers call the three serializer copies, and under which map key (`tif`) do they write this field?
