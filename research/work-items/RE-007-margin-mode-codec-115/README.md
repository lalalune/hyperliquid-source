# RE-007: reconstruct the node #115 margin-mode name codec: 3 msgpack writers, 8 str/bytes visitors

This packet makes the three-name margin-mode enum of node #115 (`normal`, `noCross`, `strictIsolated` = tags 0..2) rebuildable as executable code in both directions, including the failure paths. A clearinghouse or risk reconstruction can now decode a stored margin-mode tag byte to its wire name and back, knows that the compiled writers send every tag byte above 1 to `strictIsolated`, and can reproduce how an unknown wire name is reported. Three serializer copies dispatch the tag byte through a `test`/`cmp $1` chain and write one msgpack fixstr (`0xa6 normal`, `0xa7 noCross`, `0xae strictIsolated`) into a `Vec<u8>` with two capacity checks per arm. Eight visitors in three copy families accept only an exact, case-sensitive, full-length name, in two output forms: a one-byte Result (tag at +1) or a tagged word `0x09 | tag << 8`. The `&[u8]` visitors pass unknown input through a lossy UTF-8 conversion before reporting it, and free the converted copy only when the conversion had to allocate. Interpreting the original machine code byte by byte, the reconstruction agrees on all 2,274 serializer cases (all 256 tag bytes) and all 12,640 visitor cases, and each of the twelve deliberately wrong reconstructions is caught.

- Component ID: `risk` (task `RE-007`, risk/oracles/liquidation, `l1/clearinghouse/*` leads). The packet uses the RE-001 unwind index (`tools/fde_extents.py`) and the shared section parser (`tools/elf_index.py`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No inferred reference source was read or copied, and no file under `research/`, `tools/` or `tests/` contains `noCross` or `strictIsolated`. #94 material is not used.
- Claim status:
  - **Observation:** FDE extents, decoded instruction bytes, the tag-dispatch compares, immediates, length gates, RELATIVE relocations, and the interpreted results of the original bytes on the listed inputs.
  - **Inference:** the serde/rmp roles (a `Serialize` that writes a unit variant name as a msgpack string, field-identifier `visit_str`/`visit_bytes`), that the three names are the per-asset margin mode (in `.rodata` the family-2 string sits right after `variant index 0 <= i < 3`, and the family-1/3 strings sit beside `enabled`/`blocked`), that slot `0x64df640` is `String::from_utf8_lossy` and slot `0x64df4a0` frees its owned buffer, and that the direct callees build `unknown_variant` errors.
  - **Unresolved:** the callers of the eleven bodies; four larger bodies per family that also load the pools (`0x1def7c0`, `0x1e201f0`, `0x1fa4630`, `0x1fac540` in family 1; `0x3945390`, `0x394a4e0`, `0x3f7fe90`, `0x3fba8b0` in family 2; `0x567f110` in family 3); the internals of the grow, conversion, free and error callees; and which structures own each copy family.
- Scope:
  - Included: eleven complete bodies, with every byte of each FDE extent decoded and only `int3` fill after the last instruction: serializers `0x2924dc0`, `0x3c41210`, `0x5a27570`; visitors `0x2868660`, `0x28687f0`, `0x2868990` (family 1), `0x3bcf6b0`, `0x3bcf850`, `0x3bcf9e0` (family 2), `0x59fdd20`, `0x59fdec0` (family 3); variant-name pools `0x643e188`, `0x6475de0`, `0x64b7d28`.
  - Excluded: the callee bodies listed in `callees.tsv`, the nine larger pool-loading bodies above, all callers, and any progress gate.
  - None of the eleven entries or three pools appears in any file under `research/work-items` or in any open PR file list at the time of writing.
  - A development byte scan (not part of the generated evidence) found the `noCr` and `ctIs` bytes in `.text` in exactly six FDEs: the three serializers and the three `&str` visitors. A rip-relative `lea` scan found the three pools loaded by the eight visitors and the nine larger bodies listed as unresolved.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3. Only the standard library is needed, plus `tools/elf_index.py` and `tools/fde_extents.py`.

- The producer checks the full SHA-256 of the input before it parses anything.
- It never executes the capture, starts no process and makes no network access. It interprets the selected machine code in Python.
- Its output contains no time, randomness, absolute path or unordered-dict iteration.

```sh
python3 tools/re007_margin_mode_codec_115.py --out research/work-items/RE-007-margin-mode-codec-115
python3 -m unittest tests.test_re007_margin_mode_codec_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Determinism check (two independent outputs, different hash seed and time zone):

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re007_margin_mode_codec_115.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re007_margin_mode_codec_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes exactly the thirteen generated files below. `README.md` and `MANIFEST.sha256` are maintained separately. A full run takes about 9 s.

The producer exits non-zero and writes nothing if any of these holds:
- the digest differs;
- an entry is not an FDE start;
- any byte in a body falls outside the supported instruction subset;
- a call reaches an unmodelled target, a callee would have two roles, or a call's arguments differ from the expected ones;
- a visitor's call sequence is not `[lossy] unknown [free]`, it reports text other than the converted text, or it frees a buffer other than the owned copy;
- a store leaves scratch memory;
- a serializer's tag dispatch is not a two-compare chain before the first vector load;
- a visitor loads a pool other than the three listed, or a pool slot lacks a RELATIVE relocation or differs from the tag order;
- any case disagrees with the reconstruction;
- any negative control is not caught.

| Generated evidence | Contents |
| --- | --- |
| `functions.tsv` | 11 bodies: role, entry, FDE end, size, decoded instruction count and bytes (equal to the FDE size), LSDA, body SHA-256, direct and slot callees |
| `instructions.tsv` | 1,091 decoded instructions (VA, length, raw bytes, operation, branch/call target) |
| `callees.tsv` | 11 callees and the role each one is bound to from the body shapes |
| `serializer-dispatch.tsv` | 15 rows: per serializer, the tag load, `test`, `je`, `cmp $1`, `jne` with targets and raw bytes |
| `serializer-arms.tsv` | per serializer, every marker store, name-bytes store (imm and movabs), reserve bound, grow `additional` and result-word load, in body order |
| `visitor-literals.tsv` | per visitor, the length gates, per-byte compares, xor immediates, movabs words and result stores |
| `variant-refs.tsv` | per visitor: family, input kind, output form, the rip-relative `lea` of its error arm and the pool it loads |
| `variant-pool.tsv` | 9 rows: the three `&[&str; 3]` pools, slot VA, `.rela.dyn` file offset of the RELATIVE relocation, string VA, length, text |
| `serializer-cases.tsv` | 2,274 cases: serializer × (3 tags × length {0,1,7,64} × spare capacity 0..20, plus tags 3..255 at (cap 7, len 7) and (cap 64, len 0)); appended bytes, grow calls (`length+additional`), final length, result word, arm, verdict |
| `visitor-cases.tsv` | 1,580 inputs × 8 visitors: outcome per copy (`ok:<value>`, `err`, `err:lossy`, `err:lossy:free`), reconstruction, verdict |
| `paths.tsv` | per body, the number of inputs ending after each interpreted step count and outcome (path classes) |
| `negative-controls.tsv` | twelve wrong reconstructions and how many cases each fails |
| `summary.json` | totals, callee roles, pools and pass flags |

## Evidence

Coordinates are linked virtual addresses (VA). Section membership and file offsets come from `elf_index.sections`, with SHT_NOBITS sections excluded. Body extents come from `fde_extents.fde_extents`. The five `&[u8]` visitors have an LSDA (their landing pads free the converted copy and call `_Unwind_Resume` `0x63f0a50`); the other six have none.

**Serializers** (`0x2924dc0`, `0x3c41210`, `0x5a27570`; 548 bytes and 134 instructions each, differing only in their grow callee). Human-readable excerpt of `0x2924dc0` (GNU objdump 2.42, not used by the tool):

```
2924dc7: movzbl (%rsi),%ecx ; test %ecx,%ecx ; je normal ; cmp $0x1,%ecx ; jne strictIsolated
2924dd7: (noCross) mov (%rdx),%rcx ; mov 0x10(%rdx),%rsi ; cmp %rsi,%rcx ; je grow(len,1)
2924deb:       movb $0xa7,(%rdi,%rsi,1) ; inc %rsi ; mov %rsi,0x10(%rdx)
2924df6:       sub %rsi,%rcx ; cmp $0x6,%rcx ; jbe grow(len,7)
2924e03:       movl "ross",0x3(..) ; movl "noCr",(..) ; add $0x7,%rsi       ; overlapping dwords
2924e1b: (normal) movb $0xa6 ; cmp $0x5,%rcx ; jbe grow(len,6) ; movw "al",0x4(..) ; movl "norm",(..)
2924e5b: (strictIsolated) movb $0xae ; cmp $0xd,%rdi ; jbe grow(len,14)
2924e87:       movabs "Isolated" -> +6 ; movabs "strictIs" -> +0           ; overlapping qwords
2924ea8: mov %rsi,0x10(%rdx) ; movabs $0x8000000000000004,%rcx ; mov %rcx,(%rax) ; ret
```

- **Tag selection.** `serializer-dispatch.tsv` holds the five dispatch instructions per copy, read from the bytes. Tag 0 selects `normal`, tag 1 selects `noCross`, and every other byte (2..255) falls through `jne` to `strictIsolated`. Unlike a jump table, the chain is total: an out-of-range tag still writes a valid name. The tool drives all 256 tag bytes through each copy.
- **Growth calls.** Every growth call passes `(vec, len, additional, 1, 1)`. `additional` is 1 before the marker when `cap == len`. After the marker it is the name length (6, 7 or 14) when the remaining capacity is `<= len(name) - 1`, that is, strictly less than the name length.
- **Name bytes.** Each name is written by two overlapping immediate stores: `norm` + `al` at +4, `noCr` + `ross` at +3, `strictIs` + `Isolated` at +6.
- **Result.** Every path stores the word `0x8000000000000004` to `[rdi]` and returns `rdi`. No path returns an error.

**`&str` visitors** (tagged form only: `0x2868990`, `0x3bcf9e0`, `0x59fdec0`; 144 bytes, 41 instructions each):

```
2868990: cmp $0x6,%rdx ; je len6 ; cmp $0x7,%rdx ; jne len14
286899c: (len7) mov "noCr",%eax ; xor (%rsi),%eax ; mov "ross",%ecx ; xor 0x3(%rsi),%ecx ; or ; jne error ; movw $0x109,(%rdi)
28689b8: (len6) mov "norm",%eax ; xor (%rsi),%eax ; movzwl 0x4(%rsi),%ecx ; xor $0x6c61 ; or ; jne error ; movw $0x9,(%rdi)
28689d6: (len14) cmp $0xe,%rdx ; jne error ; movabs "strictIs" xor (%rsi) ; movabs "Isolated" xor 0x6(%rsi) ; or ; jne error ; movw $0x209
2868a05: push %rbx ; lea 0x643e188,%rcx ; mov $0x3,%r8d ; mov %rdi,%rbx ; call unknown(out,ptr,len,pool,3)
```

- **Length gates.** Lengths 6, 7 and 14 are the only ones that reach a compare; any other length goes to the error arm.
- **Whole-word compares.** Each name is compared by two overlapping xor words, so every byte position is covered exactly; the `first4_only` and `first8_only` negative controls show what dropping the second word would accept.
- **Outputs.** The tagged form writes `0x09 | tag << 8`, or lets the error callee fill the 32-byte output with `(out, ptr, len, pool, 3)`.

**`&[u8]` visitors.** Result form (`0x2868660`, `0x3bcf850`; 392 bytes, 112 instructions) and tagged form (`0x28687f0`, `0x3bcf6b0`, `0x59fdd20`; 406 bytes, 114 instructions). These use the same length gates (6 → `normal`, 7 → `noCross`, 14 → `strictIsolated`) and then compare byte by byte (`cmpb $imm,k(%rsi)`). On any mismatch:

```
286876e: mov %rax,%r14 ; mov %rsp,%rdi ; call *0x64df640    ; Cow<str> = lossy(ptr,len) at [rsp]
286877a: mov 0x8(%rsp),%rbx ; mov 0x10(%rsp),%rsi ; lea 0x643e188,%rdx ; mov $3,%ecx ; mov %rbx,%rdi ; call unknown
2868798: mov %rcx,0x8(%r14) ; movb $1,(%r14)
28687a6: mov (%rsp),%rsi ; test %rsi,%rsi ; jle done ; mov %rbx,%rdi ; xor %edx,%edx ; call *0x64df4a0   ; free owned copy
```

- The result form writes `movw $0x100*tag,(%rax)` on success (byte 0 = 0, byte 1 = tag), or byte 0 = 1 and the error pointer at +8.
- The first word of the conversion result is the capacity of an owned `String` or the borrowed niche `0x8000000000000000`, so the signed `jle` skips the free for borrowed text. The tool's conversion stub follows `from_utf8_lossy`: valid UTF-8 is borrowed, and any invalid sequence produces an owned copy with U+FFFD replacements.
- The tagged form copies the 32-byte error built on the stack (`movups` x2) into the output before freeing.

**Variant pools** (`0x643e188`, `0x6475de0`, `0x64b7d28`). Each pool is three `(ptr, len)` slots, one pool per copy family, and each slot pointer is a `.rela.dyn` R_X86_64_RELATIVE addend read by the tool. The texts are `normal`, `noCross`, `strictIsolated` in tag order. Families 2 and 3 point into their own contiguous copy of the concatenated names (`0x7b9a6a`, `0x93a379`). Family 1 does not: its `normal` slot points at `0x5fe8ed`, while `noCross`/`strictIsolated` point at `0x5feb14`/`0x5feb1b` (the linker merged the family-1 strings with other text), so the producer reads each slot's own relocation instead of assuming one base.

**Shared callees.** The eleven bodies call the same three grow helpers, three result-form and three tagged-form unknown-variant callees, and the same two slots as the Tif codec copies of the same families; `callees.tsv` lists the role each one is bound to from the body shapes.

**Interpreter.**
- The interpreter is a fixed x86-64 subset decoder and machine contained in the tool itself, so the packet stands alone. It covers the general ALU forms, accumulator immediates, byte compares, `movzx` 8/16, rip-slot calls and the SSE2 forms used by the landing-pad copies (`movups`). ZF, CF, SF and OF are kept; `jle` uses `ZF or SF != OF`.
- Writes go only to scratch memory above the image. Reads below it come from file-backed sections.
- Calls go only to the bound callees, modelled as stubs that record their arguments. After a call, the interpreter overwrites the caller-saved registers, so the bodies cannot depend on their old values.

`paths.tsv` gives the path classes: each serializer has 8 (no grow, one grow or two grows per arm), each `&str` visitor 7 (three successes and errors after each gate or compare), and each `&[u8]` visitor 35 (its byte-by-byte compare exits at the first mismatching byte, split into `err` and `err+free`).

## Implementation and comparison

The reconstruction lives in `tools/re007_margin_mode_codec_115.py` as pure functions. There is no Rust implementation yet.

- `arm(tag)` returns `tag` for 0 and 1 and 2 for every other byte.
- `recon_serialize(tag, cap, len)` appends `0xa0 | len(name)` followed by `NAMES[arm(tag)]`. It reserves 1 when `cap == len`, then reserves `len(name)` when `cap - len < len(name)`, and returns `0x8000000000000004`.
- `recon_classify(text)` returns the index of `text` in `NAMES` only for an exact, full-length, case-sensitive match.
- `recon_visitor(kind, form, text)` gives `('ok', tag)` for the result form or `('ok', 0x09 | tag << 8)` for the tagged form. For a non-name, `&str` visitors report the text unchanged, and `&[u8]` visitors report `from_utf8_lossy(text)` and free the copy exactly when the input is not valid UTF-8.

Comparison inputs:
- **Serializer:** 3 copies × (3 tags × 4 starting lengths × 21 spare capacities + 253 other tag bytes × 2 capacity states) = 2,274 cases. Each case compares the appended bytes, the exact sequence of growth calls `(len, additional)`, the final length and the result word.
- **Visitors:** 1,580 distinct inputs × 8 copies = 12,640 cases. Each case compares status, value, the reported text and whether a copy was freed. The inputs are:
  - the empty string and every prefix of each name;
  - each name plus one byte, plus a doubled last byte, and plus a NUL; with the last byte replaced by `0xff`; with a two-byte UTF-8 sequence spliced in;
  - each name in lower and in upper case;
  - every single-byte substitution of every position with 55 values (`0x00`, `0x09`, `0x0a`, `0x80`, `0xc3`, `0xe2`, `0xff` and every second printable ASCII byte), plus the case flip of that byte;
  - cross-name half splices and concatenations;
  - `A` and `0x80` repeated 0..19 times.

  127 of the inputs are invalid UTF-8; 635 visitor cases (127 × 5 `&[u8]` copies) take the owned-copy free.

Result: 2,274/2,274 serializer cases and 12,640/12,640 visitor cases match.

Negative controls (`negative-controls.tsv`). Each count must be above 0, or the producer fails:

| Wrong reconstruction | Failing cases |
| --- | --- |
| serializer in alphabetical tag order | 504 / 2,274 |
| serializer without the second (name-length) reserve | 1,098 / 2,274 |
| serializer reserving when spare equals the name length | 45 / 2,274 |
| serializer using a str8 marker (`0xd9 len`) | 2,274 / 2,274 |
| serializer reducing out-of-range tags modulo 3 | 1,014 / 2,274 |
| visitor folding case | 240 / 12,640 |
| visitor checking only the first dword of each name | 6,640 / 12,640 |
| visitor checking only the first qword of `strictIsolated` | 2,640 / 12,640 |
| visitor selecting by the length gate alone | 12,072 / 12,640 |
| visitor accepting a name prefix | 120 / 12,640 |
| visitor reporting raw bytes without lossy conversion or free | 635 / 12,640 |
| visitor with `normal` and `noCross` swapped | 16 / 12,640 |

The unit test also mutates the target bytes and checks that each change is detected:
- the dispatch compare at `0x2924dd0` (`cmp $1` → `cmp $2`): tag 1 now writes `strictIsolated`;
- the `C` compare at `0x2868690`: `noCross` is now rejected by the `&[u8]` visitor;
- the `C` byte of the xor immediate at `0x286899f`: `noCross` is now rejected by the `&str` visitor;
- the reserve bound at `0x2924dfc`: the growth sequence changes;
- a `ud2` at a body entry: rejected as an unsupported instruction.

It also checks that each of these is rejected: an unmodelled call, an error call that loads a different pool, an out-of-scratch store, a read outside every section, and a wrong input digest.

## Results and limitations

- All 11 selected bodies are fully decoded: 1,091 instructions, with decoded bytes equal to FDE bytes.
- 2,274/2,274 serializer cases and 12,640/12,640 visitor cases match the reconstruction.
- 12/12 negative controls are caught.
- The callees are stubs, not reconstructions. The growth policy, the conversion internals, the free and the error value are outside the claim; only the callees' arguments, their call order and how the bodies use their results are compared. The conversion stub's lossy output is the Python `errors='replace'` UTF-8 decode, which follows the same maximal-subpart replacement rule as Rust; the comparison of reported text depends on that stub.
- No `&str` visitor in the Result form was found for this enum; the families have three, three and two visitors.
- The margin-mode reading of the three names and the serde/rmp roles are inferences. No caller was traced, and the nine larger pool-loading bodies are not interpreted.
- No progress gate is requested. This packet covers one enum codec, not the `risk` component.

Next question: what do the nine larger bodies that load the same pools (`0x1fa4630`/`0x3945390`/`0x567f110` at 1,002 bytes, `0x1fac540`/`0x394a4e0` at 873 bytes, and the 487/376-byte pairs) do with the name, and which asset or user-state struct serializers call the three serializer copies?
