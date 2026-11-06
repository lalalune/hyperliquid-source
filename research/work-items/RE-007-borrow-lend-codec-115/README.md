# RE-007: reconstruct the node #115 borrowLend wire codec: operation enum writers and visitors, and the deny-unknown field visitors

This packet makes the wire codec of node #115's `borrowLend` action rebuildable as executable code, including its failure paths. It covers both the four-name `operation` enum (`borrow`, `supply`, `repay`, `withdraw` = tags 0..3) and the struct's three field names (`operation`, `token`, `amount`). A risk, lending or action-wire reconstruction can now do three things:
- encode a stored operation tag byte to its exact msgpack bytes and capacity-reserve sequence;
- decode a wire name or field key exactly as the binary does;
- reproduce how an unknown operation name or an unknown field key is rejected.

The binary rejects an unknown field key with an error instead of ignoring it, so the struct is `deny_unknown_fields`-shaped.

The packet interprets the original machine code of 21 bodies byte by byte:
- **Three serializer copies** dispatch the tag byte through an unchecked 4-entry jump table and write one msgpack fixstr (`0xa6 borrow`, `0xa6 supply`, `0xa5 repay`, `0xa8 withdraw`) into a `Vec<u8>`, with two capacity checks per arm.
- **Ten operation-name visitors and eight field-name visitors** sit in three copy families. They accept only an exact, case-sensitive, full-length name, in two output forms: a one-byte Result (tag at +1) or a tagged word `0x09 | tag << 8`.
- **The `&[u8]` visitors** pass unknown input through a lossy UTF-8 conversion before reporting it. They free the converted copy only when the conversion had to allocate.

The reconstruction agrees on all 1,008 serializer cases and all 48,276 visitor cases, and each of the twelve deliberately wrong reconstructions is caught.

- Component ID: `risk` (task `RE-007`, risk/oracles/liquidation, `l1/clearinghouse/*` leads). The packet uses the RE-001 unwind index (`tools/fde_extents.py`) and the shared section parser (`tools/elf_index.py`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No inferred reference source was read or copied. #94 material is not used.
- Claim status:
  - **Observation:**
    - FDE extents and decoded instruction bytes;
    - the jump-table rows and the absence of any compare in the dispatch head;
    - immediates, length gates and RELATIVE relocations;
    - the interpreted results of the original bytes on the listed inputs.
  - **Inference:**
    - The serde/rmp roles: a `Serialize` that writes a unit variant name as a msgpack string, and identifier `visit_str`/`visit_bytes`.
    - That the four names are the `borrowLend` operation and the three fields its struct. This rests on the names alone: the action name `borrowLend` appears in the action-name tables of `RE-010-display-name-path-115`, and no caller links the bodies to that action yet.
    - That slot `0x64df640` is `String::from_utf8_lossy` and slot `0x64df4a0` frees its owned buffer.
    - That the two direct-callee groups build serde `unknown_variant` and `unknown_field` errors. By hand, with GNU objdump 2.42 and not in the evidence: `0x2cf1270` loads the format texts `unknown field \``…`, there are no fields` / `, expected`, and `0x2cf1360` loads `unknown variant \``…`.
  - **Unresolved:**
    - the callers: the borrowLend struct visitor and serializer, and the action dispatch;
    - the large bodies that also load the field pools (for example `0x2b817d0`, `0x36b6980`, `0x4d3f940`, 9–11 KB each), and the five 4.2–4.3 KB bodies that also contain `borr` immediates;
    - the internals of the grow, conversion, free and error callees;
    - what the binary does with an operation after decoding (the lending state change).
- Scope:
  - Included: 21 complete bodies. Every byte of each FDE extent is decoded, and only `int3` fill follows the last instruction.
    - Serializers: `0x269b7b0`, `0x3d4ebc0`, `0x57cc180`.
    - Operation visitors: `0x2690e20`, `0x2690fb0`, `0x2691150`, `0x2691210` (family 1); `0x3d43d70`, `0x3d43f10`, `0x3d440a0`, `0x3d44140` (family 2); `0x57c35c0`, `0x57c3760` (family 3).
    - Field visitors: `0x28691a0`, `0x28692f0`, `0x2869450` (family 1); `0x467f8d0`, `0x467fa30`, `0x467fba0` (family 2); `0x534be30`, `0x534bf90` (family 3).
    - Pools: operation pools `0x6437378`, `0x6479b90`, `0x64b0958` and field pools `0x643e1d8`, `0x6491608`, `0x64a62c8`.
  - Excluded: the callee bodies listed in `callees.tsv`, the large pool-loading bodies above, all callers, and any progress gate.
  - None of the 21 entries or six pools appears in any file under `research/work-items`, `tools` or `tests`, or in any open PR file list, at the time of writing.
  - Development scans, not part of the generated evidence:
    - The `.text` bytes `borr` occur in 13 FDEs: the three serializers, the five operation `&str` visitors, and five larger bodies that are not interpreted here (`0x2ba0a70`, `0x2ba1af0`, `0x36616b0`, `0x3662730`, `0x4d67530`, 4.2–4.3 KB each, listed as unresolved).
    - A rip-relative `lea` scan found the operation pools loaded only by the ten operation visitors.
    - It found the field pools loaded by the eight field visitors and by the large bodies listed as unresolved.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3. Only the standard library is needed, plus `tools/elf_index.py` and `tools/fde_extents.py`.

- The producer checks the full SHA-256 of the input before it parses anything.
- It never executes the capture, starts no process and makes no network access. It interprets the selected machine code in Python.
- Its output contains no time, randomness, absolute path or unordered-dict iteration.

```sh
python3 tools/re007_borrow_lend_codec_115.py --out research/work-items/RE-007-borrow-lend-codec-115
python3 -m unittest tests.test_re007_borrow_lend_codec_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Determinism check: two independent outputs with a different hash seed and time zone. The development check also ran both with a `PATH` that holds no binutils.

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/re007_borrow_lend_codec_115.py --out <tmp-dir-one>
PYTHONHASHSEED=977 TZ=Asia/Seoul python3 tools/re007_borrow_lend_codec_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes exactly the thirteen generated files below. `README.md` and `MANIFEST.sha256` are maintained separately. A full run takes about 20 s.

The producer exits non-zero and writes nothing if any of these holds:
- the digest differs;
- an entry is not an FDE start;
- any byte in a body falls outside the supported instruction subset;
- a call reaches an unmodelled target, a callee would have two roles, or a call's arguments differ from the expected ones;
- a visitor's call sequence is not `[lossy] unknown_<variant|field> [free]`;
- a visitor reports text other than the converted text, or frees a buffer other than the owned copy;
- a store leaves scratch memory;
- a serializer's dispatch head contains a compare or conditional branch before its indirect jump;
- a jump-table row is not an instruction start;
- a visitor loads a pool other than the three of its codec;
- a pool slot lacks a RELATIVE relocation or differs from the tag order;
- any case disagrees with the reconstruction;
- any negative control is not caught.

| Generated evidence | Contents |
| --- | --- |
| `functions.tsv` | 21 bodies: role, entry, FDE end, size, decoded instruction count and bytes (equal to the FDE size), LSDA, body SHA-256, direct and slot callees |
| `instructions.tsv` | 1,964 decoded instructions (VA, length, raw bytes, operation, branch/call target) |
| `callees.tsv` | 16 callees and the role each one is bound to from the body shapes |
| `serializer-jump-tables.tsv` | 12 rows: per serializer, table base, tag, row VA, signed rel32 read from the bytes, arm VA, name |
| `serializer-arms.tsv` | per serializer, every marker store, name-bytes store (imm and movabs), reserve bound, grow `additional` and result-word load, in body order |
| `visitor-literals.tsv` | per visitor, the length gates, per-byte compares, xor immediates, movabs words and result stores |
| `name-pool-refs.tsv` | per visitor: codec, family, input kind, output form, the rip-relative `lea` of its error arm and the pool it loads |
| `name-pools.tsv` | 21 rows: the six `&[&str; N]` pools, slot VA, `.rela.dyn` file offset of the RELATIVE relocation, string VA, length, text |
| `serializer-cases.tsv` | 1,008 cases: serializer × 4 tags × length {0,1,7,64} × spare capacity 0..20; appended bytes, grow calls (`length+additional`), final length, result word, arm, verdict |
| `visitor-cases.tsv` | 2,682 inputs × 18 visitors: outcome per copy (`ok:<value>`, `err`, `err:lossy`, `err:lossy:free`), the operation and field reconstructions, verdict |
| `paths.tsv` | per body, the number of inputs ending after each interpreted step count and outcome (path classes) |
| `negative-controls.tsv` | twelve wrong reconstructions and how many cases each fails |
| `summary.json` | totals, callee roles, pools, the three dispatch heads, and pass flags |

## Evidence

Coordinates are linked virtual addresses (VA). Section membership and file offsets come from `elf_index.sections`, with SHT_NOBITS sections excluded. Body extents come from `fde_extents.fde_extents`. The ten `&[u8]` visitors have an LSDA: their landing pads free the converted copy and call `_Unwind_Resume` `0x63f0a50`. The eleven other bodies have none.

### Serializers

`0x269b7b0`, `0x3d4ebc0` and `0x57cc180` are 690 bytes and 170 instructions each, and differ only in their grow callee and table base. Human-readable excerpt of `0x269b7b0` (GNU objdump 2.42, not used by the tool):

```
269b7b7: movzbl (%rsi),%ecx ; lea 0x5f2b60,%rsi ; movslq (%rsi,%rcx,4),%rcx ; add %rsi,%rcx ; jmp *%rcx
269b7ca: (borrow) mov (%rdx),%rcx ; mov 0x10(%rdx),%rsi ; cmp %rsi,%rcx ; je grow(len,1)
269b7de:       movb $0xa6,(%rdi,%rsi,1) ; inc %rsi ; mov %rsi,0x10(%rdx)
269b7e9:       sub %rsi,%rcx ; cmp $0x5,%rcx ; jbe grow(len,6)
269b7f6:       movw "ow",0x4(..) ; movl "borr",(..) ; add $0x6,%rsi
269b809: (repay) movb $0xa5 ; cmp $0x4,%rcx ; jbe grow(len,5) ; movb "y",0x4(..) ; movl "repa",(..)
269b847: (withdraw) movb $0xa8 ; cmp $0x7,%rcx ; jbe grow(len,8) ; movabs "withdraw" -> +0
269b887: (supply) movb $0xa6 ; cmp $0x5,%rcx ; jbe grow(len,6) ; movw "ly",0x4(..) ; movl "supp",(..)
269b8c5: mov %rsi,0x10(%rdx) ; movabs $0x8000000000000004,%rcx ; mov %rcx,(%rax) ; ret
```

- **Tag selection.**
  - `serializer-jump-tables.tsv` holds the four signed rel32 rows per copy, read from the bytes. The tables sit at `0x5f2b60`, `0x7bca28` and `0x935204`.
  - Tag 0 → `borrow`, 1 → `supply`, 2 → `repay`, 3 → `withdraw`. This is the same order as the pools and the visitor results. The arms are laid out in a different order in the body: borrow, repay, withdraw, supply.
  - `summary.json` records each dispatch head: `push push push mov movzx8 lea movsxd add jmpind`, with no compare and no conditional branch.
  - The tag byte therefore indexes the table unchecked, and the compiled writer is defined only for tags 0..3 (Rust's enum validity invariant). The tool drives exactly those four tags. Unlike the margin-mode `test`/`cmp` chain, an out-of-range byte here would jump through whatever follows the table, so a reconstruction must not accept other tag values.
- **Growth calls.**
  - Every growth call passes `(vec, len, additional, 1, 1)`.
  - Before the marker, `additional` is 1 when `cap == len`.
  - After the marker, it is the name length (6, 6, 5, 8) when the remaining capacity is `<= len(name) - 1`, that is, strictly less than the name length.
- **Name bytes.** `borrow` and `supply` are each written as a dword plus a word at +4, `repay` as a dword plus a byte at +4, and `withdraw` as one movabs qword.
- **Result.** Every path stores the word `0x8000000000000004` to `[rdi]` and returns `rdi`. No path returns an error.

### Operation `&str` visitors

Result form (`0x2691150`, `0x3d44140`; 178 bytes, 59 instructions) and tagged form (`0x2691210`, `0x3d440a0`, `0x57c3760`; 156 bytes, 47 instructions):

```
2691153: cmp $0x5,%rdx ; je len5 ; cmp $0x6,%rdx ; jne len8
269115f: (len6) mov "borr",%ecx ; xor (%rsi),%ecx ; movzwl 0x4(%rsi),%edi ; xor $0x776f ; or ; je borrow
2691174:        mov "supp",%ecx ; xor (%rsi),%ecx ; movzwl 0x4(%rsi),%edi ; xor $0x796c ; or ; jne error
2691189:        movb $0x1,0x1(%rax) ; xor %ecx,%ecx ; mov %cl,(%rax) ; ret         ; Ok(supply)
2691192: (len5) mov "repa",%ecx ; xor (%rsi),%ecx ; movzbl 0x4(%rsi),%edi ; xor $0x79 ; ...
```

- **Length gates.** Lengths 5, 6 and 8 are the only ones that reach a compare. Length 6 is shared by `borrow` and `supply`, so it is followed by two compares. Any other length goes to the error arm.
- **Whole-word compares.** Each name is covered by xor words over every byte. The `first4_only`, `first_byte_only` and `length_only` negative controls show what dropping the trailing word, all but the first byte, or every compare would accept.
- **Outputs.**
  - The result form writes byte 0 = 0 (Ok) and byte 1 = tag. On error it writes byte 0 = 1 and the error pointer at +8.
  - The tagged form writes `0x09 | tag << 8`, or lets the error callee fill the 32-byte output with `(out, ptr, len, pool, 4)`.

### Field `&str` visitors

`0x2869450`, `0x467fba0` and `0x534bf90` are 137 bytes and 41 instructions each, tagged form only:

```
2869450: cmp $0x5,%rdx ; je len5 ; cmp $0x9,%rdx ; jne len6
286945c: (len9) movabs "operatio" ; xor (%rsi),%rax ; movzbl 0x8(%rsi),%ecx ; xor $0x6e ; or ; jne error ; movw $0x9,(%rdi)
286947f: (len5) mov "toke",%eax ; xor (%rsi),%eax ; movzbl 0x4(%rsi),%ecx ; xor $0x6e ; or ; jne error ; movw $0x109,(%rdi)
286949a: (len6) cmp $0x6,%rdx ; jne error ; ... "amou" + "nt" ... movw $0x209,(%rdi)
```

Every non-matching key reaches the error arm. That arm calls the unknown-field callee with `(out, ptr, len, field pool, 3)`; it never writes an "ignored field" index (`0x09 | 3 << 8`). This is the observation behind the `deny_unknown_fields` inference. The `unknown_field_ignored` negative control, which models serde's default of ignoring unknown keys, fails 21,432 cases.

### `&[u8]` visitors

- **Operation:** result form `0x2690e20`, `0x3d43f10` (399 bytes, 114 instructions) and tagged form `0x2690fb0`, `0x3d43d70`, `0x57c35c0` (413 bytes, 116 instructions).
- **Field:** result form `0x28691a0`, `0x467fa30` (330 bytes, 98 instructions) and tagged form `0x28692f0`, `0x467f8d0`, `0x534be30` (344 bytes, 100 instructions).

These use the same length gates and then compare byte by byte (`cmpb $imm,k(%rsi)`). On any mismatch they:
- call slot `0x64df640` to build a `Cow<str>` on the stack;
- call the codec's unknown callee with the converted pointer and length, its pool and its name count;
- store the error;
- free the owned copy through slot `0x64df4a0` only when the first word of the `Cow` is a positive capacity. The borrowed niche is `0x8000000000000000`, so the signed `jle` skips the free.

The tool's conversion stub follows `from_utf8_lossy`: valid UTF-8 is borrowed, and any invalid sequence produces an owned copy with U+FFFD replacements.

### Name pools

Each pool is N `(ptr, len)` slots, one pool per copy family and codec. Each slot pointer is a `.rela.dyn` R_X86_64_RELATIVE addend read by the tool.
- The texts are `borrow`, `supply`, `repay`, `withdraw` and `operation`, `token`, `amount`, in tag order.
- All three operation pools point their `withdraw` slot at the same merged string `0x4591a0`, while the other three slots point into each family's own copy (`0x5f3fa5`, `0x7bd334`, `0x935f3b`).
- The field pools point at `0x5feb8e`/`0x5fe6ab`, `0x7d9eef`/`0x7d9ef8` and `0x924632`/`0x92455e`, so `operation` is not contiguous with `token`/`amount` in families 1 and 3.

The producer therefore reads each slot's own relocation instead of assuming one base.

### Shared callees

- The three serializers call the same three grow helpers (`0x231e050`, `0x43bd910`, `0x5963a10`) as the Tif and margin-mode serializer copies of the same families.
- The operation visitors call three result-form and three tagged-form unknown-variant callees.
- The field visitors call two result-form and three tagged-form unknown-field callees, at different addresses (`callees.tsv`).
- The tool binds each role from the body shapes and the codec of the calling visitor. It rejects any callee that would get two roles.

### Interpreter

- The interpreter is a fixed x86-64 subset decoder and machine contained in the tool itself, so the packet stands alone. It covers:
  - the general ALU forms, accumulator immediates, byte compares and `movzx` 8/16;
  - `movsxd` and the indirect `jmp` of the jump tables;
  - rip-slot calls and the SSE2 forms used by the landing-pad copies (`movups`).
- ZF, CF, SF and OF are kept; `jle` uses `ZF or SF != OF`.
- Writes go only to scratch memory above the image. Reads below it come from file-backed sections, which is how the jump-table rows are fetched.
- Calls go only to the bound callees, modelled as stubs that record their arguments. After a call, the interpreter overwrites the caller-saved registers, so the bodies cannot depend on their old values.

`paths.tsv` gives the path classes:
- each serializer has 5;
- each operation `&str` visitor has 8;
- each field `&str` visitor has 7;
- each operation `&[u8]` visitor has 36;
- each field `&[u8]` visitor has 23.

The `&[u8]` path classes are the exits of the byte-by-byte compare at the first mismatching byte, split into `err` and `err+free`.

## Implementation and comparison

The reconstruction lives in `tools/re007_borrow_lend_codec_115.py` as pure functions. There is no Rust implementation yet.

- `recon_serialize(tag, cap, len)`, for `tag` in 0..3:
  - appends `0xa0 | len(name)` followed by `NAMES[tag]`;
  - reserves 1 when `cap == len`, then reserves `len(name)` when `cap - len < len(name)`;
  - returns `0x8000000000000004`.
- `recon_classify(text, names)` returns the index of `text` in `names` only for an exact, full-length, case-sensitive match.
- `recon_visitor(kind, form, text, names=...)`:
  - on a match, gives `('ok', tag)` for the result form or `('ok', 0x09 | tag << 8)` for the tagged form;
  - for a non-name, `&str` visitors report the text unchanged;
  - `&[u8]` visitors report `from_utf8_lossy(text)` and free the copy exactly when the input is not valid UTF-8;
  - the same function serves the operation names and the field names; the field codec has no ignored-field outcome.
- `dispatch_head(rows, va)` is the byte-level rule that the serializer dispatch is an unchecked table jump.

Comparison inputs:
- **Serializer:** 3 copies × 4 tags × 4 starting lengths × 21 spare capacities = 1,008 cases. Each case compares the appended bytes, the exact sequence of growth calls `(len, additional)`, the final length and the result word.
- **Visitors:** 2,682 distinct inputs × 18 copies = 48,276 cases. Each case compares status, value, the reported text and whether a copy was freed.
  - Every input goes to every visitor, so each operation name is also a negative case for the field visitors, and the reverse.
  - The inputs are built from all seven names:
    - the empty string and every prefix of each name;
    - each name plus one byte, plus a doubled last byte, and plus a NUL;
    - each name with the last byte replaced by `0xff`, or with a two-byte UTF-8 sequence spliced in;
    - each name in lower and in upper case;
    - every single-byte substitution of every position with 55 values (`0x00`, `0x09`, `0x0a`, `0x80`, `0xc3`, `0xe2`, `0xff` and every second printable ASCII byte), plus the case flip of that byte;
    - cross-name half splices and concatenations over all 42 ordered name pairs;
    - `A` and `0x80` repeated 0..19 times.
  - 199 of the inputs are invalid UTF-8. That gives 1,990 visitor cases (199 × 10 `&[u8]` copies) that take the owned-copy free.

Result: 1,008/1,008 serializer cases and 48,276/48,276 visitor cases match.

Negative controls (`negative-controls.tsv`). Each count must be above 0, or the producer fails:

| Wrong reconstruction | Failing cases |
| --- | --- |
| serializer in alphabetical tag order (borrow, repay, supply, withdraw) | 504 / 1,008 |
| serializer without the second (name-length) reserve | 309 / 1,008 |
| serializer reserving when spare equals the name length | 60 / 1,008 |
| serializer using a str8 marker (`0xd9 len`) | 1,008 / 1,008 |
| visitor folding case | 474 / 48,276 |
| visitor checking only the first dword of each name | 8,494 / 48,276 |
| visitor checking only the length and first byte | 19,340 / 48,276 |
| visitor selecting by the length gate alone (`borrow`/`supply` share length 6) | 37,232 / 48,276 |
| visitor accepting a name prefix | 576 / 48,276 |
| visitor reporting raw bytes without lossy conversion or free | 1,990 / 48,276 |
| visitor with the first two names swapped (`borrow`/`supply`, `operation`/`token`) | 36 / 48,276 |
| field visitor ignoring an unknown key (serde default) instead of erroring | 21,432 / 48,276 |

The unit test (24 tests) also mutates the target bytes and checks that each change is detected:
- jump-table row 0 of `0x269b7b0` replaced by row 2: tag 0 now writes `0xa5 repay`;
- the table load at the dispatch head turned into a `cmp`: `dispatch_head` rejects it;
- the `b` of the `borr` immediate at `0x2691160` → `B`: `borrow` is now rejected and `Borrow` accepted;
- the `o` of the `operatio` movabs at `0x286945e` → `O`: `operation` is now rejected by the field visitor;
- the reserve bound at `0x269b7ec` (`cmp $5` → `cmp $4`): the growth sequence changes;
- a `ud2` at a body entry: rejected as an unsupported instruction.

It also checks that each of these is rejected: an unmodelled call, an error call that loads a different pool (operation and field), an out-of-scratch store, a read outside every section, and a wrong input digest.

## Results and limitations

- All 21 selected bodies are fully decoded: 1,964 instructions, with decoded bytes equal to FDE bytes.
- 1,008/1,008 serializer cases and 48,276/48,276 visitor cases match the reconstruction.
- 12/12 negative controls are caught.
- The callees are stubs, not reconstructions:
  - The growth policy, the conversion internals, the free and the error value are outside the claim. Only the callees' arguments, their call order and how the bodies use their results are compared.
  - The conversion stub's lossy output is the Python `errors='replace'` UTF-8 decode, which follows the same maximal-subpart replacement rule as Rust. The comparison of reported text depends on that stub.
- Missing copies: family 3 has no Result-form visitor for either codec, and the field codec has no `&str` Result-form visitor in any family.
- The borrowLend reading of the names and the serde/rmp roles are inferences. No caller was traced. The struct-level visitor and serializer (which would sequence the three fields and call these bodies) are not interpreted.
- No progress gate is requested. This packet covers the leaf codec of one action, not the `risk` component.

Next question: which bodies sequence the three fields? That means the large field-pool loaders (`0x2b817d0` and its copies) and the callers of the three serializers. And how does a decoded operation change the user's lending/borrow state?
