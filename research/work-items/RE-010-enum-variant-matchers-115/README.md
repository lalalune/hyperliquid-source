# RE-010: reconstruct three serde variant matchers (visit_str + visit_bytes) behind the sibling identifier decoders

This packet reconstructs, as one executable pure function checked against the original bytes, the
`visit_str` and `visit_bytes` variant matchers that three sibling copies of the node #115 MessagePack
identifier decoder call. A reconstruction can now decode three more serde enums name-for-name: a
17-name perp-deploy action enum (`registerAsset` .. `hip3Star`) that has only **16 variants**, because
`setFeeScale` is a serde alias of `setDeployerFees` (both decode to variant 9, so the later names
shift down by one); a 114-variant short-code enum (`a` .. `ttt`); and an 18-variant short-tag enum
(`e`, `r`, `b`, `btp`, `P`, `Ps`, ...).

- Component ID: `action-dispatch` (task RE-010)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: lalalune/hyperliquid-source main `05bc2de303c05525b71e7e257426e741bc66a390`;
  no reference source was used
- Claim status: observation (byte-level outcomes of the six matchers on every listed input, the
  decoder bindings, the VARIANTS slices and the success-store immediates), inference (that these are
  serde-derived `__FieldVisitor` methods and that position 10 is an alias), unresolved (the Rust
  type names of the three enums and which of the two alias names is the serialized one)
- Scope included and excluded: included are the six matchers 0x2ba4e30 / 0x2ba5c90 (PERP),
  0x287dcb0 / 0x287ec80 (SHORT114) and 0x286cc60 / 0x286cef0 (TAG18), their whole FDE extents
  (2,269 instructions), their VARIANTS slices, the visit_bytes landing pads, and the call offsets that
  bind them to the decoder copies 0x195c140, 0x1bfca70 and 0x1c2d2c0. Excluded are the bodies of the
  three decoder copies, the number dispatchers they reach through GOT slots, the callers of the
  decoders, serde's `unknown_variant` (0x17fbba0), `String::from_utf8_lossy` and the allocator free,
  which are contract stubs whose arguments are checked. The fourth 1769-byte sibling 0x14b3080 (its
  79-name VARIANTS slice 0x63f8788 is RE-015 config-name territory) is not decoded. No progress gate
  is requested.

## Reproduce

From the repository root (Python 3 standard library only, no binutils, the binary is never run):

```
python3 tools/re010_enum_variant_matchers_115.py --out research/work-items/RE-010-enum-variant-matchers-115
python3 -m unittest tests.test_re010_enum_variant_matchers_115
```

The tool checks the input SHA-256 first and fails on any other input. It reads `.rela.dyn`,
`.rela.plt`, `.dynsym`/`.dynstr`, `.eh_frame` (through `tools/fde_extents.py`), the LSDA call-site
tables and the matcher bytes with `struct`, and rewrites all eleven generated files. It takes about
18 s. Two regenerations into different folders with `PYTHONHASHSEED=12345`, `TZ=Asia/Seoul` and an
empty `PATH` were byte-identical (`diff -r` empty). The unit test regenerates the folder into a
temporary directory and compares every file byte for byte.

## Evidence

Coordinates are virtual addresses in the #115 image. File offsets are derived from the section
headers; NOBITS sections are never read.

### Decoder copy to matcher binding (`decoder-bindings.tsv`)

The `Action` identifier decoder 0x1af3b70 (1769 bytes by FDE) calls its `visit_bytes` matcher
0x2b9cdb0 at offsets +1057 and +1195 and its `visit_str` matcher 0x2ba1af0 at +1238 (`e8 rel32`).
The three sibling decoders have the same FDE size and the same call offsets:

| enum label | decoder | visit_bytes (+1057, +1195) | visit_str (+1238) | VARIANTS slice | names | variants |
| --- | --- | --- | --- | --- | --- | --- |
| PERP | 0x195c140 | 0x2ba4e30 (2,816 B) | 0x2ba5c90 (836 B) | 0x644d330 | 17 | 16 |
| SHORT114 | 0x1bfca70 | 0x287dcb0 (1,937 B) | 0x287ec80 (1,761 B) | 0x643f1a8 | 114 | 114 |
| TAG18 | 0x1c2d2c0 | 0x286cc60 (656 B) | 0x286cef0 (452 B) | 0x643e4a8 | 18 | 18 |

The labels are this packet's names, not Rust identifiers.

### VARIANTS slices

Each matcher contains exactly one `lea rcx,[rip+slice]` followed within three instructions by
`mov r8d,count`, the `(expected, len)` pair passed to `unknown_variant` 0x17fbba0. Both matchers of
an enum name the same slice and count. Every 16-byte slot carries an `R_X86_64_RELATIVE` relocation
to the name bytes, and the second word is the length. The names are in `summary.json` and
`names.tsv`.

- PERP: `registerAsset setOracle insertMarginTable setFeeRecipient haltTrading setMarginTableIds
  setOpenInterestCaps setFundingMultipliers setMarginModes setDeployerFees setFeeScale
  setFundingInterestRates disableDex setPerpAnnotation migrateDexQuoteToken setFundingClamps
  hip3Star`
- SHORT114: the 1-letter names `a`..`z` without `i`, then `A`..`Z` without `U` and `V`, then
  doubled pairs and triples up to `ttt` (49 one-byte, 47 two-byte, 18 three-byte names).
- TAG18: `e r b btp P Ps mu f t dp du pmv pma pmu rl mbs adl ri`

### Success stores (`names.tsv`)

Every accepted name ends in exactly one `movw $imm16,(%rdi)` with `imm16 = (variant << 8) | 0x09`.
The tag byte 9 is the `Ok` niche of the 32-byte result also used by the `Action` form-B matchers.
For PERP, `setDeployerFees` and `setFeeScale` both store `0x0909`. In visit_bytes they share one
store site (0x2ba5840); in visit_str they reach two different sites (0x2ba5d6e and 0x2ba5e56) with
the same immediate. Every later name stores its position minus one (`hip3Star` -> `0x0f09`). The
other two enums store their position.

### Dispatch shape (`jump-tables.tsv`, `insns.tsv`)

The matchers do not share a code shape. The tool finds every
`lea reg,[rip+T]; movsxd; add; jmp reg` table and checks that each entry is an instruction start:

- PERP visit_str: a 16-entry length switch (`lea rax,[rdx-8]; cmp rax,15; ja`) for lengths 8..23.
  Names of 16 bytes or more are compared through SSE (`movdqu`, `pcmpeqb` against rodata, `pand`,
  `pmovmskb == 0xffff`); shorter names through immediate compares.
- SHORT114 visit_str: a 58-entry first-byte switch. visit_bytes has two 58-entry tables plus a
  20-entry table.
- TAG18 visit_str: tests the length (1, 2, 3), then uses a 37-entry first-byte table for one-byte
  names, `cmpw` chains for two-byte names, and `movzwl/xor/movzbl/xor/or` pairs for three-byte names.

Human-readable excerpt (objdump, not used by the tool), TAG18 visit_str 0x286cef0:

```
286cef0: cmp    $0x3,%rdx
286cef4: je     286cf7d
286cefa: cmp    $0x2,%rdx
286cefe: je     286cf32
286cf00: cmp    $0x1,%rdx
286cf04: jne    286d012          ; unknown_variant tail
286cf0a: movzbl (%rsi),%eax
286cf0d: add    $0xffffffb0,%eax  ; first byte - 'P'
286cf10: cmp    $0x24,%eax
286cf19: lea    -0x22742a0(%rip),%rcx   ; table 0x5f8c80
286cf74: movw   $0x1109,(%rdi)   ; `ri` -> variant 17
```

### Error tails and landing pads (`lsda-call-sites.tsv`, `unwind-cases.tsv`)

The visit_str matchers have no LSDA and call only `unknown_variant(out=rdi, value=(rsi,rdx),
expected=(rcx,r8))`. Each visit_bytes matcher has an LSDA with 3 uleb128 call sites:

1. `String::from_utf8_lossy` through GOT slot 0x64df640 (RELATIVE -> 0x141ca00);
2. `unknown_variant` with a landing pad;
3. the free of an owned Cow through GOT slot 0x64df4a0 (RELATIVE -> 0x635de30) when the capacity
   word is positive (`test rsi,rsi; jle`), followed by `_Unwind_Resume` (the PLT stub 0x63f0a50,
   checked through its `.rela.plt` JUMP_SLOT symbol).

The landing pad frees the owned string iff the input was invalid UTF-8, then resumes.

## Implementation and comparison

The reconstruction is `variant_table` + `reconstructed_match` in the tool (pure Python, about 40
lines), rendered as Rust-like pseudocode in `matchers.rs.txt`:

```
match value {                       // exact, case-sensitive, whole slice
    b"<VARIANTS[p]>" => Ok(variant(p)),   // variant(p) = p - #alias positions <= p
    _ => Err(unknown_variant(&String::from_utf8_lossy(value), &VARIANTS)) // Owned dropped
}
```

The alias set is a literal (`ALIAS_POSITIONS = {PERP: {10}}`). The bytes check it through the
success-store immediates and through every case.

The original bytes are run by a fixed-pattern x86-64 subset interpreter in the tool (about 450
lines). It handles the integer subset these matchers use, including accumulator-immediate forms,
`setcc` and byte compares, plus the SSE compare group (`movdqu`, `movd`, `pcmpeqb`, `pand`,
`pmovmskb`). The interpreter
models the input, output, heap and stack as bounded buffers. Any read past the input, any store
outside writable buffers, any unknown opcode and any unbalanced `ret` is a fault, not a result.
`unknown_variant`, `from_utf8_lossy` and free are stubs that check their arguments: VARIANTS pointer
and count, the lossy text, and the owned-pointer/capacity pair. They write a 32-byte marker error,
or in unwind mode transfer to the landing pad that the LSDA call-site table names.

Inputs (`cases.tsv`, built from the bytes): every name; each byte +1 / -1 / case-flipped; drop
first / last byte; `+s`, `+NUL`, doubled; high last byte; invalid, two-byte and truncated UTF-8
tails; all 256 one-byte strings; for the short-name enums, letter pairs (`xx`, `xX`, `xy+1`) and
the third-letter sweep of every 3-byte name; `a`*0..32 and `\xff`*0..32. The visit_str matchers run
the valid-UTF-8 subset.

| function | cases | mismatches | instructions executed | unwind cases (mismatches) |
| --- | --- | --- | --- | --- |
| PERP visit_bytes 0x2ba4e30 | 1,256 | 0 | 631 / 631 | 82 (0) |
| PERP visit_str 0x2ba5c90 | 1,046 | 0 | 181 / 181 | - |
| SHORT114 visit_bytes 0x287dcb0 | 2,153 | 0 | 679 / 679 | 212 (0) |
| SHORT114 visit_str 0x287ec80 | 1,749 | 0 | 460 / 460 | - |
| TAG18 visit_bytes 0x286cc60 | 862 | 0 | 194 / 194 | 64 (0) |
| TAG18 visit_str 0x286cef0 | 664 | 0 | 124 / 124 | - |

The six functions total 7,730 normal runs and 358 unwind runs. On every valid-UTF-8 input,
visit_str and visit_bytes give the same result (`str_bytes_agree_on_utf8_cases` equals
`utf8_cases` for all three enums).

Negative controls:

- Model mutants (`mutants.tsv`): 88 / 88 rejected. These are 16 general mutants per entry point;
  bytes-only lossy/free mutants run only on visit_bytes; `no_alias_positional_index` and
  `alias_rejected` run only on PERP. Among them: case-insensitive, prefix, sorted order, swapped
  indices, ignore last byte, first byte only, accept trailing NUL, strip whitespace, strict-UTF-8
  text, never / always free, lossy-then-match and ASCII fold.
- Image mutants (`summary.json` `image_mutants`): 54 / 54 single-bit flips rejected. Each is the
  immediate low byte of a sampled `cmp`/`xor` or the variant byte of a sampled success store, in all
  six functions. A first version that flipped the last immediate byte had one survivor: the high
  byte of `xor $0x6d70,%eax` at 0x286cf98, an equivalent mutant because only `%ax` is consumed.
  That is why the low byte is flipped.
- Unit tests: wrong digest, unmapped read, non-FDE start and a non-call byte at a binding offset
  are rejected. A wrong alias literal disagrees with the bytes. A one-bit store corruption turns
  `ri` -> 17 into 16.

No Rust implementation is built in this packet: not yet implemented.

## Results and limitations

- 6 / 6 matchers reconstructed with 0 mismatches over 7,730 + 358 runs and 2,269 / 2,269
  instructions executed. 88 / 88 model and 54 / 54 image mutants were rejected. 12 unit tests.
- The PERP enum has 16 variants and 17 accepted names. `setDeployerFees` and `setFeeScale` are one
  variant. Which name is the canonical serialize name, and whether the alias is the older wire name,
  is not decided here, because the serializer side was not read.
- The Rust type names of the three enums are not established. "PERP", "SHORT114" and "TAG18" are
  labels. The PERP names match perp-deploy actions, but the enclosing action variant and its
  handler are outside this packet.
- The interpreter runs a subset; outcomes outside the listed inputs are inferred from full coverage
  and the compare structure, not executed.
- The callers of the three decoder copies, and the number dispatchers they reach through GOT
  slots, are not decoded here.

Next question: which serializer emits the PERP names? Its rodata use of `setDeployerFees` versus
`setFeeScale` would settle the canonical name. Which callers reach decoders 0x1bfca70 and 0x1c2d2c0,
so that SHORT114 and TAG18 can be tied to their Rust structs?
