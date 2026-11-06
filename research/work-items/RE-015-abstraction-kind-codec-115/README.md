# RE-015: reconstruct the node #115 seven-name abstraction-kind name decoder

With this packet the string-to-variant decoder of one seven-variant
unit enum can be rebuilt. Its variants are `Perp`, `Spot`, `Token`, `Pdi`,
`ActivateDexAbstraction`, `ActivateUnifiedAccount` and `AllBoleTokens`, in
declaration order. A reimplementation can now:

- decide the exact accepted byte strings and their tags (0..6);
- decide the length dispatch, lengths 3..22 through a 20-arm table with every other length rejected;
- decide the two Rust return shapes;
- decide which `&[&str; 7]` pool entry is passed to the unknown-variant error.

All of this is proven by running the original bytes of five monomorphised
copies in a fixed-subset interpreter against an independent pure-Python
classifier. There are 37,640 cases and 0 mismatches, and all 6 deliberately wrong
reconstructions are caught.

- Component ID: `constants` (task RE-015, global literal / pool-entry / discriminant inventory)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`; no reference source used
- Claim status: observation for the generated tables (bytes, relocations, interpreter results); inference for the Rust-level reading (serde `visit_str` of a unit enum); unresolved for the enum's Rust type name and its serializer
- Scope included: the 5 visitor bodies `0x23c65f0`, `0x3bdd720`, `0x4d6b5d0` (tagged-word form) and `0x23c6720`, `0x3bdd5e0` (`Result<u8, E>` form), and their 5 length jump tables (20 rel32 entries each). Also included are the 12 compare literals per body (imm16/imm32/imm64 and four rip-relative 16-byte SSE constants) and the 3 variant-name pool entries `0x642f400`, `0x6476120`, `0x649c2f8` (7 slots each, `R_X86_64_RELATIVE`).
- Scope excluded: the 5 unknown-variant error callees (`0x17fbba0`, `0x2cf1360`, `0x2f7fef0`, `0x45a8fe0`, `0x47d2d80`), which are modelled as opaque stubs whose arguments are checked. Also excluded are the callers that embed this enum, its serializer, and any #94 coordinates. No component gate is requested.

## Reproduce

From the repository root, with `artifacts/node/115/hl-node` present (the
producer checks the SHA-256 first and refuses any other input):

```
python3 tools/re015_abstraction_kind_codec_115.py --out research/work-items/RE-015-abstraction-kind-codec-115
python3 -m unittest tests.test_re015_abstraction_kind_codec_115
sha256sum -c research/work-items/RE-015-abstraction-kind-codec-115/MANIFEST.sha256
```

- The producer uses only the Python standard library plus `tools/elf_index.py` (section headers) and `tools/fde_extents.py` (FDE extents).
- It never executes the capture and starts no external program.
- One run takes about 35 s.
- Two runs with `PYTHONHASHSEED=7 TZ=Asia/Seoul` and `PYTHONHASHSEED=0 TZ=UTC` produced byte-identical folders (`diff -r` empty).

Generated files (all rewritten by the command above):

| file | rows | content |
|---|---:|---|
| `functions.tsv` | 5 | FDE extent, decoded instruction count, body SHA-256, callee per body |
| `instructions.tsv` | 400 | every decoded instruction (VA, length, bytes, op, branch target) |
| `length-dispatch.tsv` | 5 | bound `ja`, reject arm, min/max length, jump-table and pool `lea` sites |
| `jump-table.tsv` | 100 | per body, 20 rel32 entries → arm, `compare`/`reject`, names of that length |
| `variant-pool.tsv` | 21 | 3 pools × 7 slots: slot VA, `.rela.dyn` file offset, text VA, length, text |
| `compare-literals.tsv` | 60 | every name fragment compared by the bodies, with its form |
| `visitor-cases.tsv` | 7,528 | per input, the outcome of all 5 bodies + reconstruction + verdict |
| `paths.tsv` | 50 | per body, interpreter step count × outcome histogram |
| `negative-controls.tsv` | 6 | wrong reconstruction → mismatching cases / cases |
| `summary.json` | 1 | totals and pass flags |

## Evidence

Coordinates are virtual addresses, except that `.rela.dyn` positions are
file offsets. `.text` file offset = VA − 0x1000. Low read-only constants
(`0x450870`..`0x5ed589`) have VA = file offset.

- **Boundaries.**
  - Each body is an exact FDE start from `.eh_frame`.
  - Linear decoding covers the full FDE: 294 bytes for each tagged copy and 319 bytes for each Result copy.
  - Nothing is undecoded and there is no LSDA.
  - The three tagged copies are byte-for-byte the same shape and differ only in rel32 displacements. Their body hashes are in `functions.tsv`.
- **Length gate.** `lea rax,[rdx-0x3]; cmp rax,0x13; ja reject`. A length below 3 wraps and is rejected, and a length above 22 is rejected. Lengths 3..22 index a 20-entry rel32 table (`0x5ec280`, `0x7b3184`, `0x914414` for the tagged copies; `0x5ec2d0`, `0x7b3134` for the Result copies). Only lengths 3, 4, 5, 13 and 22 reach a compare arm. The other 15 table entries point at the reject arm, and the producer fails if a table arm ever disagrees with the set of name lengths.
- **Compare arms.** Excerpt from the tagged copy `0x23c65f0`; the literals are regenerated byte-exactly in `compare-literals.tsv`.
  - len 3: `movzx eax,word [rsi]; xor eax,0x6450; movzx ecx,byte [rsi+2]; xor ecx,0x69; or cx,ax` → `Pdi` → tag 3
  - len 4: `cmp dword [rsi],'Perp'` → tag 0, then `cmp dword [rsi],'Spot'` → tag 1
  - len 5: `'Toke'` dword + `'n'` byte → tag 2
  - len 13: two overlapping qwords, `'AllBoleT'` at +0 and `'leTokens'` at +5 → tag 6
  - len 22: two overlapping 16-byte SSE2 windows at +0 and +6 (`movdqu; pcmpeqb; pand; pmovmskb; cmp 0xffff`) against `ActivateDexAbstr`/`teDexAbstraction` → tag 4, else `ActivateUnifiedA`/`teUnifiedAccount` → tag 5
- **Return shapes.**
  - Tagged copies store the word `0x09 | tag << 8` to `[rdi]`; byte 0x09 is the enclosing result's "value" discriminant.
  - Result copies store `byte [rax+1] = tag; byte [rax] = 0`.
  - On reject, the tagged copies call the error callee with `(rdi=out, rsi=ptr, rdx=len, rcx=pool, r8=7)` and return.
  - The Result copies call `(rdi=ptr, rsi=len, rdx=pool, rcx=7)`, then store the returned error pointer at `[out+8]` and `byte [out]=1`.
  - The interpreter checks these arguments on every rejecting case.
- **Pool entries.** Each `lea` of the error path points at a 7 × 16-byte `&str` array.
  - Every slot pointer is produced by an `R_X86_64_RELATIVE` relocation, read from `.rela.dyn` by the producer, and every length is the following qword.
  - The texts of all three pools are identical and in tag order, and the producer fails otherwise.
  - The copy families pair as (`0x23c65f0`, `0x23c6720`) → `0x642f400`, (`0x3bdd720`, `0x3bdd5e0`) → `0x6476120`, and `0x4d6b5d0` → `0x649c2f8`.
- **Discovery.**
  - I scanned `.text` for `81 /7` compares whose imm32 is four ASCII letters and grouped the hits by FDE. The `Perp`/`Spot` pair appeared in exactly these five bodies.
  - There were 0 hits for the addresses or pools in `research/work-items` and none in the open-PR file lists checked at run time.
  - The RE-010 display-name packet lists the different names `agentEnableDexAbstraction`/`userDexAbstraction`, not this enum.

## Implementation and comparison

- **Reconstruction** (`recon_classify` in the tool) is an exact byte-string equality against `NAMES`, with the tag equal to the index. The two body shapes wrap it as `('ok', 0x09 | tag << 8)` or `('ok', tag)`, and anything else is `('err', None)`. A Rust form is:

  ```rust
  enum AbstractionKind { Perp, Spot, Token, Pdi, ActivateDexAbstraction, ActivateUnifiedAccount, AllBoleTokens }
  // visit_str: match v { "Perp" => Ok(Perp), ..., _ => Err(E::unknown_variant(v, VARIANTS)) }
  ```

  The Rust type name is not recovered, and `AbstractionKind` is a placeholder.
- **Interpreter.** The original bytes run in a decoder and machine for a fixed x86-64 subset:
  - MOV/LEA/ALU/compare forms, `movzx` 8 and 16, `movsxd`, near and indirect jumps, push/pop/call/ret;
  - SSE2 `movdqu`, `pcmpeqb`, `pand` and `pmovmskb`.

  Any other opcode, any store outside scratch memory, a read of an unset scratch byte, a call to an unmodelled target or an unbalanced stack raises `Reject`. Inputs are padded with zero bytes to 48 so that the `+6` 16-byte window is defined; zero is not a byte of any name.
- **Cases.** There are 7,528 distinct inputs × 5 bodies = 37,640 runs:
  - each name, every prefix, name + `x`, name + last byte, lower and upper case;
  - every single-position replacement by 99 bytes (printable ASCII, NUL, tab, LF, DEL, 0x80, 0xc0, 0xff);
  - half/half and four-byte/sixteen-byte cross splices of name pairs;
  - `A` × 0..24.
- **Negative controls.** Each wrong reconstruction must disagree with the interpreted original on at least one case:

  | wrong reconstruction | mismatches / cases |
  |---|---:|
  | prefix match instead of equality | 70 / 37,640 |
  | ASCII case folding | 415 / 37,640 |
  | tags 4 and 5 swapped | 10 / 37,640 |
  | 22-byte names checked on the first 16 bytes only | 6,070 / 37,640 |
  | `AllBoleTokens` checked on its first 12 bytes only | 505 / 37,640 |
  | tags by length order instead of declaration order | 35 / 37,640 |

- **Byte-corruption controls** (unittest): changing `'P'` of the `'Perp'` immediate, the last byte of the `teDexAbstraction` constant, swapping two jump-table entries, lowering the `cmp rax,0x13` bound, or inserting `ud2` each changes the interpreted outcome or raises `Reject`. A wrong pool argument and a corrupted digest are rejected.
- No Rust build is included, so the Rust path is not yet implemented. The reconstruction above is the executable Python model.

## Results and limitations

- `summary.json`: `visitor_matches` 37,640 / `visitor_cases` 37,640, `accepted_inputs` 7 / 7,528, `all_negative_controls_caught` true, and `decoded_instructions` 400 over 5 bodies, with 0 undecoded bytes.
- `tests/test_re015_abstraction_kind_codec_115.py`: 19 tests, 0 skips.
- The error callees are stubs. Their message formatting and allocation are not reconstructed, and only their argument registers are checked.
- The interpreter models ZF/CF only, and that is sufficient for every branch in these bodies (`je/jne/ja`).
- The enum's owning struct, its serializer and its Rust name are unresolved. Names such as `Pdi` are reported as bytes, with no meaning inferred.
- No gate is requested. This is one enum codec of the constants inventory, not the inventory.

Next question: which struct deserializers call these five visitors? A caller scan for direct `call 0x23c65f0`/`0x3bdd720`/`0x4d6b5d0` would give the field name and the action that carries this kind. What serializer writes the same seven names back?
