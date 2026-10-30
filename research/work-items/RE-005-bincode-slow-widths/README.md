# RE-005 sibling: which bincode-fork varint slow Reader paths and integer widths does node #94 contain?

- Component ID: RE-005 (bincode-fork varint / integer-encoding boundary; slow Reader path and u32 width)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: base `main` @ `1f8c67c63ca4794c9689235471c60297f8a5c985`; no upstream source commit (the bincode fork source is not available)
- Claim status: observation (static disassembly); inference where marked below
- Scope included and excluded: included are the u32 slice decoder, the u64 slice slow branch, both Readers, the error builder, decode vectors and the u16 length-marker scan. Excluded are the u64 fast-path body (merged packet), Reader `0x466dad0`, and runtime behaviour.

Status: **evidence packet, no gate claimed.** Sibling to
`../RE-005-bincode-varint/` (the merged u64 *slice fast path*). This packet does
**not** modify that packet. It pins:

1. The **u32 slice decoder** at `0x466bc10..0x466bd03` (the other integer width
   next to the u64 fast path) and its slow-branch call through GOT `0x5775138`
   into the u32 Reader.
2. The **slow branch** out of the already-pinned u64 slice decoder
   `0x466bd10` (`cmp rax,8; jbe` → GOT `0x57745e0` → u64 Reader). The fast-path
   body itself is not re-claimed.
3. The two **Reader** bodies that those slow branches call:
   - `varint_decode_u32_reader` `0x466d850..0x466d975`, jump table `0x6f6ec8`
   - `varint_decode_u64_reader` `0x466d980..0x466dabc`, jump table `0x6f6ed8`
4. The shared **error builder** at `0x466dac0..0x466dace` (result tag `0x3`,
   then `sil` / `dl`).
5. Decode vectors for inputs of length ≤ 8 and for the `0xfe` / `0xff` markers,
   derived from the observed little-endian (`dl == 0`) instruction semantics.
6. Exact call-site counts: every `call [rip+disp32]` in `.text` whose GOT
   relocates to either Reader (`0x466d850`: **2**, `0x466d980`: **12**).

## Reproduce

Target: `artifacts/node/94/hl-node`, release #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes).
Static and offline. The binary is never executed.

```sh
python3 -B tools/bincode_varint_slow.py | sha256sum
# 2a997306317bd14b243d1f780501514707f3b4a5d75726555a0156608867df14 = slow-sites.json
python3 -I -B research/work-items/RE-005-bincode-slow-widths/verify.py
python3 -O -B research/work-items/RE-005-bincode-slow-widths/verify.py
python3 -I -B research/work-items/RE-005-bincode-slow-widths/independent_verify.py
# prints PASS / FAIL / INCONCLUSIVE
python3 -I -B tools/bincode_varint_decode.py | sha256sum
# negative control: 6da03736b718d6c7db769a0a1be7e9131a6229cea6b198dd85d535282be5a56f, unchanged
python3 -m unittest tests.test_bincode_varint_slow -v
```

Tools: Python 3 standard library only; GNU objdump 2.44 for the GNU-only tests
(they skip under an LLVM-shaped objdump). Working directory: repo root. Platform:
Linux x86-64. Side effects: none, apart from stdout.

Output is byte-identical under `PYTHONHASHSEED` 0, 7 and 99.

| file | sha256 |
|---|---|
| `slow-sites.json` | `2a997306317bd14b243d1f780501514707f3b4a5d75726555a0156608867df14` |
| `objdump-excerpts.txt` | `0a8b937e511c334bc640b417042359a864051e8b758de85b5aeadefbe1e9eb03` |

The objdump excerpts were made with GNU objdump (`-d -M intel --no-show-raw-insn`)
over the five FDE ranges. They are for human reading only. The tool and tests
never parse them.

## Evidence

Coordinates are virtual addresses (VA), not file offsets. Analysis was complete over the five FDE ranges and the full `.text` scan; nothing timed out. Function bounds come from this binary's own
`.eh_frame_hdr` / `.eh_frame` FDEs.

### u32 slice decoder

| item | value |
|---|---|
| FDE | `0x466bc10..0x466bd03` |
| fast-path gate | `cmp rax,4` @`0x466bc3d`; `jbe 0x466bca7` @`0x466bc41` |
| jump table | `0x6f6e98` → `0xfb:0x466bc79` / `0xfc:0x466bc85` / `0xfd:0x466bcd3` / `0xfe:0x466bcbb` |
| slow GOT | `0x5775138` → `0x466d850` |
| Ok tag | `0x12` at `0x466bc9f`; value stored as DWORD at `[rdi+4]` |
| `0xfd` error | `esi=2`, `edx=3` |
| `0xfe` error | `esi=2`, `edx=4` |
| `0xff` error | `esi=2`, `edx=0xc` |

### u64 slice slow branch (fast path claimed elsewhere)

| item | value |
|---|---|
| FDE (shared with fast path) | `0x466bd10..0x466bdf5` |
| gate | `cmp rax,8` @`0x466bd3d`; `jbe 0x466bdb1` @`0x466bd41` |
| slow GOT | `0x57745e0` → `0x466d980` |
| fast-path `0xfe` arm | `esi=2`, `edx=4` @`0x466bdc5` (differs from the Reader's `esi=3`) |
| fast-path `0xff` arm | `esi=2`, `edx=0xc` @`0x466bddd` |

### Readers

| reader | FDE | table | `0xfb`/`0xfc`/`0xfd`/`0xfe` | expected_code on `0xfe` | store width |
|---|---|---|---|---|---|
| u32 | `0x466d850..0x466d975` | `0x6f6ec8` | `0x466d8b7`/`0x466d8c4`/`0x466d945`/`0x466d92d` | 2 | 4 |
| u64 | `0x466d980..0x466dabc` | `0x6f6ed8` | `0x466d9e7`/`0x466da01`/`0x466d9f4`/`0x466da8c` | 3 | 8 |

Both Readers:

- Read the tag with `movzx r8d, byte [rcx]`, then `cmp r8, 0xfb`.
- On `tag < 0xfb`: store the tag as the value, Ok tag `0x12`.
- On empty input: UnexpectedEnd tag `0x0`, need `1`.
- On `tag >= 0xfb`: `add r8d, -0xfb; cmp r8d, 3; ja oor` indexes the relative jump table.
- Payload arms check remaining length (`cmp rax, 3/5/9`) before the LE load; on
  shortfall they write UnexpectedEnd with `need = required - present`.
- `0xfb` reads a u16 at `+1` (with `rol cx,8` when `dl != 0`); `0xfc` a u32
  (`bswap`); `0xfd` a u64 on the u64 Reader only (u32 Reader treats `0xfd` as
  error with `found_code=3`).
- `0xfe` / out-of-range call the shared error builder at `0x466dac0` with the
  codes above. **No 16-byte (u128) read exists.**

### Error builder

`0x466dac0..0x466dace`: `mov byte [rdi], 0x3; mov [rdi+1], sil; mov [rdi+2], dl; ret`.
Reached through GOT `0x57745e8`.

### Wire rule (observed)

| tag | meaning |
|---|---|
| `< 0xfb` | value is the tag byte; 1 consumed |
| `0xfb` | u16 LE at +1; 3 consumed |
| `0xfc` | u32 LE at +1; 5 consumed |
| `0xfd` | u64 LE at +1 (u64 Reader); error on u32 Reader; 9 consumed |
| `0xfe` | error; `found_code=4`; **no u128 read** |
| `0xff` | error; `found_code=0xc` |

### u16 length-marker scan (`u16_marker_scan`)

The scan covered 35 `0xfb` sites, exactly one length-2-adjacent hit at
`0x134698d`, which is a chain-id lookup, not a u16 decoder, so there is no u16
slice decoder.

- Sites: every `cmp <reg>,0xfb` instruction start in `.text`, 35 in total. The
  list is pinned in the tool and re-proved equal to GNU objdump 2.44's full
  `.text` disassembly by a GNU-only test. Memory-operand forms: 0. 8-bit forms:
  0. A raw byte-pattern search finds 354 candidates; the other 319 are not
  instruction starts. `83 /7 fb` is a sign-extended `-5` compare and is
  excluded.
- Rule: a site is `length2_adjacent` when a `cmp <reg>,2` starts in
  `[site-0x80, site+0x80)` and a `lea r,[rip+disp] ... jmp r` dispatch starts in
  `[site, site+0x20)`, both clipped to the containing FDE. Every site's window
  contents and classification are written to `slow-sites.json`.
- Result: 1 hit, `0x134698d`. 34 sites have no `cmp <reg>,2` in the window. The
  next closest is `0x3959c68`, whose nearest `cmp <reg>,2` is 271 bytes away.
- `0x134698d` (FDE `0x1346860..0x1346daf`): `lea rcx,[rdi-1]; cmp rcx,0xfb; ja`
  then a jump table at `0x2096fc`, so it tests whether `rdi` is in 1..252. The
  `cmp rcx,2` at `0x134690d` (128 bytes earlier) follows
  `lea rcx,[rdi-0x2328]`, so it tests whether `rdi` is in {9000, 9001}. It is not
  a remaining-length check. The function has 87 `cmp rdi,imm` or
  `lea rcx,[rdi-imm]` instructions on the integer in `rdi`, with values such as 31337, 42161, 8453 and 11155111. It returns
  `xor eax,eax; mov rdx,rdi; ret`. GNU disassembly shows no memory operand
  other than RIP-relative operands and the jump-table load, so the function
  never reads a tag byte from a buffer. That makes it an EVM chain-id
  membership lookup, not a decoder.

## Implementation and comparison

Independent Rust path: not yet implemented. No Cargo.lock, compiler/linker flags,
two-build result, or normalized comparison/masks exist for this packet. Fixture
identity is the binary SHA-256 above. Boundary and error cases are covered by the
22 decode vectors (inputs of length ≤ 8 and the `0xfe` / `0xff` markers). The
corruption control is the negative-control hash below.

## Results and limitations

Metrics (machine-readable in `slow-sites.json`):

- Readers pinned: 2 of 2 slow-branch targets (`0x466d850`, `0x466d980`).
- Reader call sites: `0x466d850` 2, `0x466d980` 12, over all `call [rip+disp32]` in `.text`.
- Decode vectors: 22.
- `0xfb` compare sites: 35 of 35 instruction starts. `length2_adjacent` hits: 1 of 35 (`0x134698d`, not a decoder).

Passed: `verify.py` (`-I -B`, `-O -B`) and `independent_verify.py` (PASS).
No progress gate is requested.

### What this does not claim

- No claim that the binary executes these paths at runtime; evidence is static.
- No claim about the `0x466dad0` Reader (`esi=5` on its `0xfe` arm); different
  expected-type code, out of scope.
- No claim that the scan rule catches every conceivable u16 decoder shape; it
  proves the absence of the bincode idiom (a `cmp <reg>,2` within `0x80` bytes
  of a `cmp <reg>,0xfb`, plus a jump-table dispatch within `0x20` bytes).
- The chain names for the `0x1346860` immediates are an inference from the
  numbers, not an observation. u16 appears only as the `0xfb` payload width;
  u128 appears only as the `0xfe` error marker.
- The merged RE-005 fast-path packet (u64 slice + 21 dispatch sites) is not
  modified; its JSON hash
  `6da03736b718d6c7db769a0a1be7e9131a6229cea6b198dd85d535282be5a56f` is the
  negative control.
- Function names are our labels; the binary has no symbols for them.
- `esi`/`edx` are pinned as raw codes; mapping them onto a source-level
  `IntegerType` enum is an inference, not an observation.

### Negative control

`tools/bincode_varint_decode.py` recompute must stay at
`6da03736b718d6c7db769a0a1be7e9131a6229cea6b198dd85d535282be5a56f`. The slow
tool refuses to emit if that hash moves.

### Next question

What does the `0x466dad0` Reader decode (`esi=5` on its `0xfe` arm), and which
source-level `IntegerType` variants do the raw `esi`/`edx` codes correspond to?
