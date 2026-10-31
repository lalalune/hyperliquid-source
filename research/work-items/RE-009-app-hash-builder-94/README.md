# RE-009: how node #94 builds the 32-byte computed app_hash

- Component ID: RE-009
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985
- Claim status: observation for bytes, tables, offsets and constants; inference for names and meaning, marked below; readers of the value unresolved
- Scope included and excluded: included are the three builders `0x2755dc0`, `0x4d7e8c0`, `0x4d7c910`, their 41 closures, the Keccak core in each closure body, the two-digest output and the height cadence at the three call sites. Excluded are the meaning of each state field, the bytes each serializer writes, the job runner internals and every reader of the stored value.

## Reproduce

Run from the repository root. The tool reads the ELF only and never executes it.

```sh
python3 tools/app_hash_builder.py --out research/work-items/RE-009-app-hash-builder-94
python3 -m unittest tests.test_app_hash_builder
sha256sum -c research/work-items/RE-009-app-hash-builder-94/MANIFEST.sha256
```

No external program feeds any output. Sections come from `tools/elf_index.py`, extents from `tools/fde_extents.py`, RELATIVE addends from `.rela.dyn` through `struct`. Instructions are matched only as fixed byte patterns, so a binutils change cannot move a count. Files: `app-hash-builder.json` and `closure-rows.tsv`. `<at>` in `log_pieces` stands for the at-sign byte.

## Evidence

All addresses are ELF VAs. Offsets are relative to the second argument of each builder.

### Call sites and cadence

| lane | caller FDE | builder | mode byte | builder call | map offset |
| --- | --- | --- | --- | --- | --- |
| low | `0x2209d40` | `0x2755dc0` | `+0x8f2` | `0x220b007` | `+0x3b28` |
| primary | `0x42e4600` | `0x4d7e8c0` | `+0x1372` | `0x42e4fcf` | `+0x45a8` |
| secondary | `0x42e5d40` | `0x4d7c910` | `+0x8f2` | `0x42e669f` | `+0x3b28` |

Each site compares the mode byte with 2. Below 2 it picks modulus 50, otherwise 2000 (`b8 32 00 00 00`, `b9 d0 07 00 00`, `cmovb`). The builder runs only when `r13 % modulus == 0`. The result then goes to a store call with `r13` and the map offset above: `0x285f980` in the low lane, `0x4928fd0` in the other two.

The low-lane bytes, as a human-read excerpt:

```text
220afc2: cmp    BYTE PTR [rbx+0x8f2],0x2
220afc9: mov    eax,0x32
220afce: mov    ecx,0x7d0
220afd3: cmovb  rcx,rax
```

### Closure tables

Each builder allocates `0x290` bytes, which is 41 pairs of (box, vtable), and writes count 41. There are two tables with 41 rows at stride `0x20`: `0x56bda38` for the low lane, and `0x57446e8` shared by the two others. Row box sizes match between tables.

`closure-rows.tsv` has one line per row. In the low lane the capture code gives:

| capture | rows |
| --- | --- |
| base pointer | 1 (row 0, box 8) |
| one state field | 32 (box 8 each) |
| group of state fields | 3 (rows 38, 39, 40: 15, 16 and 8 fields) |
| boxed Vec built by the builder | 5 (rows 1, 2, 6, 12, 13) |

The tool checks each box size against its captures. It finds 71 distinct field offsets from `0x80` to `0x3acc`, none captured twice. The five Vecs come from a loop over `+0x3370` (count `+0x3378`, stride `0x138`) and from `+0x3388`/`+0x3390` (stride `0xd8`). Before that loop the builder compares `+0x3378` with `+0x5c8` and calls a check with Location `l1/src/dex_registry/dex_registry.rs:35:48`.

### Hash core

81 of the 82 call slots are 14-byte thunks onto a body. In low-lane row 28 the slot is the body. All 82 bodies hold exactly one hash core:

- it serializes its capture into a buffer, then builds a hash state with rate 136 and delimiter 1;
- one call through slot `0x576e1d8` (`0x4f59a10`), a `0xe0`-byte state copy, one call through slot `0x576e1e0` (`0x4f59e40`) with length 32;
- the 32 result bytes go to the out pointer.

`0x4f59480`, held by slot `0x5777790`, references the table at `0x7d04c8`. The tool regenerates all 24 words from the Keccak-f[1600] LFSR and they match.

66 of the 82 bodies set writer config `0x1000400` themselves. The other 16 do not hold those bytes in their own extent.

### Output

In all three builders the same byte chain ends the hash work:

```text
call blocks hash            -> digest at rsp+0x2c8
call digest list hash       -> digest at rsp+0x330
movupd xmm0, [rsp+0x330]    16 bytes
movupd xmm1, [rsp+0x2c8]    16 bytes
movupd [out+0x10], xmm1
movupd [out], xmm0
```

The blocks hash takes `0x1830` bytes copied from three `0x810` blocks at `+0xcb8`, `+0x15c0`, `+0x1ec8` (`0x28183c0` low, `0x4ae6a60` shared). The digest list hash takes the job results (`0x2819270` low, `0x4ae4440` shared). Its writer `0x1e5de50` walks 32-byte entries and calls slot `0x5773120` for each with a `0x42`-byte buffer and length `0x20`.

So `out[0..16]` is the first 16 bytes of the digest list digest, and `out[16..32]` is the first 16 bytes of the blocks digest.

Each builder then uses log template `0x1ded08` once. Its text includes `computed app_hash:`, `[context:`, `[pre_hash_latency:` and `[total_latency:`.

### Inferences

- The hash is Keccak-256: rate 136, delimiter 1, 32 output bytes, 0x80 final pad seen in `0x4f59e40`, and the LFSR round table. The delimiter rules out SHA3-256.
- Row digests enter the list in row order. The job runner `0x25b7ef0` was not read.
- Each digest is written as text: `0x42` is 66 bytes, enough for a `0x` prefix and 64 hex digits.
- `+0x3370` is the dex list, from the `dex_registry.rs` Location on the length check.
- `r13` is the block height. Reference `engine.rs` has no row for these builders, so this is read from the log text and the map use only.
- The mode byte chooses a chain kind. Its meaning is unresolved. Low-lane row 38 captures `+0x8f2`, so the byte is itself hashed.
- The log line prints the digests joined with one separator. The chain at `0x27571c3` was only read by shape.

### Overlap

`research/work-items/RE-009-storage-state-roots/hashers.json` lists `0x28183c0`, `0x2819270` and the Keccak helpers as hash sites, and its README names the round table. It does not link them to these builders. This packet only pins that three `0x810` blocks enter one digest; it does not say how they are maintained.

## Implementation and comparison

not yet implemented

## Results and limitations

Metrics are in `app-hash-builder.json`: 41 rows in each of 2 tables, 82 of 82 bodies with one hash core, 3 of 3 sites with moduli 50 and 2000, 3 of 3 builders with the output chain, 71 distinct low-lane fields.

- Capture offsets are read for the low lane only. The shared table has matching row count and box sizes, but its capture code uses other registers and was not walked.
- Row order inside the list is inferred, not proved. See above.
- Field names are not recovered. The serializers were not read, so no digest here can be recomputed yet.
- Readers of the stored value are out of scope.
- No progress gate is requested.

Next question: what type does each of the 41 rows serialize, starting with row 0 and the 15, 16 and 8 field groups in rows 38 to 40?
