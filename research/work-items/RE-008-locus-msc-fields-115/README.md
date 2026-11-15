# RE-008: node #115 Locus field names and their abci box offsets (stage 89)

- Component ID: abci. Question: open PR #6093 found the seq visitor `0x2fc21d0` for `struct Locus with 16 elements`, and open PR #6095 named the 59 Exchange fields, with Locus as hash slot 0. Neither named Locus's 16 fields or said which box offset each one occupies.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6093 and #6095. It does not depend on their files.
- Claim status: instruction bytes, string bytes, relocations and branch targets are observations. Readings of names such as "context" or "chain" are inferences.
- Scope included: the name table, the field-identifier matcher `0x5472fd0`, and the decode, stack and box stores for each of the 16 elements in `0x2fc21d0`. Scope excluded: the bodies of the 16 element decoders, the visit_map form `0x332c430`, and the Exchange `msc` field (index 58) type. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/locus_msc_fields_115.py --check
python3 -m unittest tests.test_locus_msc_fields_115
```

The tool reads the ELF. It does not execute the binary and does not start objdump or readelf. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the 16 names and the matcher

- `0x794e8a` holds 48 bytes, `ctxclssclftrustchnpdluaRblpqusctruacvlthcmpmumsc`. That is 16 three-letter names, immediately before the record string `struct Locus with 16 elements` at `0x794eba`. Relocation `0x6464530` points to that string.
- The matcher `0x5472fd0` requires length 3, then runs 16 blocks of 25 bytes from `0x5472fdf`. Each block XORs the input word and byte with a name and branches to an arm that returns that name's index.
- The tool decodes all 16 blocks and arms: index k matches the k-th name in the list. Any other input returns 16.

## Evidence 2: index → box offset

In `0x2fc21d0`, element k is decoded by one call. Its value is kept in one stack slot, and the final assembly at `0x2fc302f..0x2fc32b3` copies it into the output (`rbx`).

| Index | Name | Decoder | Stack store | Box store | Box offset | Size |
|---|---|---|---|---|---|---|
| 0 | ctx | `0x421da60` | `0x2fc2261` | `0x2fc31f4` | `+0x0` | 0x80 |
| 1 | cls | `0x446b470` | `0x2fc240a` | `0x2fc3040` | `+0x7c0` | 0x18 |
| 2 | scl | `0x3bfd340` | `0x2fc25b8` | `0x2fc3047` | `+0x80` | 0x5f0 |
| 3 | ftr | `0x3c1d250` | `0x2fc26fa` | `0x2fc3065` | `+0x7d8` | 0x190 |
| 4 | ust | `0x47137f0` | `0x2fc2833` | `0x2fc309c` | `+0x968` | 0x48 |
| 5 | chn | `0x467f840` | `0x2fc288d` | `0x2fc32ad` | `+0xb9a` | 1 |
| 6 | pdl | `0x3b6b160` | `0x2fc28b9` | `0x2fc3297` | `+0xb98` | 1 |
| 7 | uaR | `0x3b6b730` | `0x2fc2a90` | `0x2fc30d7` | `+0x9f8` | 0x20 |
| 8 | blp | `0x3b71920` | `0x2fc2b65` | `0x2fc30e5` | `+0x670` | 0x150 |
| 9 | qus | `0x3b6c0a0` | `0x2fc2ba1` | `0x2fc310d` | `+0xb78` | 0x18 |
| 10 | ctr | `0x3b6c150` | `0x2fc2c09` | `0x2fc3272` | `+0xa78` | 0x100 |
| 11 | uac | `0x3b6cdf0` | `0x2fc2d45` | `0x2fc3158` | `+0x9b0` | 0x48 |
| 12 | vlt | `0x3b70ef0` | `0x2fc2de6` | `0x2fc3176` | `+0xa18` | 0x20 |
| 13 | hcm | `0x3b6af70` | `0x2fc2e0e` | `0x2fc32a2` | `+0xb99` | 1 |
| 14 | pmu | `0x3b6f220` | `0x2fc2e5b` | `0x2fc328b` | `+0xb90` | 8 |
| 15 | msc | `0x3b717d0` | `0x2fc2e73` | `0x2fc31f7` | `+0xa38` | 0x40 |

- **The fields tile the struct.** The 16 spans cover `+0x0..+0xb9b` with no gap and no overlap; the tool checks this.
- **Same order as the hash.** The offsets in index order equal #6027's slot-0 address order: base, `+0x7c0`, `+0x80`, `+0x7d8`, `+0x968`, `+0xb9a`, `+0xb98`, `+0x9f8`, `+0x670`, `+0xb78`, `+0xa78`, `+0x9b0`, `+0xa18`, `+0xb99`, `+0xb90`, `+0xa38`.
- **`ctr` is 0x100 bytes.** Its decoder result gives a qword (→ `+0xa78`), a dword (→ `+0xa80`) and 0xf4 bytes copied from `rsp+0xc00` to `+0xa84` (`0x2fc2c59`, `0x2fc31dd`).
- **`msc` has a default.** When the sequence ends before element 15 (`cmp r14, [rsp+0xc0]` at `0x2fc2fcc`), the visitor fills `msc` with zeros, an empty Vec (8) and the f64 0.4 from `0x459098`.

## Inferred labels

- `ctx` (`+0x0..+0x80`) holds the height `+0x28`, the round `+0x30` and the consensus time `+0x60` (#6090). The freeze assertion text from #5970, `freeze_height >= self.locus.context.height()`, fits `ctx` = context.
- `chn` is the selector byte `+0xb9a` that the simulate-panic check (#6091) compares with 3. Reading it as a chain or network kind is an inference.

## Results and limitations

- Result: all 16 Locus field names are bound to their indices and box offsets.
- Limits:
  - The element decoders' bodies are not read; field types are not named.
  - The visit_map form `0x332c430` is not mapped.
  - The tool relies on program order for "last store before the assembly". Stack slots such as `rsp+0x920` are reused, and the pinned store is the later one.
  - (b) is not resolved. The Exchange `msc` field (index 58, `+0x3908..+0x3a00`, which contains the simulate-panic pair `+0x39a8`/`+0x39b0`) is a different field from Locus `msc` (`+0xa38`), and its type and sub-field names are not mapped. The string `struct LocusMisc` exists at `0x452e80` and is referenced at `0x2c7d4fb`, `0x3c4d6bb` and `0x5616d9b`; which field uses it is not proven.
- Next lead: the Exchange element 58 decode in the Exchange seq visitor `0x49da420` (`invalid_length(0x3a)` at `0x49df969`), to type the field holding `+0x39a8`/`+0x39b0`.
