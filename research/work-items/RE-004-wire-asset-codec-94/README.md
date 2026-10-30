# RE-004: the wire asset id decoder and encoder, proved over every input by interval refinement

- Component ID: RE-004 (quantities and rounding), reference leads `l1/asset/pdi.rs`,
  `l1/dex_registry/clearinghouses.rs` and `l1/exchange/handlers/34_twap_cancel.rs`
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the literals, the function extents, the id arithmetic and the error
  tags under the stated host model; inference for the names of the id classes; unresolved items are
  listed under Results and limitations
- Scope included: the decoder 0x3c0cc70, its lookup helper 0x3c0c990, the encoder 0x3c0cea0, and the
  two inline encoder copies inside 0x3bfd1d0 and 0x3bfd7a0.
- Scope excluded: the bodies of the host functions the decoder calls (listed under Results), the
  callers, what the ids select downstream, and node #115.

## Reproduce

Platform: Linux x86-64, Python 3.12.3. Run from the repository root. The binary is read as bytes and
never executed. The tool calls no external program, so its output does not depend on a binutils
version: section headers, `.rela.dyn` and `.eh_frame_hdr` are read with `struct`, instruction lengths
come from a decoder inside the tool, and an evaluator inside the tool runs the bytes.

```
python3 tools/artifacts.py verify
python3 tools/wire_asset_codec.py --out research/work-items/RE-004-wire-asset-codec-94
python3 -m unittest tests.test_wire_asset_codec
(cd research/work-items/RE-004-wire-asset-codec-94 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first and stops on a mismatch. It takes about a minute. Outputs:
`evidence.json`, `intervals.tsv`, `helper-vectors.tsv`, `tail-vectors.tsv`, `literals.tsv` and
`callers.tsv`. The analysis completed and was not limited by a timeout.

A one-off review check, not part of the generated files: the instruction starts of the 5 functions
were compared with GNU objdump 2.42. 901 instructions, 0 differences.

## Evidence

Coordinates are ELF virtual addresses.

**Boundaries.** From `.eh_frame_hdr` and each FDE: decoder [0x3c0cc70, 0x3c0ce9d), helper
[0x3c0c990, 0x3c0cbe7), encoder [0x3c0cea0, 0x3c0d0b3), [0x3bfd1d0, 0x3bfd3b5) and
[0x3bfd7a0, 0x3bfdf02). The `.rela.dyn` entry for slot 0x5773950 has addend 0x3c0cc70.

**Census.** `literals.tsv` lists every occurrence in `.text` of 110000, -110000, -100000, -100001,
0x7fff3ca and 0x7fff3cb: 16 hits. 14 are an immediate or a displacement of a decoded instruction, all
inside the family. The other 2, in 0x1a75bf0 and 0x4ac8a50, are one straddle across two instructions
and one branch displacement. The tool refuses a family literal used as an immediate or displacement
anywhere else. `callers.tsv` holds 64 indirect calls through slot 0x5773950 and 31 direct calls to
the encoder, in 67 functions, each checked to start on a decoded instruction.

**Method.** Each run covers one interval of inputs. A value derived from the input is kept as
`((a*x + c) mod 2^64) >> k`. Every compare, carry and sign test on such a value cuts the interval at
the exact inputs where its result can change, and the run restarts on the two pieces. A piece that
finishes with no cut therefore has one path and one output form for every input in it, so the rows of
`intervals.tsv` are a proof over the whole domain and not a sample. Equality is handled the same way,
which is why one id can stand alone as a row. A value that cannot be tracked is unknown, and a branch
on an unknown value stops the tool. The tool then compares each merged row at both ends, slope
included, against the closed form below. 17 tables took 20215 pieces.

**Decoder (u32 `x`, all 2^32 inputs).** `asset_kind` is the word at +8 of the result and `value` the
word at +0x10. Tag 0x186 is success.

| `x` | Result |
|---|---|
| 0..=9999 | `asset_kind=0`, `value=x`, if dex 0 has `x < len`, else tag 0x60 carrying `x` |
| 10000..=109999 | `asset_kind=1`, `value=x-10000`, if the helper finds it and the round trip holds, else tag 0x17f |
| 110000..=99999999 | `y=x-100000`, `dex=y/10000`, `local=y%10000`: `asset_kind=0`, `value=y` if `dex` exists and `local < len`, else tag 0x60 carrying `y` |
| 100000000..=0xffffffff | `asset_kind=1`, `value=` helper result, only if the id rebuilt from the token equals `x`, else tag 0x17f |

The dex length is the u64 at +0x10 of a 0x2f0-byte entry. Dex 0 is reachable only through the first
row, and the third row reaches dex 1 to 9989.

**The dex-missing path returns 0x60, not 0x141.** At 0x3c0cda7 the decoder writes 0x141 into a
temporary, copies it, sees that the copy is not 0x186 at 0x3c0ce10, drops it at 0x3c0ce4a, and then
writes tag 0x60 and `y` to the result at 0x3c0ce4f. On the success path the same 0x141 temporary is
built and dropped at 0x3c0cda0. The tool refuses any table row with tag 0x141, and the table
`decoder partial-registry` shows 0x60 for a missing dex and for a short one alike.

**Encoder (0x3c0cea0).** Its bit 0 flag picks the kind. Whole u64 domain:

| Input | Result |
|---|---|
| flag 0, `idx` 0..=9999 | `idx` |
| flag 0, `idx` 10000..=99899999 | `idx+100000` |
| flag 0, larger | 0xffffffff |
| flag 1, token side >= 2, `idx` 0..=99999 | `idx+10000` |
| flag 1, token side >= 2, `idx` 100000..=99999999 | 0xffffffff |
| flag 1, token side >= 2, `idx` 100000000..=0xffffffff | `idx` |
| flag 1, token side >= 2, larger | 0xffffffff |
| flag 1, token side 0 or 1, `q` 0..=419496729 | `10*q + side + 100000000` |
| flag 1, token side 0 or 1, larger `q` | 0xffffffff |

The product and both additions saturate at u64::MAX, which then fails the 32-bit test.
Inputs at or above the token count panic on a bounds check. The tool sets that count to 2^58, the
most 32-byte entries a vector can hold, which is why the last row of `encoder token side=2` is a
panic. Both inline copies, the `shr 5` form in 0x3bfd1d0 at 0x3bfd274 and the branchless form in
0x3bfd7a0 at 0x3bfda0c, give the three flag 0 rows for every u64.

**Round trip.** In the full-registry table all 100000000 ids below 10^8 decode as success, and the
encoder returns each of them. In the other direction every encoder row with a value below 10^8
decodes as success with the same kind and returns its input. Rows are joined by composing their
forms, so this is exact. Outcome-style ids were joined at `q=12` and `q=419496729`, sides 0 and 1:
each id is the only success row for its token.

**Helper (0x3c0c990).** Below 10^8: `None` if `x >= token count` or the predicate through slot
0x5773198 is nonzero, else `x`. From 10^8: `y=x-100000000`, `q=y/10`, `r=y%10`. `r>1` gives `None`
before any lookup, and `r` of 0 or 1 selects a field offset of 0 or 0x28. The `/10` is proved for
every u64 from the bytes at 0x3c0c9e0: `m=0xcccccccccccccccd`, `shift 67`, `m*10-2^67=2`, and
`y*2 < 2^67`. 0xffffffff has `r=5`, so the sentinel never decodes. The largest outcome-style id is
4294967291. After a map hit (from 0x3c0cb87) the id is read at entry-0x68+offset, bounds-checked
against +0x188, and looked up in 0xe8-byte records at +0x180. Success needs a list length of exactly
1 at +0x60, and the first element of the list at +0x58 is the result.

A human-readable excerpt, not used by the tool:

```
3c0cd50: cmp  esi,0x2710
3c0cd56: jb   3c0cd73
3c0cd58: cmp  esi,0x1adb0
3c0cd5e: jae  3c0cd6c
3c0cd60: add  r14,0xffffffffffffd8f0
3c0cd67: jmp  3c0cc93
3c0cd6c: add  r14,0xfffffffffffe7960
3c0cd73: mov  r15d,0xd1b71759
3c0cd79: imul r15,r14
3c0cd7d: shr  r15,0x2d
```

**Inferences.** Not proved by the bytes: that kind 0 is a perp and kind 1 a spot token, that the
`q` and `side` pair is an outcome market and its side (the id form `10*q+side` is observed, the
meaning is not), and that the 32-byte table is the token list. The labels 0x60 InvalidPerpAsset and
0x17f UnknownSpotAsset are the reference's. The bytes show only the numbers and their payloads.

**Reference check, labels only.** `l1/dex_registry/clearinghouses.rs` agrees with the four decoder
ranges, with 96 (0x60) carrying the normalized id for both a missing dex and a missing local index,
and with the perp encoder. Two points differ:

- The comment in `l1/exchange/handlers/34_twap_cancel.rs` says status 321 is returned directly from
  the classifier when the dex does not exist. The binary returns 0x60 there, as `clearinghouses.rs`
  does, so the two reference files disagree and the bytes side with `clearinghouses.rs`.
- For a token index from 100000 to 99999999, `encode_wire_asset_id` in `clearinghouses.rs` gives
  `index+10000`. The binary gives 0xffffffff at 0x3c0cea0, because it rebuilds the window and
  compares (the `cmp r9d,edx` kind test at 0x3c0cf4e fails for such an id). Without that check, an
  index such as 200000 would become 210000, which the decoder reads as a perp id.

## Implementation and comparison

not yet implemented

## Results and limitations

`evidence.json` holds the counts. 17 of 17 tables match their closed forms over the whole domain, 92
of 92 helper vectors and 18 of 18 tail vectors match. `python3 -m unittest tests.test_wire_asset_codec`
runs 33 tests, all passing. 19 are mutated-byte controls that must be refused and 4 are corrupted-input
or wrong-rule controls. No progress gate is requested.

Limits:

- The host functions are stubs. `0x3c1ada0` and `0x3379490` (drops) are assumed to leave callee-saved
  registers and the word at +0x68 alone. Slot 0x57738c8 is modelled as writing `(q, side)` and slot
  0x5773198 as returning a predicate. The helper is a stub inside the decoder tables, with the
  behaviour shown separately above. Every stub is a stated host model, and the decoder tables hold
  under it, across the 10 worlds named in `intervals.tsv`.
- The helper is proved by 92 edge vectors plus the `/10` bound, not by intervals. The map probe loop
  and 0x399c4a0 are not modelled: a run stops at the first hash call, and the hit tail is run from
  0x3c0cb87 with a prepared entry.
- Outcome-style decoder rows use two `q` values. The encoder side is whole-domain in `q`.
- A token index from 10^8 encodes to itself. With side >= 2 that id decodes as tag 0x17f, so these
  rows are outside the backward round trip. Whether such an index can exist is unknown.
- Both `shr 5` guards (0x3bfd28e, 0x3bfda75) are shadowed by later compares. A one-step change to
  either does not alter any output, and a test records this. So the bytes pin their immediates, not
  the evaluator.
- A linear sweep resynchronises after a bad start, so a clean stop at the FDE end is weak evidence of
  alignment. The objdump comparison above is the stronger check, for these 5 functions only.
- The message text behind tag 0x60 is not checked. Callers are listed, not traced.

Next question: what does the predicate at 0x3728670 test, that is, which tokens does the helper
refuse a spot id for, and is it the same token set that has an outcome-style id?
