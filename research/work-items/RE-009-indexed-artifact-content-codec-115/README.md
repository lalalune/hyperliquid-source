# RE-009: reconstruct the node #115 IndexedArtifactContentSerde deserialize path

With this packet the whole serde_json decode path of the storage enum
`IndexedArtifactContentSerde` can be rebuilt from bytes and checked. That
covers the five wire names and their indexes, the String and Object entry
paths, the single-key map rule and the index-table release (including its
overflow panics). It also covers the unit-variant rejection, the struct-variant
callee and field list for each arm, and the exact output layout of each arm
(tags 2/3/5/6, a niche-carrying 0xb0-byte HotfixMetadata move, error tag 7).
An independent Python reconstruction matches the original machine code in
6,388 of 6,388 interpreted cases across two copy families. All 14 deliberately
wrong reconstructions are caught.

- Component ID: `storage` (task RE-009, `db/*`; the variant pool is adjacent to the `db/src/owned_db_home.rs` location string)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: hyperliquid-source `05bc2de303c05525b71e7e257426e741bc66a390`; no reference source used
- Claim status:
  - observation: the machine-code behaviour of the 10 bodies, under the stated stub contracts;
  - inference: the Rust-level names (serde_json `Value`, `IndexMap`, `EnumDeserializer`, `Unexpected`);
  - unresolved: the struct-variant field visitors and the meaning of the output tag value 4.
- Scope included and excluded:
  - Included: two copy families × 5 roles. The roles are the `deserialize_enum` entry, the Object/map enum access, `visit_enum`, the variant seed and the exact-name `&str` visitor.
  - Excluded: the 10 struct-variant bodies (`0x14ff380..0x14ff780`, `0x4d518c0..0x4d51cc0`), the Value/iterator drop glue and the allocator. These are stubbed, and their call arguments are checked.
  - No progress gate is requested.

## Reproduce

From the repository root (Python 3.10+ standard library only; no binutils, no subprocess, the capture is never executed):

```
python3 tools/artifacts.py verify
python3 tools/re009_indexed_artifact_content_115.py --out research/work-items/RE-009-indexed-artifact-content-codec-115
python3 -m unittest tests.test_re009_indexed_artifact_content_115
```

The producer refuses any input whose SHA-256 is not the #115 digest above. It
exits non-zero on any mismatch or on any negative control that is not caught.
Its output is deterministic: no time, randomness, absolute path or dict-order
dependence. Two runs into different directories are byte-identical (`diff -r`
is empty).

## Evidence

Coordinates are virtual addresses in the #115 ELF. Body extents come from
`.eh_frame` FDEs via `tools/fde_extents.py`, and section and file-offset
mapping comes from `tools/elf_index.py`. Every body below is an FDE start, and
`linear()` decodes it to its FDE end or to an int3-only tail
(`functions.tsv`, `instructions.tsv`: 1,091 instructions).

| role | family 1 | family 2 | FDE bytes |
| --- | --- | --- | --- |
| `deserialize_enum` on a Value (entry) | `0x1506410` | `0x57d3a40` | 224 |
| Object → single-key map enum access | `0x157ce90` | `0x4e2a0f0` | 716 |
| `visit_enum` (jump table on variant index) | `0x15001f0` | `0x57c3d80` | 640 / 1045 |
| variant seed | `0x1590700` | `0x4ee4e90` | 300 |
| exact-name `&str` visitor (jump table on len−12) | `0x1500470` | `0x57c41a0` | 293 |

Data decoded from bytes (`name-pools.tsv`, `jump-tables.tsv`):

- Variant pools are `&[&str; 5]` built from RELATIVE relocations. They are `0x63fbf90` (family 1) and `0x64b0a28` (family 2), and their names in order are NodeMetadata, VisorMetadata, HotfixMetadata, NodeArtifact and PublisherBinaryMetadata.
- The type-name literal `IndexedArtifactContentSerde` (27 bytes) is at `0x465a39` and `0x93628c`.
- Family-2 struct-variant field lists (passed as `r8`/`r9`):

  | variant | pool | fields |
  | --- | --- | --- |
  | NodeMetadata | `0x64b8278` | `hv`, `bh` |
  | VisorMetadata | `0x64b8298` | `bh` |
  | HotfixMetadata | `0x64b82a8` | `hv`, `bh`, `ha` |
  | NodeArtifact | `0x64aa878` | `vts`, `hf`, `oqf` |
  | PublisherBinaryMetadata | `0x64b82d8` | `n`, `bh` |

  Family 1 calls struct bodies that take only `(out, value)`, so they carry their own field lists.
- Jump tables (`lea; movsxd [t+i*4]; add; jmp`):
  - `visit_enum` tables `0x46567c` and `0x9351b0` have 5 entries each.
  - `&str` visitor tables `0x465690` (family 1, at `0x1500481`) and the family-2 table have 12 entries each, for lengths 12..23.
  - All targets land inside their own body.

Call sites and their resolved targets for every interpreted body are in
`callees.tsv`, including the landing-pad calls that are not reached.

Human-readable excerpt (objdump, family 2 `visit_enum`, not used to make any evidence file):

```
57c3dd5: movzx edx,BYTE PTR [rsp+0x118]     ; variant index from the seed
57c3ddd: lea   rsi,[rip+...]  # 9351b0      ; 5-entry jump table
57c3ded: cmp   rcx,r14                      ; r14 = 0x8000000000000005 (no value)
57c3e2b: lea   rdx,[...] # 93a9ad "NodeMetadata" ; r8 = 0x64b8278 fields, r9 = 2
57c3e52: call  4d51ac0                      ; struct variant body
57c40fa: mov   BYTE PTR [rsp+0x48],0xd      ; Unexpected::UnitVariant -> invalid_type
```

## Implementation and comparison

There is no Rust implementation yet. The reconstruction is the set of pure
functions `r_ident`, `r_seed`, `r_enum`, `r_object`, `r_table_free` and
`r_entry` in the tool. Each one is compared, case by case, with a run of the
original bytes in the tool's x86-64 subset interpreter. Calls between the 10
bodies are executed for real (nested), so an entry case runs the entry, the map
access, `visit_enum`, the seed and the visitor on original code. A comparison
covers the full 0xb8-byte output region, pre-filled with 0x5a so that untouched
bytes must stay untouched, plus the ordered log of every external call and its
arguments.

Reconstructed semantics (both families agree):

1. **Visitor.** An exact byte match of the input against the five names gives `Ok(index)`. Anything else calls `unknown_variant(text, pool, 5)`. There is no case folding and no prefix matching.
2. **Seed.** It runs the visitor on the key. It frees the owned key buffer when `cap != 0`, calling `dealloc(ptr, cap, 0)` after the visitor and before the result check. On an unknown name it returns `Err` (marker `0x8000000000000006`) and drops the value, unless the value is `None` (`0x8000000000000005`).
3. **`visit_enum`.** A seed error gives output tag 7. A `None` value (unit variant) calls `invalid_type(Unexpected::UnitVariant = 0x0d)` and gives tag 7. Otherwise the per-arm struct body is called, and its output is placed as follows:

   | variant | output |
   | --- | --- |
   | NodeMetadata | tag 2, with 0x28 bytes taken from result+8 |
   | VisorMetadata | tag 3, with 0x20 bytes taken from result+1 |
   | HotfixMetadata | the whole 0xb0-byte result is moved over the output (its own word 0 ∈ {0, 1} acts as the tag; 2 is its error niche) |
   | NodeArtifact | tag 5, with 0x38 bytes taken from result+0 (word-0 error niche 2) |
   | PublisherBinaryMetadata | tag 6, with 0x21 bytes taken from result+1 |

   Every struct error gives tag 7 with the error word at +8.
4. **Entry.** The Value kind is word0 ^ 2^63 when bit 63 is set, otherwise 5 (Object):
   - **String (3)** goes to `visit_enum` with no value. A known name therefore always gives the unit-variant error, and the string buffer is freed.
   - **Object (5)** goes to the map access, described in step 5.
   - **Any other kind** calls `unexpected(value)`, then `invalid_type`, then drops the input. The result is tag 7.
5. **Map access.**
   1. The IndexMap index table is released first. With mask m, the control offset is `(8m + 0x17) & ~0xf` and the size is `m + offset + 0x11` (mod 2^64). The call is `dealloc(ctrl − offset, size, size < 16 ? 4 : 0)`.
      - m = 0 skips the release.
      - m = 2^64−1 and m > 0xffff_ffff_ffff_ffee each call a distinct panic location.
   2. Exactly one entry (or a second iterator item with the `None` key niche) builds `{key, Some(value)}` for `visit_enum`.
   3. Zero entries give `invalid_value(Unexpected::Map = 0x0b)`.
   4. Two or more entries trigger, in order:
      1. free the second key;
      2. drop the second value;
      3. call `invalid_value(Map)`;
      4. drop the first value;
      5. free the first key.
   5. The iterator is dropped last, and it still holds `len − consumed` buckets (0x68 bytes each).

Case counts (`summary.json`; all verdicts `match`):

| table | cases | content |
| --- | --- | --- |
| `ident-cases.tsv` | 862 | 431 names and mutations × 2 families |
| `seed-cases.tsv` | 3,448 | × cap {0, len+8} × value {None, Bool} |
| `enum-cases.tsv` | 480 | 10 keys × cap × 4 values × 3 arm outcomes × 2 families |
| `entry-cases.tsv` | 1,598 | 12 Value words, with 8 String names and 157 Object shapes (12 index-table masks, 1–3 entries, None niches) |

Negative controls (`negative-controls.tsv`). Each wrong reconstruction is
run through the same comparison and must disagree with the interpreted bytes
at least once. All 14 are caught:

- case-folded match;
- prefix match;
- sorted variant order;
- key buffer not freed;
- value kept on unknown variant;
- unit variant accepted;
- VisorMetadata tag 4;
- PublisherBinaryMetadata 0x20-byte payload;
- HotfixMetadata given its own tag;
- Array accepted as a name;
- rejected input not dropped;
- multi-key map decoded from its first key;
- index table size without 16-byte rounding;
- mask `0x…ef` freed instead of panicking.

The unit tests also patch one byte of the `NodeArtifact` compare immediate in a
copy of the capture and require the interpreter to diverge. They check that a
corrupted capture, a shifted pool, a non-FDE entry and an unmodelled call are
all rejected.

## Results and limitations

- 6,388 / 6,388 cases match. There are 0 mismatches, and 14 / 14 negative controls are caught.
- Every stubbed callee runs under an explicit contract: it logs its arguments and writes a fixed pattern. The struct-variant bodies, Value drop glue, `IntoIter` drop, allocator and serde error constructors are not interpreted. Their argument values (key pointer and capacity, Value word, field pool, field count, Unexpected byte) are checked.
- Inputs that real data cannot produce, such as a bucket key capacity equal to the `None` niche or an index-table mask above `isize::MAX`, are exercised only to pin the machine-code branches. They are not claimed as reachable states.
- The output tag value 4 is never written by these bodies. It may belong to a variant without a serde arm, or be part of the HotfixMetadata niche range; this is unresolved.
- This is a reconstruction of semantics, not a Rust build, and no gate is requested.

Next question: what are the field visitors of the five struct-variant bodies (family 2 `0x4d518c0`..`0x4d51cc0`), and what Rust types sit behind `hv`, `bh`, `ha`, `n`, `vts`, `hf` and `oqf`?
