# RE-001: What do the #94 and #115 FDE gaps that are not pure `0xcc` hold, and what reaches them?

- Component ID: none (binary-wide function-map input; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (baseline);
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (separate target, reported side by side, no #94 addresses reused)
- Source commit / reference commit: hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (not used by this packet)
- Claim status: observation (gap byte classes, decoded islands, validated
  references); inference (entered islands are code without unwind data);
  unresolved (library origin, function boundaries inside islands, computed targets)
- Scope included: the 134 (#94) and 133 (#115) same-section `.text` gaps from
  [RE-001 FDE extents](../RE-001-fde-extents/README.md) that contain bytes other
  than `0xcc`; their decode; direct-branch, RIP-relative, relocation and
  relocation-slot references into their non-fill bytes.
- Scope excluded: int3-only gaps (already accounted), `.init`/`.fini`/`.plt`,
  CFG recovery, register-indirect and jump-table targets, library attribution,
  component ownership. RE-001 is **not** complete.

## Reproduce

Platform: Ubuntu 24.04.3 LTS under WSL2 (Linux 6.6.87.2 x86_64), Python 3.12.3,
GNU objdump 2.42. Static decoding only; no captured binary is executed.

```sh
make verify
make fde-gaps   # writes work/index/node-{94,115}-gap-classes.{tsv,json} and -gap-xrefs.tsv
```

`tools/fde_gap_classes.py` verifies the artifact digest, takes the gaps from
`fde_extents.py` and, for each gap that is not pure `0xcc`:

1. Decodes it with `objdump -d -z --insn-width=15` from the gap start to 15 bytes
   past its end, because objdump prints an instruction cut at `--stop-address`
   as `.byte`. The gap end must be an instruction start.
2. Treats `int3`, `nop*` and `xchg %ax,%ax` as fill. An independent byte matcher
   (int3, or canonical NOPs with zero displacement after `0x66` and `0x2e`
   prefixes) must agree on where leading fill stops.
3. Splits the remaining bytes at `int3` into **islands**, with fill trimmed at
   both ends.
4. Streams `objdump -d -z --no-show-raw-insn -j .text` once to collect direct
   branches and RIP-relative operands whose targets fall in an island. It also
   reads `R_X86_64_RELATIVE`/`IRELATIVE` addends in `.rela.*` and RIP-relative
   reads of those relocation slots.
5. Re-decodes each code source from the start of its FDE (or island) and keeps
   it only if the same instruction appears at the same address.

An **entry** is a validated reference to an island instruction start from FDE
code or a relocation slot. It must be a branch, or a pointer to `endbr64`.
References that start inside an island never count, because island bytes may
be data decoded as instructions.

Generated outputs (byte-identical on a second run; SHA-256):

| File | Rows | SHA-256 |
| --- | ---: | --- |
| node-94-gap-classes.tsv | 134 | `a6f7cd84130e1b4807f3317e206f46c2ca90966b3ac201236ba4f8fada452212` |
| node-94-gap-xrefs.tsv | 88 | `eca34cfb4fe04f9711ae7219f294e4fd151c6cc75c527e381b2225bed7395cea` |
| node-94-gap-classes.json | — | `f453dc49d8bb221cab4829875be4e52c5bc2e8834329b1cbaacc843e0c56c592` |
| node-115-gap-classes.tsv | 133 | `068350b03114f8fa08cf33d235bab3d1a4e1484d9cf5ac9d137789fd9e24c60a` |
| node-115-gap-xrefs.tsv | 93 | `22c3703b7f722bc7e450db20e09a1c9c50553b20495d0ca915cda56279896246` |
| node-115-gap-classes.json | — | `f2c8b3ac8140995e1537856eb839a02e27091090e9b52b044fc94aba80beae3e` |

All six files are retained beside this record. The xref TSVs list every
reference except jumps and pointer operands inside the same island; those are
counted per island in the JSON.

## Evidence

Coordinates are linked virtual addresses from the ELF section table.

| Observation | #94 | #115 |
| --- | ---: | ---: |
| Gaps that are not pure `0xcc` (count / bytes) | 134 / 65,584 | 133 / 65,949 |
| Fill only: `int3` and canonical NOPs | 129 / 2,091 | 128 / 2,057 |
| NOP fill then four `00` bytes | 1 / 6 | 1 / 6 |
| Gaps with other bytes | 4 / 63,487 | 4 / 63,886 |
| Byte matcher vs objdump disagreements / gap ends inside an instruction | 0 / 0 | 0 / 0 |
| Islands with a validated entry (count / bytes) | 7 / 63,208 | 7 / 63,208 |
| Islands reached only by a pointer to a non-`endbr64` address | 0 | 1 (334 bytes) |
| Unreferenced islands that are not all zero bytes | 0 | 0 |
| Validated entries (distinct targets) | 16 | 16 |
| `endbr64` in islands / of them without a validated entry | 15 / 0 | 15 / 0 |
| Validated reads of the relocation slots | 45 in 11 FDEs | 42 in 10 FDEs |

Islands (#94 first; same-size #115 island in the last column):

| #94 island | Bytes | Entries | How the entries are reached | #115 |
| --- | ---: | ---: | --- | --- |
| `0x1343cb0..0x1343d69` | 185 | 2 | RELATIVE slots in `.init_array` and `.fini_array`; one internal `call 0x1343cb0` | `0x1419330` |
| `0x54a5500..0x54a8358` | 11,864 | 3 | RELATIVE slots in `.got`; each slot read by validated FDE code (`call *slot(%rip)` or `mov`) | `0x633a680` |
| `0x54a8380..0x54aacdd` | 10,589 | 3 | as above | `0x633d500` |
| `0x54aad00..0x54ad28c` | 9,612 | 1 | as above | `0x633fe80` |
| `0x54ad2c0..0x54b41da` | 28,442 | 4 | as above | `0x6342440` |
| `0x5631580..0x5631ef2` | 2,418 | 2 | 4 `lea …(%rip),%r9` in FDEs `0x55ec060` and `0x55ec1a0`, both targets `endbr64` | `0x62e4700`, byte-identical |
| `0x5660010..0x5660072` | 98 | 1 | 25 direct calls from 6 FDEs | `0x63f0960`, byte-identical |
| `0x5656880..0x5656884` | 4 | 0 | all zero bytes, no reference | `0x5d249c0`, byte-identical |

- **Every entered island decodes cleanly:** 0 invalid encodings in all seven
  islands of each node. Every entry is reached from FDE code or a pointer slot.
  The four large #94 islands decode to 10,636 instructions.
- **#115 holds an extra data island**, `0x633a500..0x633a64e`:
  - It starts with 64 zero bytes.
  - At `0x633a540` follow 24 little-endian `u64` values equal to the 24
    Keccak-f[1600] round constants (`0x1`, `0x8082`, `0x800000000000808a`, …).
  - At `0x633a600` follows the NUL-terminated literal
    `Keccak-1600 absorb and squeeze for x86_64, CRYPTOGAMS by <appro@openssl.org>`.
  - Its only references are two `lea …(%rip),%r15` in FDEs `0x633a2e0` and
    `0x633a380`, both pointing at `0x633a540`.
  - Decoding these bytes as code gives 4 invalid encodings and 6 spurious
    branches. Of these, 2 hit instruction starts in the next island and 4 hit
    the middle of instructions. They are listed as `from_other_island` and
    `target_not_instruction_start`, and none of them counts as an entry.
  - The literal does not occur anywhere in the #94 file.
- Analysis was complete for both binaries: a single full `.text` sweep plus
  per-gap and per-source decodes, under 40 s per node. The binaries are
  stripped, so no island is named.

Inference, kept apart from the observations above: the 16 entries are code that
has no unwind data. They are reached by direct calls, address-taken RIP
operands, init/fini array slots, or GOT slots read by validated calls. An island
is not a function: `0x54ad2c0` has four entries. Whether the islands are
hand-written assembly or startup objects, and which library emitted them, is not
established here.

## Implementation and comparison

No Rust implementation or binary comparator: this packet is deterministic offline
tooling and static observation. `tests/test_fde_gap_classes.py` has 14 tests.
Three of them run GNU objdump over the synthetic ELF from `tests/test_fde_extents.py`:

- a direct call from an FDE enters an island, and a jump into the middle of
  `endbr64` is rejected;
- a stray byte before an FDE desynchronizes the linear sweep, and the false
  `call` it shows inside a `movabs` immediate is `source_not_confirmed`; the
  gap end inside that instruction is reported;
- an island with no reference is `unreferenced`, and a NOP-only gap is `fill`.

The other tests cover the objdump line parser, fill rules, the byte matcher,
island splitting and trimming, branch and RIP operand forms with and without
symbols, slot reads, relocation types, the `.tbss` overlap and every reference
role.

Thirteen deliberate defects each fail these tests:
- an island source counted as an entry;
- a pointer without a landing pad counted as an entry;
- `.tbss` chosen as a slot section;
- no int3 split;
- trailing fill left untrimmed;
- NOP displacement ignored;
- `xchg %ax,%ax` not treated as fill;
- symbol-less targets missed;
- mid-instruction targets accepted;
- no FDE re-decode;
- no lookahead past the gap;
- slot reads ignored;
- every relocation type kept.

## Results and limitations

- Every byte of the #94 gaps that are not pure `0xcc` is now accounted for
  (65,584):
  - 2,097 bytes are in the fill-only and zero-byte gaps;
  - 279 are `int3`/NOP fill around the islands in the other four gaps;
  - 63,208 are in seven islands that have validated entries.

  #115 closes the same way (2,063 + 344 + 63,208 + 334 bytes in the data island).
- Islands are decoded byte ranges between `int3` runs, **not validated function
  boundaries**.
- References are direct branches, RIP-relative operands and RELATIVE/IRELATIVE
  relocations. Computed, register-indirect and relative jump-table targets are
  not followed, so an address with no listed reference is not proven
  unreachable.
- A linear sweep can miss a source when it is out of sync at that address. The
  re-decode only prevents false sources; it does not find missed ones.
- No progress gate is requested; every component gate stays false.

Next question: do the four large islands in each node differ only in their
RIP-relative displacements? Which CPU-feature checks in the slot-reading FDEs
choose among the 11 GOT-slot entries?
