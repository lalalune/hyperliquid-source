# action-wire: rmp_signable suffix and signing-domain leads (#94)

- Component: `action-wire`, a component-map bounded packet related to RE-005.
- Artifact: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source revision: unavailable in this checkout (no `.git` metadata). Provenance
  records the can1357 repository revision `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  the locally inspected inferred lead `l1/action/rmp_signable.rs` has SHA-256
  `c8e33b318a4e35aaed0cdc16b6b18f7022207920181ab2a73dad32ab4936a4f8`.
  Its current content is not independently established as that revision. It is
  unlicensed inferred reference material, used only as a lead.
- Status: observations and bounded inference; no full signing implementation,
  action-wire mapping, Rust build, or component gate requested.
- Scope excludes bincode varint, node #115, visor, execution, and signing.

Run outcomes for this contribution are also summarized in `RESULT.md`.

## Reproduce

From repository root, Linux x86-64, Python 3.13.5 and GNU objdump 2.44:

```sh
python3 tools/rmp_signable_path.py --out research/work-items/action-wire-rmp-signable-94/
python3 -m unittest tests.test_rmp_signable_path -v
python3 research/work-items/action-wire-rmp-signable-94/verify.py
objdump -d --start-address=0x333f240 --stop-address=0x333f686 artifacts/node/94/hl-node
objdump -d --start-address=0x37eb2d0 --stop-address=0x37eb702 artifacts/node/94/hl-node
objdump -d --start-address=0x3984fe0 --stop-address=0x39853ec artifacts/node/94/hl-node
```

The three objdump outputs, concatenated in order, are retained verbatim in
`objdump-excerpts.txt`; labels printed as offsets from unrelated dynamic symbols
are objdump's nearest-symbol annotations, not recovered function names. The
Python generator is stdlib-only and uses `tools/info_request_path.py` ELF helpers
(SHA-256
`ffe4f98ba84648f6ffa1fdaca288799cc62d51fa7d089c82fb28cba77c1d88d1`).
It regenerates `rmp-signable-path.json` byte-for-byte
(SHA-256 `3c1edd32f4ad2805bccb6216fd94a061087972896fdb0bdd61342a1b4094d85a`).
The manifest covers packet files except itself; `verify.py` validates the
manifest and independently regenerates the JSON. It needs no objdump; the
optional binutils unit test checks instruction starts. Different objdump
versions may format a fresh excerpt differently. No target executable is run.

## Evidence and observations

All addresses are original ELF virtual addresses, ranges half-open. This PIE's
selected FDE start `0x333f240` has file offset `0x333e240`; path VA `0x1f3237`
and diagnostic VA `0x58c079` have identical file offsets. The Location slot
`0x56e9c08` has file offset `0x56e7c08`. No load base has been added.

The `.rela.dyn` RELATIVE relocations and 24-byte Location-shaped records in
`.data.rel.ro`, filtered to first-party `.rodata` paths, yield exactly three
records for `/home/ubuntu/hl/code_Mainnet/l1/src/action/rmp_signable.rs`;
all report line 14, column 55. The path is an inventory prefix match. The
candidate RIP LEAs have been checked as instruction starts using objdump from
the enclosing FDE starts. The FDE table supplies bounds, not source function
names or a complete function census.

| Location VA | RIP LEA instruction VA | owning FDE [start, end) |
| --- | --- | --- |
| `0x56e9c08` | `0x333f5fd` | `0x333f240`–`0x333f686` |
| `0x56f3b98` | `0x37eb679` | `0x37eb2d0`–`0x37eb702` |
| `0x570da60` | `0x3985373` | `0x3984fe0`–`0x39853ec` |

Within the first FDE, `0x333f5ef` LEAs `0x58c079`, and `0x333f60c` supplies
length 43: ``called `Result::unwrap()` on an `Err` value``. This generic
error diagnostic and the Location are passed on the same failure path; it is
not a signing-specific string. Raw full-file byte search finds zero occurrences
of the reference lead `connectionId`; this agrees with the imported literal
classification `unanchored`. Absence of those contiguous bytes does not prove
that the corresponding field or behavior is absent.

On the success path of FDE `0x333f240`, the following instruction starts and
bytes are preserved in JSON and the complete disassembly:

- `0x333f2c6` loads eight bytes from context offset `0x10`; `0x333f2de`
  byte-swaps and `0x333f2e6` stores them at the current buffer end, advancing
  length by eight. On x86-64 this writes the loaded numeric value big-endian.
- `0x333f2f3` tests context byte `0x18` against one; `0x333f30d` writes tag
  one and `0x333f339`/`0x333f341` copy four plus sixteen bytes from context
  offset `0x19`; the other branch writes zero at `0x333f36a`. Growth branches
  and returns to the stores are in the full excerpt.
- A separate context option test at `0x333f34f`/`0x333f379` can write a
  zero byte at `0x333f393`, followed by the byte-swapped eight-byte value at
  context offset `0x08` (`0x333f3a0`, `0x333f3b5`, `0x333f3bd`).
- After these stores the buffer pointer and length are passed at `0x333f45d`
  through RELATIVE slot `0x576e1d8` to `0x4f59a10`; a later call at
  `0x333f48b` uses slot `0x576e1e0` to `0x4f59e40` with output length 32.
  Their actual semantics are not established by this packet.
- `0x333f4d2` compares the saved input byte with three; `sete`, move `0x62`,
  subtract, and store at `0x333f4d6`–`0x333f4dd` write ASCII `a` for equal
  and `b` otherwise. `0x333f519` stores immediate `0x539` (1337) in the result.

## Inferences and unresolved questions

The Location, context offsets, append ordering, endianness and conditional
20-byte copy together support identifying this FDE's sequence as the reference
lead's nonce/vault/optional-expiry suffix path. Names `nonce`, `vault`, and
`expiry`, source-domain purpose, and the `1337` field's role remain inferred;
the machine code alone does not name them. The reference suggests Keccak
connection-id assembly, and the helper calls consume the buffer and produce 32
bytes, but no helper closure or algorithm identity was validated here. Neither
a complete EIP-712/signature domain nor the `connectionId` serde layout is
established. We have not established action serialization, all possible
monomorphs, callers, output ABI, data dependencies, or runtime behavior.

The Location census is complete only for the stated relocation/path filter;
raw opcode-pattern LEAs can have false positives in general, although the three
reported sites were separately disassembled. No broad CFG recovery, exhaustive
xref census, function coverage denominator, or binary equivalence is claimed.
The reference's `reserve(extra_len)` is not established as a single pre-reserve
operation; capacity checks/growth calls are visible instead. No implementation,
build, raw/normalized comparison, helper/data/relocation closure, fixtures or
execution-based boundary cases have been measured.

Controls reject target digest changes, corrupted code/branch/Location/LEA and
diagnostic bytes, altered or incomplete manifests, and off-by-one FDE bounds;
the tests also compare regenerated JSON under multiple hash seeds. `make doctor`
passed; `make verify` authenticated artifacts/signatures but failed on missing
`research/imported/visor.dis.txt`; `make reproduce` and `make catalogue-check`
passed. No progress data or generated catalogue was edited. The next question
is to independently identify the two indirect hash helpers and follow their
caller/return dataflow with a complete static CFG and checked relocations.
