# constants: Which global_constants literals does #94 carry, and how does code reach them?

- Component ID: `constants` (path rule `global_constants/*`)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: hyperliquid-source
  `6fb86319763b30860f92b9da746cbe4f9b637573`; can1357-hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation (pool entries, xrefs, 76-entry table, layout,
  default discriminant); inference (function names and roles); unresolved (the
  unnamed neighbour functions, #115 drift, every behaviour not exercised)
- Scope included: the two reference files `global_constants/aws_name.rs` and
  `global_constants/static_config.rs`, every string the component owns that is
  present in #94, the `AwsName` discriminant order, the `StaticConfig` layout,
  and all direct code references to those strings.
- Scope excluded: the rest of the node, runtime behaviour, buildability, any
  comparator against compiled Rust, #115 and the visor. No gate is claimed.

## Reproduce

Platform: macOS 26.4.1 arm64, Python 3.12.13, Apple LLVM 17.0.0 `objdump`.
Static parsing only; the captured binary is never executed.

```sh
shasum -a 256 artifacts/node/94/hl-node
python3 tools/constants_scan.py --release 94 --out research/work-items/constants
python3 tools/constants_scan.py --release 94 --check research/work-items/constants
python3 -m unittest tests.test_constants_scan -v
```

The tool verifies the artifact SHA-256 against `provenance/artifacts.json` and
fails closed on a digest mismatch, a missing/duplicated pool entry, a table run
that is not 76 entries, or any order difference against the pinned reference
list. A second run produces byte-identical outputs.

Retained outputs:

| File | Content | SHA-256 |
| --- | --- | --- |
| `constants.json` | machine-readable record | `f96c97435f2c1195cc4a05a578725e575950d7cb14a2e191a6d13f2d49cf33db` |
| `strings.tsv` | 2 seeds + 76 table entries | `5c9a65c930f0645661e96fc7e5a59c51baff38b86d0cd2d424e170f0c44ed65b` |
| `xrefs.tsv` | 9 reference sites | `d0da5edc9b6f7156b331d32db5d5dc7dceae04777b53fbed65d3d4daed979e8b` |
| `context.txt` | raw hex around each cited address | `373eb95d9c81ec837f3e40a5f0374c9783e01afb0e769a93a6a2031aa0f58e0b` |
| `disassembly/select_cham_dir.txt` | window `0x164f810`–`0x164f970` | `9545e0535a5ff09d7bdddc3e135ad0a1eb1babd2ef88e156a55b739ebddcb296` |
| `disassembly/read_static_config_aws_name.txt` | window `0x164fb80`–`0x164fea0` | `42b6cd41f85042a5d11f6c2069cda7ed042b4b7c8dbc0b78f0d90fd9cb7e1e28` |
| `disassembly/static_config_load.txt` | window `0x164ff00`–`0x1650060` | `77151280e6f5b7a9952adc6ed3bbaaa723cdb057f45e4fa7c114170d7fa49c40` |
| `disassembly/aws_name_table_fallbacks.txt` | the three table xref sites | `6e2f25aa00fd3dec98934d00f81d959a741872585dcaeb0e6f887ad178389d83` |

Coordinates are linked virtual addresses (VA). `.rodata` has VA == file offset
in this link; `.text` is offset by `0x1000`, so `xrefs.tsv` carries both the
site VA and its file offset.

The xref site coordinates and generated output hashes were corrected in [RE-015 xref instruction starts](../RE-015-xref-instruction-starts/README.md). The original scanner reported the opcode byte after the REX prefix; the corrected sites point at the first byte of each reported instruction. Target addresses, instruction bytes, table contents and window bounds are unchanged.

## Evidence

### The seeds are pool entries, not plain literals

Both seeds sit in a compact format-argument pool. An entry is
`[alignment marker] [length] [bytes] 00`; the marker `0xc0` carries 0–6 padding
bytes in its low three bits, zero here. The module's own builder at `0x1344760`
decodes that shape: a byte with bit 7 set is consumed as padding flags, the next
byte is the piece length. All path entries below use the same marker.

| Seed | Text VA | Entry VA | Entry bytes | Xref site | Window |
| --- | ---: | ---: | --- | ---: | --- |
| `/static_config` | `0x1ef5f7` | `0x1ef5f5` | `c0 0e` | `0x164fbae` | `0x164fb80`–`0x164fea0` |
| `/cham` | `0x1fc0ee` | `0x1fc0ec` | `c0 05` | `0x164f840` | `0x164f810`–`0x164f970` |

The second byte of each entry equals the text length (14 and 5), and the text
is NUL-terminated. A naive search for the text address finds no xref at all:
both code sites point two bytes before it. `NvTestnet` at `0x2180ff` is the same
trap in another form: it is a slice of one concatenated name blob and has no
direct xref either; its canonical reference is the pair at `0x5668488`.

### The 76-entry `AwsName` table

`.data.rel.ro` holds 76 consecutive 16-byte `(pointer, length)` pairs at
`0x5668288`, every pointer fixed by an `R_X86_64_RELATIVE` relocation. The
strings are exactly the 76 names of the pinned reference array, in the reference
order, so the table index equals the `repr(u8)` discriminant 0–75. 62 point into
one contiguous `.rodata` blob (`0x217ff1`–`0x21822e`, names from `0x21800b`); the other 14 are
deduplicated to earlier copies of names the compiler needed elsewhere
(`EaMm`, `FBinSpot`, `FBinPerp`, `FHuobiPi`, `FCobSpot`, `FKraSpot`, `OBinSpot`
and the seven `*HlPerp` names).

Independent count checks in the same blob:

- `variant index 0 <= i < 76` at `0x218244` — the serde variant bound.
- `LocalSandboxTestnetMainnet` precedes the names, then
  `variant index 0 <= i < 4` at `0x21822b` — the four `HlChain` variants.

`AWS_NAME_VARIANTS: [AwsName; 76]` is *not* materialized: no contiguous
`00 01 … 4b` byte run exists in the file.

### Default and layout

`DEFAULT_AWS_NAME = AwsName::NvTestnet` is discriminant 32. The fallback path of
`read_static_config_aws_name` materializes it as `movb $0x20` (`0x164fc56`);
`parse_static_config_aws_name` uses `movl $0x20` (`0x164fdac`) as the `None`
sentinel. `StaticConfig` is returned by value in a `0x49`-byte buffer: three
24-byte `String`s and the `AwsName` byte at `+0x48` (`0x164ffc2`), matching
`home_dir`, `cham_dir`, `code_dir`, `aws_name` in that order.

### Code references

All nine RIP-relative references are direct `lea` operands; there are no
indirect table walks in the scan set.

| Target | Target VA | Site | Window |
| --- | ---: | ---: | --- |
| `/cham` | `0x1fc0ec` | `0x164f840` | `0x164f810`–`0x164f970` |
| `/hl` | `0x1ed055` | `0x164f88d` | `0x164f810`–`0x164f970` |
| `/static_config` | `0x1ef5f5` | `0x164fbae` | `0x164fb80`–`0x164fea0` |
| `/code` | `0x1ed05b` | `0x164ff5f` | `0x164ff00`–`0x1650060` |
| `cham_dir does not exist: ` | `0x1f6798` | `0x164ffe8` | `0x164ff00`–`0x1650060` |
| `could not create ` | `0x201ea5` | `0x164f9a4` | `0x164f970`–`0x164fa80` |
| `AWS_NAME_STRINGS` | `0x5668288` | `0x13f5891` | `0x13f4360`–`0x13f5980` |
| `AWS_NAME_STRINGS` | `0x5668288` | `0x13f61cd` | `0x13f5980`–`0x13f6410` |
| `AWS_NAME_STRINGS` | `0x5668288` | `0x13f6c2b` | `0x13f6410`–`0x13f6dc0` |

The three table sites are the `unknown_variant` fallbacks of three string→variant
parsers at `0x13f4360`, `0x13f5980` and `0x13f6410`; each builds
`unknown variant … expected one of …` through the shared helper `0x13b5050`
with the table and the bound 76.

Two clusters carry the component:

- `0x13f4360`–`0x13f7030` (`aws_name.rs`): the three parsers and their jump
  tables; entry lengths 2–13 are dispatched from `0x217b80`, `0x217d30` and
  `0x217d60`.
- `0x164a059`–`0x1650300` (`static_config.rs`): `select_cham_dir`
  `0x164f810`, `is_existing_dir` `0x164f710`, `home_dir_string` `0x164fa80`
  (calls `std::env::home_dir` at `0x158f430`), `read_static_config_aws_name`
  `0x164fb80`, `StaticConfig::load` `0x164ff00`, the `CreateDirError` drop glue
  `0x164f6b0`, the `could not create` panic helper `0x164f970`, and the
  `JsonCursor`/UTF-8 helpers from `0x164a059` to `0x164e930`.
  `parse_static_config_aws_name` is `0x164d630`, called from `0x164fca8`.

Window bounds are the nearest `.eh_frame_hdr` start at or before the site and
the next start. They are index bounds, not decoded FDE extents (RE-001 is
still open).

### Negative controls

- Direct xrefs to the text addresses `0x1ef5f7` and `0x1fc0ee`: 0 and 0.
- Xrefs to any individual table slot (`0x5668288 + 16*i`): only the base has
  xrefs; no slot is referenced alone.
- `an AWS name variant or an object with an aws_name field`: 0 occurrences, even
  as a fragment (`AWS name variant`, `aws_name field`).
- `home directory not found`: 0 occurrences, also for `home directory`.
- The imported literal classifier scored 65 grounded and 2 unanchored for this
  component. It skips literals shorter than 8 bytes, so 13 real variants
  (`Ec`, `Ea`, `Ea2`, `Ea3`, `EaMm`, `Eb`, `Ed`, `Ee`, `Sa`, `Sb`, `Sc`, `Sd`,
  `FHlPerp`) never entered its denominator. The table above is not length-biased.

## Implementation and comparison

No Rust is implemented here, so no build, raw/normalized body count or helper
closure is claimed. Reference agreement and disagreement, item by item:

| Reference fact | #94 | Basis |
| --- | --- | --- |
| 76 `AwsName` names, order, discriminants | agree 76/76 | table `0x5668288`; bound `0x218244` |
| `CHAM_DIR_SUFFIX`, `HL_DIR_SUFFIX`, `CODE_DIR_SUFFIX`, `STATIC_CONFIG_SUFFIX` | agree | `0x1fc0ec`, `0x1ed055`, `0x1ed05b`, `0x1ef5f5` |
| `DEFAULT_AWS_NAME = NvTestnet` (32) | agree | `0x164fc56`, `0x164fdac` |
| `StaticConfig` field order and size | agree, `0x49` bytes | writes at `+0x00/+0x18/+0x30/+0x48` |
| `home_dir_string` via deprecated `env::home_dir` | agree | call to `0x158f430` |
| `cham_dir does not exist: {}` / `could not create {}: {}` | agree | `0x1f6798`, `0x201ea5` |
| `AWS_NAME_VARIANTS` const array | absent | no `00…4b` run |
| `home directory not found` | absent | 0 occurrences |
| `expecting` text | absent | 0 occurrences |

## Results and limitations

Machine-readable totals: 2/2 seeds resolved to one pool entry each; 76/76 table
entries match the reference order; 14/76 names are deduplicated copies, 62/76
sit in the blob; 9 xref sites over 7 targets, 0 unresolved direct xrefs;
0/2 direct text-address xrefs; 0/2 unanchored strings found.

What this does not establish: that the table is `AWS_NAME_STRINGS` by symbol
(there is no `.symtab`), that any function has the reference's exact signature
or semantics, that the parsers accept/reject the same inputs, or that the
discriminants are used as `repr(u8)` outside the table. Neighbour functions
inside both clusters are unnamed and only bounded. #115 was not scanned. All
four component gates stay false; this is a partial packet and requests no gate.

Next question: does the `parse_static_config_aws_name` state machine at
`0x164d630` implement the same escape rejection (`\` → `None`) and the same
externally-tagged `{"Variant": null}` form as the reference, and where does the
`0x20` `None` sentinel diverge from a real `NvTestnet`?
