# RE-001: recover node94 packed IPv4 translation and its eight fixed pairs

- Component: `consensus`, bounded function/range/data recovery under RE-001.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  `node/consensus/node_ips.rs` supplied an unverified address lead only. No
  unlicensed implementation was copied. Rust and verifier code are independently
  authored from the retained instructions and data.
- Question: which packed inputs are translated, which direction is selected,
  what table is searched, and what value does the helper return?
- Claim: observed static control/data flow plus an independent bounded Rust
  implementation. No component gate is advanced.

Before this packet, the repository had an imported normalization lead but no
validated analysis of this helper, its initializer or its direct caller.
This packet resolves the selected value computation and binds the eight-row
table to actual constructor instructions. It does not claim a complete node-IP
parser, firewall, network configuration or consensus implementation.

## Evidence and result

All addresses are ELF link-time virtual addresses. Ends are exclusive. Each
range is an exact `.eh_frame` FDE and is fully decoded by GNU and LLVM objdump.
An FDE and static decoding do not prove every possible runtime entry point.

| Role | Range | File offset | Bytes |
| --- | --- | --- | ---: |
| Translation helper | `0x45c3ae0..0x45c3d19` | `0x45c2ae0` | 569 |
| Eight-row constructor | `0x45be020..0x45be0cf` | `0x45bd020` | 175 |
| Direct caller | `0x487dcc0..0x487e2f8` | `0x487ccc0` | 1,592 |

The denominator is these **2,336 retained original bytes**. This is a static
evidence denominator, not reconstructed matching bytes. `records.json` binds
their hashes, FDE/CIE addresses, instruction obligations, table records and
RELA records. `fdes.readelf.txt` is the independent GNU unwind cross-check.
The long C++ labels printed by objdump are nearest exported symbols, not
identified names for these Rust bodies.

The helper masks its first register to five bytes. Its low byte is a tag; the
next four bytes supply the comparison word. It tests only bit 0 of the tag:
odd values return the retained five bytes without entering either table path.
The first two address bytes classify exactly `10/8`, `172.16/12` and
`192.168/16` as private. The 172 arm tests the second octet's upper nibble.
There is no additional loopback, link-local, unspecified or multicast rule in
this selected classifier.

| Low mode byte | Input class | Route |
| --- | --- | --- |
| Zero | Private | Search first DWORD of each row; return second DWORD |
| Zero | Other | Keep input |
| Nonzero | Private | Keep input |
| Nonzero | Other | Search second DWORD of each row; return first DWORD |

Each search walks records in increasing offsets with an **8-byte stride** and
returns on the first equality. Empty tables and misses keep the original tag
and address. Matches construct a new address word with tag **zero**. The table
loaded by this capture contains no duplicate column values; first-match
precedence is a property of the recovered loop, not an observed duplicate in
production. Upper input bits are never returned.

The original reference models the map with two keyed trees and discusses V6
and local-node cases. This packet establishes only the packed five-byte numeric
contract. In particular, an odd low byte is a bypass test, not proof that the
helper accepts or returns an IPv6 value. The direct caller separately compares
the returned low byte with 2; the complete meaning of that sentinel is outside
this projection.

### Table construction

The RELATIVE relocation at `0x5786570` points to `0x45be020`. That constructor
requests 64 bytes, stores eight successive 64-bit immediates and returns
`{8, pointer, 8}`. Splitting each store into two little-endian DWORDs yields:

| Row | First/private-side IPv4 | Second/public-side IPv4 |
| --- | --- | --- |
| 0 | 172.31.8.148 | 43.206.47.239 |
| 1 | 172.31.8.11 | 3.115.82.128 |
| 2 | 172.31.0.143 | 54.250.198.159 |
| 3 | 172.31.5.30 | 54.64.115.135 |
| 4 | 172.31.3.250 | 18.177.47.248 |
| 5 | 172.31.1.142 | 18.182.46.12 |
| 6 | 172.31.14.167 | 43.206.157.116 |
| 7 | 172.31.12.35 | 43.207.136.220 |

These are immutable historical data observations in the target, not assertions
about current endpoints. No address was contacted. The allocation and failure
helpers are retained as external obligations, not executed or reimplemented.

### Initialization boundary and callers

Only inputs requiring translation reach the global state at `0x5786588`.
Zero state reads the pointer/count at `0x5786578/0x5786580` directly. Nonzero
state takes a deferred path through GOT slot `0x576e8b8`, whose relocation is
`0x4ee3b20`, and then re-reads the count. Both deferred paths pass the same
descriptor at `0x572b030` and source Location at `0x572b058`. The latter binds
`library/std/src/sync/once.rs:219:20` under the compiler hash retained in
`records.json`. The initial captured state word is 3; its full concurrent
transition semantics are not established here. The descriptor's two callback
relocations are recorded; their full behavior and the Once callee are excluded.

A scan of all `.text` E8 encodings yields two candidate calls, at `0x487ddef`
and `0x487e200`. Both are confirmed instruction boundaries in the complete
caller FDE. There are no `.rela.dyn` entries targeting the translation helper;
this is not a census of every possible indirect or tail call. At both sites
the caller constructs the first register from DWORDs at input `+0x4c/+0x50`
and loads a single mode byte. It stores the result as a DWORD at output `+0x14`
and a byte at `+0x18`, corroborating the five-byte output. The caller's tree,
iterator, allocation and collection behavior is retained for context but not
reconstructed.

## Reproduce

Python 3.10+ uses existing repository ELF/FDE parsers. GNU objdump/readelf
2.47.20260726 and LLVM objdump 18.1.4 produced the independent static exports.
Rust 1.94.1 (`e408947bf`, 2026-03-25) builds the standalone module. The observed
host was Darwin arm64; the original target remains Linux x86-64. No Ghidra
profile, captured execution, emulator, network, keys or live fixture is used.

```sh
make doctor verify catalogue-check reproduce
python3 research/work-items/RE-001-node94-ip-translation/verify.py --controls
python3 -m unittest discover -s tests -p test_node94_ip_translation.py -v
# Standalone build/test/repeated-build commands:
cat src/node94-ip-translation/README.md
make test
```

On this macOS host GNU binutils and LLVM must both precede system tools:
`PATH=/opt/homebrew/opt/binutils/bin:/usr/local/opt/llvm/bin:$PATH`.
The stock Apple objdump is not the GNU provider required by repository checks.
The pinned reference's LFS object must be materialized, as required by setup.

To reproduce each static export, substitute the three intervals from the table:

```sh
objdump -d -Mintel --start-address=0x45c3ae0 --stop-address=0x45c3d19 \
  artifacts/node/94/hl-node
llvm-objdump -d --x86-asm-syntax=intel \
  --start-address=0x45c3ae0 --stop-address=0x45c3d19 artifacts/node/94/hl-node
readelf --debug-dump=frames artifacts/node/94/hl-node
```

`--write` regenerates `records.json` after authenticating the full input. The
default mode compares regenerated records and verifies `MANIFEST.sha256`.
The corruption controls bypass both whole-image and per-body digest guards;
14 mutations must fail the instruction, RIP-target or relocation obligations.
They cover direction, prefix masks, lookup column, first-match edge, stride,
value selection, tag clearing, one table immediate, row count and initialization.
The focused tests also bind every Rust table row to the initializer bytes.

## Implementation, validation and limits

[`src/node94-ip-translation/lib.rs`](../../../src/node94-ip-translation/lib.rs)
is safe, allocation-free, dependency-free `no_std` Rust with a new numeric API.
It implements the table-ready returned value using the eight observed rows.
The inlined lookup is distinct from the captured global synchronization and
allocation path. Tests cover all prefix pairs, all tag/mode bytes, captured rows,
private-range boundaries, unchanged inputs and synthetic first-match cases.
Static expectations and local tests are not a runtime differential result.
No original-byte equivalence, Linux cross-build, full ABI or complete helper
closure is claimed. No compiled machine-code bytes are transplanted.

`validation.json` records exact observed checks, tool identities, build hashes
and test inventory coverage. `scope-check.json` records the all-state PR scan
and closest prior work. The known neighboring packets (#702 config gates,
#569 update scheduling, #562 mismatch logging) cover different functions and
questions; no changes to them are needed. Searches cannot rule out undeclared
work or every unmentioned detail in historical patches.

Next close the initializer callback/Once protocol and the caller's ownership
contract before using this projection as a drop-in replacement. Original
concurrency, allocation failure and wider network behavior remain unresolved.
