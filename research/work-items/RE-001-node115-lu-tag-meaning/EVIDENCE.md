# RE-001-node115-lu-tag-meaning: what decides lu.rs tag 1 vs 3

- Component ID: RE-001 (`base/src/lu.rs` conversion tags, via callee `0x5cf2d30`)
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
  (upstream main, node-115-only migration)
- Claim status: observation (return condition, call-site direction, GOT census,
  Location records, panic strings); inference (Tokio-internal meaning of the
  TLS slot, variant meaning of the `0x160`/`0x240` selection, identity of the
  second argument); unresolved (Rust function name, second-argument pointee,
  `0x5cf3b90` coop-path behavior)
- Scope included and excluded: included — helper body `0x5cf2d30..0x5cf2fef`,
  its FDE/CIE, GOT relocations, the three panic Location records, the 27-site
  GOT census, and the conversion call-site excerpt `0x15d5f37..0x15d5f8e` as a
  cited record. Excluded — #183's claimed conversion body (cited, not
  re-claimed), the helper's callees' internals (mapped as call targets only),
  any Rust reimplementation, any component gate.

## Reproduce

Working directory: repository root of a checkout at the base commit above.
Platform: Linux x86-64. Tools: GNU objdump/readelf (binutils 2.42),
python3 (capstone 5.0.7 for the instruction count only).

```sh
sha256sum artifacts/node/115/hl-node
# a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
objdump -d -M intel --start-address=0x5cf2d30 --stop-address=0x5cf2fef artifacts/node/115/hl-node
readelf --debug-dump=frames artifacts/node/115/hl-node | grep -E "pc=0000000005cf2d30|pc=00000000015d5cb0"
python3 tools/node115_lu_tag_meaning.py
python3 -m unittest tests.test_node115_lu_tag_meaning -v
```

No execution of the node binary, no network, no side effects: the verifier
reads the binary and the packet files only. Section VA→file-offset rules used
throughout (verified against section headers): `.text` offset = VA − 0x1000,
`.rodata` offset = VA, `.data.rel.ro` offset = VA − 0x2000, `.got` offset =
VA − 0x2000, `.eh_frame` offset = VA. RELATIVE relocation addends are
authoritative for `.data.rel.ro` pointer slots whose stored value is zero.

## Evidence

Original addresses are virtual addresses (VA). Validated boundaries: helper
FDE `0x5cf2d30..0x5cf2fef` (703 bytes) from `.eh_frame` section offset
`0x72d65c`, CIE `0x39672c` (`zPLR`); conversion call-site excerpt
`0x15d5f37..0x15d5f8e` (87 bytes) from #183's claimed conversion body
(PR #2106, open), hash-pinned in `records.json` and verified against the
binary directly. Raw disassembly: `helper.objdump.txt` (full body),
`callsite.objdump.txt` (excerpt). Callers: zero direct `E8` callers; 27
indirect call sites through GOT slot `0x64e0858` (list in `records.json`).
Callees: direct `0x5cf1d70` (136B), `0x5cf1d10` (85B), `0x5cead40` (309B);
indirect `0x5ca0d20` (255B), `0x5ce91b0` (769B), `0x5cf3b90` (162B),
`0x1680bd0` (52B), `0x1680e80` (44B), `0x1680cab` (20B); passed function
pointer `0x5cdf410` (71B); thunk `0x5cdf610` (19B) in panic arguments.
Source mapping evidence: three Location records via RELATIVE addends
(`entry.rs:549:30`, `entry.rs:539:9`, `sleep.rs:467:23`) and two Tokio panic
strings (115-byte timers-disabled message, "`\rtimer error: `" fragment).
Analysis was complete over the helper FDE (165 instructions, linear
disassembly, no gaps: the landing pad is contiguous inside the FDE).

## Implementation and comparison

Not yet implemented/measured: no Rust reimplementation is included or claimed.
Comparison performed: the helper body is hash-pinned; the conversion call-site
excerpt is hash-pinned against the binary; GOT relocations and Location
addends are re-read from the binary by the verifier; the GOT census is
recomputed by scanning `.text` for `ff 15` calls resolving to `0x64e0858`.
Corruption controls: unit tests flip the body digest, a table-entry target,
a Location field, and a call-site direction byte, and each must fail.

## Results and limitations

Metrics: helper 703 bytes / 165 instructions, 1 false path, all other
non-panic paths true, 3 panic paths, 27 GOT call sites, 0 direct callers,
3 Location records, 2 panic strings. What passed: verifier exit 0, unit
tests 5/5 (standalone), `make doctor` analysis_ready true, `make verify`
exit 0, `make catalogue-check` exit 0, full `make test` with only the known
pre-existing `test_node115_catalogue` cross-device-link failure (see below).
What remains unknown: Rust function name, second-argument pointee,
`0x5cf3b90` behavior, TLS slot's Tokio-internal meaning, `0x160`/`0x240`
variant meaning. No gate is requested: this packet answers #183's next
question and corrects its "compare helper" gloss; it does not cover a full
component scope. Next question: what the conversion's passed-through context
pointer points to, and what the `0x5cf3b90` coop-path call does with it.
