# RE-005: kind-5 reader and its little-endian wrapper, node94

Static target evidence and a bounded independent Rust contract; no component gate requested. This closes the specific
Reader0x466dad0 gap explicitly excluded by [PR253](https://github.com/lalalune/hyperliquid-source/pull/253),
without changing its u32/u64 work or the merged varint packet. The kind-5 label
means the literal byte5 passed to the error builder, not a recovered Rust type.
No unlicensed inferred source was copied.

Target: node94, SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
All addresses are ELF virtual addresses; file offsets are resolved from actual
sections. FDEs come from the authenticated unwind metadata, not symbol labels.
The pinned inferred reference remains unchanged and is not implementation proof.

| FDE | Range | Observed role |
| --- | --- | --- |
| Reader | 0x466dad0..0x466dc0c | two-word pointer/remaining state; incoming byte selects payload order |
| Wrapper | 0x466be70..0x466bf55 | fixed8 charge gate, fast path when remaining>8, otherwise Reader with dl=0 |
| Error builder | 0x466dac0..0x466dace | writes tag3, byte1=sil, byte2=dl; returns output pointer |

Together these are559 bytes and169 instructions. GNU and LLVM independently
decode the same owned non-executable snapshot and agree on every instruction's
bytes, boundaries and canonical operands. No code/data bytes are masked.
Only snapshot pathnames, equivalent RIP expressions and signed immediate display
forms are normalized; original native listings remain beside this record.

## Result and cursor contract

Reader tags0..250 return the tag value. Tags251/252/253 read2/4/8 payload bytes,
in the order selected by incoming dl (zero=little, nonzero=swapped). Nonminimal
representations are accepted by these instructions. Tag254 writes bytes[3,5,4];
tag255 writes[3,5,12]. These are raw observations, not recovered Rust enum names.

On a nonempty Reader input, the tag is consumed **before** payload-length or
invalid-tag rejection. A short payload returns tag0 and missing byte count;
only its tag has been consumed. Empty input returns tag0/missing1 without
advancement. Successful decoding consumes1/3/5/9 bytes.

The wrapper is little-endian on both paths. With remaining>8 it reads directly;
an invalid254/255 tag leaves the cursor unchanged. At remaining<=8 it calls the
Reader through RELATIVE slot0x57745d0 and therefore consumes an invalid tag.
The size-dependent error-state difference is retained, not normalized away.

The wrapper's leading32-bit selector enables its gate only when exactly1.
It checks whether counter+8 would overflow, then stores that sum, then compares
it with the limit. Overflow returns tag2 without changing the counter; limit
exhaustion returns tag2 **after** charging8. Both leave the cursor unread.
Other raw selector words skip the gate. Whether those words or dl=255 are valid
Rust-level states is unknown; they are machine-state controls, not API promises.

The model compares24 bytes of output storage and40 bytes of state, prefilled
with a sentinel to detect exact writes and untouched bytes. Those window sizes
and padding are fixture choices, not a claim about initialized Rust fields or
the full enum/object layout. Return-pointer, stack and callee-saved rbx are
also checked. Memory accesses outside the bounded fixtures/data are refused.

## Measurements and controls

28,992 distinct deterministic fixtures compare decoded instructions against
separate byte/cursor/charge equations: every tag and lengths0..18, endian
bytes0/1/255, width boundaries, nonminimal payloads, selector0/1/2, and counter/
limit boundaries. There are zero mismatches,169/169 instructions visited and
both outcomes at all15 conditional-jump/move sites (30/30). This is a finite
model check, not proof of all paths or target execution.

Four calls through the Reader's one declared GOT slot are re-decoded by both
providers from their real containing FDEs. `reader.json` records them and both
four-entry jump tables. This census covers only RIP-relative ff15/ff25 uses of
that slot; it does not claim all direct/aliased calls, inlining or caller logic.
Only the one wrapper above is fully interpreted. Both local callees and their
RELATIVE bindings are closed within these three FDEs.

The9 focused tests include13 actual ELF corruption controls below the identity
check: threshold, tag cursor, short width, success tag, endian direction, kind
byte, error layout, fixed charge, overflow threshold, fast/slow gate, forced
endianness, jump-table swap and actual RELA callee redirection. Both native
providers decode changed instruction bytes; model, bounded-memory or binding
checks reject each. A separate wrong-identity control verifies admission.
Public collection always requires the exact target digest; identity bypass is
only used by these lower-level tests. No expectations or validators were relaxed.

`cases.tsv.gz` has one row per compared fixture, columns: entryVA, payloadHex,
incomingEndianByte, selectorWord, limit, initialCounter, observedOutput24Hex,
observedState40Hex. The two independently calculated byte sequences must agree
before a row is emitted. Gzip has fixed metadata. `toolchain.json` records the
actual host/tool versions; native formatting is provider-specific.

## Reproduce

```sh
# GNU objdump must be on PATH; set LLVM_OBJDUMP when not already discoverable.
python3 -B tools/kind5_reader.py --output work/kind5-new
python3 -m unittest tests.test_kind5_reader -v
python3 -B research/work-items/RE-005-kind5-reader-94/verify.py
make doctor verify test catalogue-check reproduce
```

The collector refuses an existing output directory. It never launches the
captured node, networks, signs, or installs packages. The packet verifier
checks source/file hashes and repeats both native decodes and all fixtures.
This host used Python3.12.10, GNU2.47.20260726 and Apple LLVM17 on macOS15.7.7
arm64. Hosted CI, containers and captured target runtime: NOT RUN. The Rust
component below has its own host-build evidence.
The next question is the caller's actual type/layout ownership and how these
raw error/cursor states are consumed; neither is established by the marker
family or the kind byte. All four serialization gates remain false.

## Executed repository checks

The original static packet at `dbb74f3be862ba16106a44b92d2c39796ec110f9`
passed `make doctor verify test catalogue-check reproduce`:
440 tests in103.621s, no skips; all8 artifact identities,3 public signatures,
37 imports and7 reference pins verify; catalogue and all retained inventory/
classification outputs reproduce. The packet verifier passes. A second full
collection reproduces all5 exports byte-for-byte on the recorded host. These
are local results, not hosted CI or component acceptance.


## Independent Rust decoder contract

The component follows `src/README.md` by living under `src/`. Its Cargo
manifest, lockfile and Rust source/test bytes are unchanged by the relocation.
The retained Rust results and source bindings were regenerated from the new
path; the prior packet is preserved in Git at
`c8d737933d07d90d294e4935afce4df41f7e5a45`.

`src/node94-kind5-reader` implements these three FDEs' observed
byte/cursor/fixed-charge behavior through a safe, allocation-free `no_std`
interface. This closes the initial packet's lack of any Rust implementation.
The original disassembly, integer evaluator, byte equations and compressed
case ledger are unchanged. The new Rust is authored from those authenticated
instructions and packet data without copying unlicensed inferred source.

The new interface does not assert native ABI or source-type recovery. It
keeps the kind byte5 opaque. Its output adapter writes only observed fields;
the fixture's synthetic pointer base and40-byte state window occur only in
its test adapter, not in the library's Rust representation.

```sh
python3 tools/kind5_reader_rust.py --controls --output work/kind5-rust-new
# Or use make kind5-rust once; its default output must not already exist.
```

The runner first authenticates and dual-decodes the same node94 snapshot and
repeats the original169-instruction evaluation. The fresh28,992-row ledger
must equal the retained ledger byte-for-byte before Rust runs. Rust debug and
release each pass7 tests, including the complete corpus with no ignored tests.
Every24 output bytes and40 state bytes match for every row. This validates
the declared finite data contract, not captured execution or all possible
inputs. The default direct Cargo test deliberately ignores that corpus until
its fresh export is supplied; the runner explicitly includes it.

Nine actual Rust-source mutations compile and then fail tests: marker
consumption, payload width, endian direction, the8/9-byte fast threshold,
fixed charge, charge/limit store order, opaque error kind, invalid255 code
and success tag. These do not merely alter expected fixtures. Original13 ELF
corruption controls remain in the static suite. Two clean offline release
builds produce raw-identical `.rlib` archives; hashes and all command results
are in `rust/comparison.json`. This is component build reproducibility, not
identity with the captured ELF. Formatting and Clippy with warnings denied
pass. No packages are installed or fetched.

This host uses existing Rust/Cargo1.88.0 on macOS arm64, GNU objdump2.47 and
Apple LLVM17. The missing whole-node manifests, exact Linux build provenance,
caller/source type ownership and target runtime proof remain unresolved.
The repository's root rebuild toolchains and all four serialization gates
are unchanged. `rust/source-sha256.json` pins the actual compared sources;
`rust/` retains raw test/build/control logs without home-directory paths.

## Separate node115 correspondence

[drift/README.md](drift/README.md) records a bounded RE-014 comparison of the
complete reader, error builder and two node115 wrapper copies. Of eight
FDE-start prefix candidates, four pass the full instruction/relocation/table
comparison and four lookalikes fail. Five real node115 byte/data/relocation
corruptions are rejected below the separate whole-image admission gate.
This is static correspondence with explicit slot aliases, not target execution
or a transfer of the node94 fixture measurements to node115. The original
node94 source, static exports and Rust results remain unchanged.
