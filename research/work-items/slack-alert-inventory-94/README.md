# slack-alert-inventory-94: exact-file static evidence

Task: RE-001, bounded `base/src/slack_alert.rs` inventory. Component:
`foundation`, limited to that exact source path. This packet adds only
`tools/slack_alert_inventory.py`, `tests/test_slack_alert_inventory.py` and this
directory. No progress, catalogue or acceptance gate is changed.

Target: node #94, `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The embedded compiler-path prefix is matched byte-for-byte; it is stored as
hexadecimal evidence, never replaced with the analyst's local filesystem path.

## Bounded question and provenance

Which relocation-backed Rust panic Location layouts name this exact file,
which decoded RIP-relative LEAs refer to their slots, which actual unwind
ranges contain those instructions, and which length-bearing literals and
rel32 call edges are established within that scope?

Repository base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
The existing [reference file](../../../references/can1357-hl/base/slack_alert.rs)
is unlicensed inferred material, used only as search hints. Its file digest,
finite error-prefix byte selectors and probe digests are in `inventory.json`.
Absent reference text is not copied into this packet. Plaintext literal
probes are independently checked against the authenticated node bytes.
Reference names, types, algorithms and comments are not accepted semantics.

The decoder derives from repository MIT tooling on local branch
`spot-meta-inventory-94`, commit
`79ab22c585d5b53cbe0eaa82fbd9f0e458d14d38`, path at that commit
`tools/spot_meta_inventory.py`. This new tool contains its own decoder; it
does not require that branch to be checked out. Existing MIT
[ELF](../../../tools/elf_index.py) and [FDE](../../../tools/fde_extents.py)
parsers are read-only dependencies. Their content digests and the producer
digest are recorded in the regenerated inventory.

The catalogue maps this file to foundation but provides no address seed for
it. Imported literal labels indicate global occurrence only; they are not
accepted as code attribution. FDE selection starts with exact-path Location
relocations and focused LEA xrefs. No broad decompilation was performed.

## Reproduce

Run from the repository root with Python 3.10+ and its standard library, the
authenticated target and the pinned reference checkout. Actual validation
used CPython 3.13.5 on Linux x86-64. Packet generation, its tests and its
verifier require no objdump, Ghidra, REA, Java, packages, network, captured
executable or installed disassembler. The repository-wide checks below retain
their existing tooling dependencies. Other platforms/Python versions were not
run here.
The reference is small and read only; the target is mapped read only, and
corruption tests use copy-on-write mappings. Full binary copies are avoided.

```sh
python3 tools/slack_alert_inventory.py --out research/work-items/slack-alert-inventory-94/
python3 -m unittest tests.test_slack_alert_inventory -v
python3 research/work-items/slack-alert-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

The generator overwrites only its JSON outputs after successful analysis.
The verifier checks a closed filename whitelist, packet hashes, target digest,
known target facts, exact JSON regeneration and all generated report tables.
It never silently refreshes hashes or reports. `MANIFEST.sha256` covers every
packet member except itself; `verify.py` and `RESULT.md` are required members.
The tests also run producer and verifier with external process/network calls
blocked. No ambient environment, host identity, timestamp or personal runtime
state is serialized. Embedded compiler paths are target bytes, recorded in hex.

## Method and raw evidence

`inventory.json` records link-time ELF VAs and explicit file offsets, with
exclusive FDE ends. These coordinates are not ASLR addresses. Location
records retain the raw slot, path bytes and RELA entry. The layout is a
pre-relocation zero pointer, u64 path length, u32 line and u32 column;
R_X86_64_RELATIVE supplies the path address. Identical line/column pairs at
different slots remain separate records. Every matching path relocation must
parse; malformed records abort the census rather than disappear.

Actual `.eh_frame` CIE/FDE extents are parsed and cross-checked against the
unwind start table. Raw CIE, FDE and index records plus code hashes are kept.
A pattern search in executable sections only discovers candidate LEAs.
Acceptance requires full sequential decoding from the owning FDE start, exact
RIP LEA decoding and alignment of internal direct branch targets. Unsupported
instructions abort; there is no resynchronization. `instructions.json` retains
all bytes in each selected range as offset/raw/kind rows. This proves a
consistent linear decoding, not CFG reachability or exclusive file ownership.

Literal binding requires an exact scoped LEA target followed by either an
adjacent pointer/qword-length store or a bounded, non-clobbering register
setup ending at a call. Each length must equal the full probe length. The
case-sensitive candidate census searches the entire file. No nearby pool
string, generic panic text, formatter fragment or out-of-scope LEA is promoted.
The reference error probes are fixed prefixes before interpolation, searched
byte-for-byte; their absence does not disprove an operation.

Direct calls require a decoded E8 rel32 at an established instruction boundary
and an exact scoped FDE entry as destination. Internal E9 jumps, direct calls
outside those entries and indirect transfers are accounted separately. The
Location LEAs also retain following instruction context; RIP-indirect pointer
slot addresses are decoded without dereferencing or naming their callees.
No call to a separately named component is claimed.

## Derived census

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 2 |
| decoded_instructions | 6272 |
| diagnostics_absent | 3 |
| diagnostics_bound | 5 |
| diagnostics_probed | 12 |
| diagnostics_unresolved | 4 |
| indirect_calls_unresolved | 382 |
| indirect_jumps_unresolved | 17 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 331 |
| location_leas | 27 |
| locations | 21 |
| pointer_length_anchors | 15 |
| scoped_fde_bytes | 33622 |
| scoped_fdes | 6 |
| scoped_rel32_calls | 6 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 7 |
| unresolved_external_rel32_calls | 224 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

<!-- BEGIN GENERATED LOCATIONS -->
| Location VA | Line:column | LEA sites | Owning FDE starts |
| --- | --- | --- | --- |
| 0x566a8e8 | 24:67 | 0x1458ab3 | 0x1457070 |
| 0x566a900 | 34:13 | 0x1458983 | 0x1457070 |
| 0x566a918 | 41:48 | 0x1458a24 | 0x1457070 |
| 0x566a930 | 15:71 | 0x1458a43, 0x1458a55 | 0x1457070 |
| 0x566a948 | 60:10 | 0x145890b | 0x1457070 |
| 0x566a960 | 51:22 | 0x1449928 | 0x1449410 |
| 0x566a978 | 44:16 | 0x14498e6, 0x14498f3 | 0x1449410 |
| 0x566c5d8 | 24:67 | 0x147b624 | 0x1479d30 |
| 0x566c5f0 | 34:13 | 0x147b4d6 | 0x1479d30 |
| 0x566c608 | 41:48 | 0x147b595 | 0x1479d30 |
| 0x566c620 | 15:71 | 0x147b5b4, 0x147b5c6 | 0x1479d30 |
| 0x566c638 | 60:10 | 0x147be30 | 0x1479d30 |
| 0x566c650 | 51:22 | 0x1479848 | 0x1479330 |
| 0x566c668 | 44:16 | 0x1479806, 0x1479813 | 0x1479330 |
| 0x566d568 | 24:67 | 0x14b432e | 0x14b23d0 |
| 0x566d580 | 34:13 | 0x14b41dd | 0x14b23d0 |
| 0x566d598 | 41:48 | 0x14b428c | 0x14b23d0 |
| 0x566d5b0 | 15:71 | 0x14b42ab, 0x14b42bd | 0x14b23d0 |
| 0x566d5c8 | 60:10 | 0x14b418d | 0x14b23d0 |
| 0x566d5e0 | 51:22 | 0x14ac258 | 0x14abd40 |
| 0x566d5f8 | 44:16 | 0x14ac216, 0x14ac223 | 0x14abd40 |
<!-- END GENERATED LOCATIONS -->

<!-- BEGIN GENERATED FDES -->
| Start VA | End exclusive | Bytes | FDE record VA |
| --- | --- | --- | --- |
| 0x1449410 | 0x1449a79 | 1641 | 0xfcf58c |
| 0x1457070 | 0x145964f | 9695 | 0xfd0e94 |
| 0x1479330 | 0x1479999 | 1641 | 0xfd5500 |
| 0x1479d30 | 0x147bfb3 | 8835 | 0xfd55a0 |
| 0x14abd40 | 0x14ac3a9 | 1641 | 0xfd950c |
| 0x14b23d0 | 0x14b4b89 | 10169 | 0xfda8a4 |
<!-- END GENERATED FDES -->

## Implementation and comparison

No Rust implementation or build is proposed. Cargo lockfile, compiler/linker
flags, two-build comparison, behavioral fixtures, raw/normalized matches and
whole-ELF identity remain unmeasured. No normalization masks are used. Only
the Location relocations and recorded literal/instruction bytes are resolved;
helper, data, vtable and indirect-call closure remain open.

See [RESULT.md](RESULT.md) for positive/negative results, validation, explicit
non-claims and the next bounded question. Evidence is observational; semantic
names and reference behavior are inferences or unresolved. No complete
foundation gate is requested.
