# RE-005: string precision, width and normal request effects

This packet reconstructs the node #94 `Formatter::pad` normal callback/header
relation at `0x1573450..0x1573889`: 1,081 bytes / 300 instruction rows.
Its body SHA256 is
`f958a0383269ead1a2056ba42785c9050e46a57aa0f990a27976fe27cb5eee77`.
The node target SHA256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
the source base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

The new semantic gap is scalar precision and truncation, option-bit gating,
raw width after precision, default-left alignment, cached writer identities,
live methods and raw versus canonical callback errors. The helper never
directly writes formatter fields. This differs from integral padding's sign,
optional prefix and success-only zero-header restoration.

The original adjacency seed `0x15728c0` was authenticated as a different
602-byte `pad_formatted_parts` body, followed by a 649-byte helper and a
415-byte tuple helper. The actual string helper was selected by a bounded
nearby complete-FDE/published-section comparison and independent address
ownership searches. Those earlier bodies remain ignored research inputs;
they earn no claim in this packet.

`native-intake/` binds the complete selected main, FDE/CIE, code relocation
fields and actual data. All four primary code relocation fields are real;
the count call uniquely reaches `0x15796c0..0x1579c8b`. That 1,483-byte /
365-row counter theorem is credited to reviewed PR #1439. Small counter-only
bindings/proof are retained in `credited-counter1439/`, not its unrelated
main/prefix evidence. No new helper byte or semantic credit is counted.
Actual alignment-table bytes and published table relocation addends both yield
`[left,right,center,left]`. The published object is attribution and supporting
correspondence, not a new original-source/compiler build claim.

## Pre-source authority and build scope

The independent native-derived proof and raw corpus were sealed before new
Rust source. Freeze SHA256:
`00eaff92d84ae4a569aab8c1950fa991f8c271dd4445b3a02fb4f11b697d06e9`.
It covers 26,054 distinct raw inputs, 9,915,008 individual callback observations
and 49,649 exact adjacent-event RLE records. The separate sequential protocol
audit reproduces every event individually, independently of segment compression.
The finite corpus corroborates the full mathematical normal-domain proof; it
does not exhaust all strings or execute the captured node.

`independent-pre-source/FILE-MAPPING.json` records byte-identical local filename
renaming and lossless authority compression. To reproduce the independent
generator/auditor, copy them into a fresh ignored work directory, restore the
original `string-pad-1081-*` filenames using that mapping, decompress the
authority, and run the retained scripts there. They use only Python standard
library Unicode and supplied callback mathematics, with no node execution or
instruction-state evaluator. Production Rust clients receive only eight raw
input fields; expected output and selected-substring/layout plans stay external.

The new Rust lives at `src/node94-string-pad/`; its README states the chosen
safe interface and normal domain. It has real scalar count/precision logic,
uses the actual audited core/std research provider, forbids unsafe code and
does not invent a workspace, dependency graph or fixed-helper stub.

After a clean source checkpoint, run the scoped experiment with a fresh output
directory outside the checkout:

```sh
python3 -B research/work-items/RE-005-string-pad-94/validate_string_pad.py \
  --root "$PWD" --head "$(git rev-parse HEAD)" --output /tmp/string-pad-new-run \
  --provider-audit /path/to/PROVIDER-AUDIT.json \
  --core-archive /path/to/libcore-e60dd2ab51fbc7de.rlib
```

The runner records actual O0/O3 unit/client outputs, one optimized raw rebuild,
thirteen compiled source controls, eleven below-digest static controls and seven
comparator controls. It binds the full target, archive, all tracked physical
inputs and modes, seven genuine pins, all 103 official provider payloads, both installed component manifests and
actual gcc/BFD identities before/after. Native internal binutils records remain
separate from the recorded compiler/program/identity command streams.

## Actual native-proof-derived Rust validation

The first new compiler experiment passes at clean source checkpoint
`70cc50b2e6d4ba75c6541328aed886712e7a959b`, tree
`48c7fe73aae25e86d30e8f4b28c412005c0f61dd`. Both O0 and O3 clients
emit all 26,054 exact sealed canonical JSONL rows, with 9,915,008 supplied normal
callback observations per profile. Both two-test unit binaries pass. One
additional O3 rlib and separately linked client are raw-equal to their first
O3 artifacts. This is independently authored Rust checked against a relation
derived from native proof; it is not captured execution or target-byte equality.

All thirteen compiled source controls are rejected by complete output mismatch.
They cover absent-option gating, precision selection/length, byte versus scalar
width, raw width after precision, default-left and center ordering, raw statuses,
cached identities, unauthorized header writes and the last trailing-fill error.
Eleven below-whole-digest native controls include code/data changes and actual
competing/cross-boundary loader writes. Seven comparator controls reject row/ID,
status and noncanonical wire corruption. `build/RESULT.json` retains exact counts.

The actual full target census has 80,300 eight-byte relocation writers:
78,833 RELATIVE, 263 GLOB_DAT, 924 R_X86_64_64, 2 TPOFF64 and 278 JUMP_SLOT.
No REL/RELR table is admitted; no writer intersects selected code/constants/
alignment data, and the selected counter GOT has exactly one full symbol-zero
RELATIVE writer. This is the selected helper/data closure, not a whole-loader
or whole-node reconstruction.

The selected primary published-artifact comparison is registered once in
`research/byte-windows.json`: 1,065/1,081 raw equal positions and all 1,065
non-relocation positions equal outside its four actual four-byte fields.
This registry candidate is the licensed published object, not the independently
authored semantic Rust. The shared 1,483-byte counter is retained strictly to
authenticate the fixed helper required by the normal proof. It is already
credited to reviewed #1439 and is not selected as an additional byte-window result
here; no new counter recovery or aggregate denominator credit is added. Catalogue
tables are regenerated from the ledger, with every acceptance gate still false.

`build/CALLS.json` records 56 compiler/program/identity commands and 112 raw
streams. The lossless stream pack retains those originals and before/after
audits, exact mutant sources and bounded native byte evidence; it excludes
full target ELFs and runnable own artifacts. Native internal objdump metadata/
listings are retained separately. The full upstream license and `NOTICE` apply
to the bounded official excerpts. `independent-review/` retains the actual
artifact review and two fresh executions of the already compiled clients from
raw eight-field inputs only, plus original replay scripts/compressed streams.
Their `.retained` suffix preserves exact original gzip bytes without creating
new LFS pointer requirements; `FILE-MAPPING.json` binds names and raw hashes.

`repository-checks/` retains passing doctor, verify, catalogue-check and reproduce
commands at the same source checkpoint. All 10,847 tracked physical inputs,
seven actual pins, 103 provider payloads, both installed component manifests,
target/archive/linker identities and HEAD/tree/status remain unchanged. The
later evidence/docs commit does not change compiled source, native producer,
measured runner or frozen cases.

Full `make test`/expanded evaluator families, captured program execution, hosted
CI and full-node builds remain NOT_RUN. The claim excludes private ABI/pointers,
rendering, faults/unwind, concurrency, invalid aliases and original compiler/
opcode equivalence. No acceptance gate changes. See `NOTICE` and full upstream
MIT license for bounded artifacts. The draft uses `[skip ci]`.
