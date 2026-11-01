# RE-001: conditional input domain of two cumulative-minute consumers

The merged [minute packet](https://github.com/lalalune/hyperliquid-source/pull/140)
proves the local conversion and inclusive1440 boundary, but leaves its producer
and caller reachability open. This packet connects two selected consumers to the
already studied remainder-producing helper. It supplies complete caller CFGs,
actual field offsets, relocation bindings and a preservation audit.

The result is conditional: on the producer's ordinary return, with the consumed
four bytes preserved until use, the two minute values lie in0..1439. Caller B
additionally requires index0..5 whenever it takes its unchecked BPL-indexed
dispatch. Opaque calls and escaped stack pointers prevent an unconditional
runtime exclusion of1440. [PROOF.md](PROOF.md) states every premise and boundary.

- Task/component: RE-001 / foundation; one static composition question.
- Source baseline: main `d3af75257a396c85d20857f421c370ddb8cb40e5`.
- Target: node #94,91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: linked ELF VAs, mapped through unique file-backed PT_LOAD ranges.
- Full selected FDEs: callers `0x4925220..0x4925f0c` and
  `0x4925f10..0x4926dac`, producer `0x151cba0..0x151cca5`.
- All three bodies are credited existing context. The new result is their
  conditional caller composition;7,309 bytes/1,480 rows are retained evidence,
  not newly reconstructed/matched code. No acceptance gate changes.

## Evidence and reproduction

`observed/` contains three complete GNU listings, three independent LLVM listings,
three native CIE/FDE exports and records.json. Every instruction byte is compared
with the authenticated image, and GNU/LLVM instruction partitions agree without
address or operand masks. Python and native readelf independently establish the
three FDE extents. Selected call relocations, exact relative transfers, all corridor
memory writes/calls and earlier stack-address formations are retained.

The source helper and its signed64 modulo theorem come from
[RE-009-state-dump-result-projection-94](../RE-009-state-dump-result-projection-94/README.md).
The original fourteen-site minute arithmetic comes from
[RE-001-cumulative-minute-94](../RE-001-cumulative-minute-94/README.md).
The collector reuses their existing MIT arithmetic-proof helpers and ELF/CFI
parsers; all five imported source dependencies are SHA-256 checked before import.
No unlicensed inferred implementation is read or copied for this contribution.

With GNU binutils first on PATH, run from the repository root:

```sh
packet=research/work-items/RE-001-cumulative-minute-input-domain-94
python3 -B "$packet/collect.py" --output work/minute-input-new
diff -ru "$packet/observed" work/minute-input-new
python3 -B "$packet/verify.py"
python3 -O -B "$packet/verify.py"
```

Use a new output directory. `--llvm-objdump` can select a local LLVM installation;
the retained default is Apple LLVM in CommandLineTools. Exact text reproduction
requires the recorded versions in records.json; no cross-version textual identity
is promised. Native tools receive a private chmod0400 snapshot named node94.elf.
Neither that file nor any extracted instruction slice is launched.

The verifier regenerates the complete packet twice and compares retained file
membership and bytes. Below the complete-input admission gate, real byte mutations
are freshly disassembled by GNU and tested against the derived relations: wrong
destination/load/store offsets, a wrong call slot/relocation, a bad reciprocal,
changed guard, an intervening overlapping store, producer-bypassing direct/table
edges, changed selector, prefixed selector clobber/producer-bypassing jump, and
altered FDE extent. It also checks malformed input
rejection before native parsing, missing/changed exports and output preservation.
These are static counterfactuals, not captured-instruction execution or emulation.

`VALIDATION.json` records actual results and any failed development check. Native
decoding agreement and corruption rejection support the evidence, while the
conditional semantic argument remains independently reviewable in PROOF.md.

## Scope and next step

Applicable root checks are `make doctor`, `make verify`, `make catalogue-check`
and `make reproduce`, plus focused static parser/proof checks. Unrestricted
`make test` discovers captured-instruction interpreters such as kind5_reader,
so it is outside this static-only authorization. The publication commit uses
`[skip ci]` following existing static packets; no full-suite or hosted-CI pass
is claimed. Root validation is recorded separately from this packet's checks.

All input hashes, imported pins and generated progress files remain unchanged.
New code/prose use the root MIT terms; native exports retain upstream rights.
No captured execution, emulator, live node service, signing or chain action is
part of this packet. A next bounded question is whether the relevant helper
memory effects can discharge the no-clobber premise, or which constructors supply
the other twelve pointer-based minute inputs. Neither is silently assumed here.
