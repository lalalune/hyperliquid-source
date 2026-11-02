# RE-001: node94 capacity-summary selection and worker cleanup

Component: foundation / node-runtime integration. Bounded question: which
112-byte record does the production worker summarize, which two integer
quantities does it pass to formatting, and what happens to the result?

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
Addresses are ELF virtual addresses; range ends are exclusive.

## New finding

The complete selector `0x13cc100..0x13cc375` reads an array pointer at object
+0x188 and count at +0x190. Within each 112-byte record it compares unsigned
words A at +0x58 and B at +0x60. It skips B>A, chooses the first valid record
with maximal raw A, and formats each successive strict maximum. Ties retain
the earlier record. It independently clamps A and B to `2^63-1`, then passes
`(clamped_A-clamped_B)/2^30` and `clamped_A/2^30` as integer formatting
arguments. Selection uses the raw total, before clamping. The five exact
format-program bytes are `c0 01 2f c0 00`.

The complete worker `0x1400e90..0x1400fb9` constructs thirteen option bytes
set to one, requests the external builder, calls the selector, passes two
conditional initialization boundaries, releases the returned buffer when its
capacity is nonzero, and drops the built object. Its normal path does not
publish the rendered buffer. This narrows the unresolved fixed work target in
#1678 without claiming its builder, system interactions or all helper effects.

“Capacity summary” is an inferred descriptive label for these offsets and
arithmetic. Disk/process identity, units of the upstream fields, source-level
types and complete rendered output are not established merely by that name.
The static relation assumes a valid bounded array, stable fields and normal
helpers with valid result/ownership records. `PROOF.md` records the instruction
argument and limits. There is no captured-code execution or emulation.

## Evidence and reproduction

| Complete FDE | Bytes | Instructions |
| --- | ---: | ---: |
| Selector 0x13cc100..0x13cc375 | 629 | 148 |
| Worker 0x1400e90..0x1400fb9 | 297 | 65 |

Both entire FDEs are retained: **926 bytes / 213 instructions**, including
exceptional cleanup. Complete GNU/LLVM exports agree on bytes and instruction
starts; GNU readelf independently supplies FDE headers. `records.json` binds
27 semantic spans, 15 RELATIVE relocations, six literal/data records, every
explicit call, and two instruction-qualified incoming calls. The census only
covers E8 and RIP-relative FF15/FF25 encodings in `.text` and RELATIVE slots;
it is not proof of arbitrary indirect reachability.

From repository root with pinned inputs materialized and GNU/LLVM tools on PATH:

```sh
packet=research/work-items/RE-001-capacity-summary-94
python3 "$packet/export_disassembly.py"
python3 "$packet/verify.py" --controls
python3 "$packet/arithmetic.py"
python3 -m unittest tests.test_capacity_summary -v
make doctor verify test catalogue-check reproduce
(cd "$packet" && shasum -a 256 -c MANIFEST.sha256)
```

Local tools: Python 3.14.7, Capstone 5.0.7, GNU objdump/readelf
2.47.20260726, LLVM objdump 18.1.4, macOS arm64. No instruction bytes or
operands are masked. Shared exporter plumbing recognizes LLVM's separate
literal LOCK prefix rows; these selected bodies have no such prefix.

**50 actual-byte corruption controls** bypass whole-image, body-digest and
export guards: 27 instruction spans, 15 relocation addends, six literal/data
records and two FDE extents. Separate mutations check each integrity guard.
All mutations are in memory. Four focused tests also validate 45 boundary
pairs, 11 signed-division values, 4,100 release-capacity values and the exact
13-byte option span. These are arithmetic lemmas, not a selector implementation
or target equivalence test. Full validation and overlap metadata are recorded
before publication; skips are not passes and local results do not claim CI.

## Ownership and remaining work

New evidence, proof and verifier code are independently authored under MIT;
binary excerpts retain their original rights. Image/export plumbing reuses our
MIT-authored #1678 packet without a branch dependency. No inferred unlicensed
source was copied. Shared format/controller, build-mode/Once and drop-helper
work remains credited and outside these two bodies. In particular #1678 leaves
the worker unresolved, #233 studies a callee of the external object destructor,
and #694 studies the shared build-mode initializer. Their bodies are not
recovered again here. `overlap.json` records the live all-state audit, a search
of reachable merged history, and limits. `overlap-snapshots.json.gz` retains
the complete immutable-head snapshot list separately from the readable summary.

No Rust reconstruction, build/compiler provenance, new first-party byte credit,
whole-function equivalence, component completion or progress gate is claimed.
Next recover the builder's field provenance and the object destructor, then
close formatter/initialization and LSDA/personality contracts before assigning
an application purpose or exception-complete ownership relation.
