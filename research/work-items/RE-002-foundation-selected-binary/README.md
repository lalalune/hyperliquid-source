# RE-002: preserve the selected binary across the native-export boundary

- Component: foundation tooling; no implementation or progress gate requested.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Original source: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Observation: `inspect(--binary)` authenticates the selected file, but both
  foundation millis and duration tools passed the repository's default input
  to objdump. A normal source-only checkout with an unmaterialized LFS pointer
  therefore failed native export even when the selected external file was valid.

## Reproduce

On Ubuntu24.04, Python3.12.3 and GNU objdump2.42, with an authenticated #94:

```sh
python3 research/work-items/RE-002-foundation-selected-binary/probe.py \
  --binary /absolute/path/to/hl-node94 --objdump /usr/bin/objdump
python3 -m unittest discover -s tests -p test_foundation_binary_selection.py -v
```

The probe copies the actual tools and retained packets into a temporary
source-only fixture, writes the normal133-byte Git LFS pointer at its default
artifact path, and invokes the actual CLIs. The external artifact is real,
digest-checked node94; it is only read/disassembled. No captured target runs.
`before.json` preserves the original CLI failures. `after.json` records the
fixed absolute/relative paths and the invalid-input control.

The first attempted test fixture used a hard link across filesystems and failed
before reaching product code. It was replaced by a normal copy. That setup
error is not the product reproduction. On original code the final regression
had one passing negative-control test and four expected failing subtests in
the two selection tests. After the change all three tests pass.

## Change and evidence

Resolve the caller's path before changing the subprocess working directory,
and pass that same path through `inspect` to `analyze` and objdump. Existing
size/SHA, byte/FDE locks, retained-export mode and canonical records remain.
The new tests use retained native-output fixtures to inspect the subprocess
path; the independent probe uses the real GNU CLI. These are separate claims.

The native windows remain the existing packet's exact VA/FDE ranges: millis
conversion `0x13c8e10..0x13c8f53` and its calendar helpers, and duration
`0x392fab0..0x392fcba`. No instructions or semantic arithmetic interpretation
are changed. No reference source is copied, and no normalization mask is added.

## Limits

The fixture's unmaterialized default is deliberate and disclosed. Fully
materialized defaults already worked before the fix. The defect concerns
which input the native provider opens, not ELF decoding or malformed data.
Open PR554 addresses GNU continuation-row instruction counts; its source was
reviewed for overlap but is not included here. This packet does not assert
GNU/LLVM canonical-output equality or repair that separate parser issue.
Open PR88 fixes bridge report path formatting; it does not select the input
of either foundation subprocess. No gates, imported packets, binary pins,
Rust workspace, user configuration, chain traffic or deployments are changed.

Next question: after these separate fixes are reviewed, native-export output
can be compared across providers without conflating path selection and row
normalization. Whole-program/runtime equivalence remains unmeasured.
