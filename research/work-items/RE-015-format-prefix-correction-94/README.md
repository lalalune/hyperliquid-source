# RE-015: correct the retained constant-template interpretation

- Component: foundation; RE-001 evidence correction supporting the RE-015 inventory.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Scope: correct semantic prose/docstrings, without changing scanner output, imported evidence or any gate.

## Problem and prior work

The retained constants packet calls `c0` an alignment marker, its low bits padding,
and the shared formatter code owned by `global_constants`. These claims can mislead
reconstruction: under the compiler-stamped Rust layout the byte consumes an argument.
[PR #348](https://github.com/lalalune/hyperliquid-source/pull/348) already identifies
this problem in its db-template packet. This correction credits that finding;
it does not claim the formatter or its interpretation as a new discovery.
That PR leaves the original constants packet unchanged. Open #189 corrects the
constants coordinates; this change leaves its table and generated coordinates alone.

## Observed bytes and interpretation

`records.json` is collected from one fully hashed capture. The two anchors contain
`c0 0e /static_config 00` and `c0 05 /cham 00`. Their seven-byte RIP-relative LEAs
start at `0x164fbae` and `0x164f840`, pointing at the `c0` bytes. These independently
read instruction starts differ from the legacy scanner sites (ModRM coordinates);
the current change does not repair that distinct coordinate issue covered by #189.
The selected templates are complete; the containing caller bodies are not analyzed.

The compiler revision stamped in the formatter diagnostic is
`e408947bfd200af42db322daf0fadfe7e26d3bd1`. Its
[core formatting contract](https://github.com/rust-lang/rust/blob/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/fmt/mod.rs#L662-L706)
defines `c0` as a default argument placeholder, the following small byte as a literal
length, and a zero token as template end. Low placeholder bits select optional
formatting fields, rather than padding. The fetched source file SHA-256 is
`ff56f0d7f3ce245b6171f2b742bfa07e1a7596158e43a9917a0340c7e9eb8a27`.
This is a compatibility interpretation tied to the stamped revision, not proof
that the entire captured compiler or library was an unmodified upstream build.

The actual FDE containing `0x1344760` ends at `0x13448f2`. The LEA at `0x13448ba`
selects Location `0x5663328`; its `R_X86_64_RELATIVE` path, length 72 and line/column
650:14 identify `library/alloc/src/fmt.rs`. This does not establish ownership by
`global_constants`. We do not claim to close the formatter, helper calls, argument
value or rendered path. The byte anchors and diagnostic are observations; their
format-template meaning uses the stamped source contract.

## Reproduce

From the repository root, Python 3.12.14 on macOS arm64:

```sh
python3 -B research/work-items/RE-015-format-prefix-correction-94/collect.py > /tmp/format-prefix-records.json
cmp /tmp/format-prefix-records.json research/work-items/RE-015-format-prefix-correction-94/records.json
python3 -B tools/constants_scan.py --check research/work-items/constants
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-015-format-prefix-correction-94 && shasum -a 256 -c MANIFEST.sha256)
```

The collector authenticates the complete capture before parsing, requires exact
anchor bytes and LEA targets, and binds the diagnostic relocation and FDE.
It reads bytes only. The existing constants check passes both before and after,
so all generated inventory outputs remain identical. No new behavioral tests are
added for this prose correction. No captured executable, Ghidra, chain or network
interaction is performed by the collector. No component gate is requested.

## Remaining question

Determine the concrete argument value at these two call sites before inferring a
rendered absolute path; neither inventory suffix establishes that value.
