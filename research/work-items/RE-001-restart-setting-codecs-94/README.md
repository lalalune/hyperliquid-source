# RE-001: restart setting wrapper and reader codec dispatch

- Component: foundation / configuration reader. Question: which decoder paths
  and result-word protocols feed the restart-page setting's floor-of-one return?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an unlicensed lead.
- Status: observed path template, calls/branches/result words and conditional
  component/helper models. Full grammar and live configuration remain unresolved.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/restart_setting_static.py --out work/restart-setting-94.json
python -m unittest discover -s tests -p test_restart_setting_static.py -v
python research/work-items/RE-001-restart-setting-codecs-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
No captured code, live configuration read, shell, database, network or chain
operation executes. Only the pinned public capture is parsed.

Retained complete FDEs `[0x13ca000,0x13ca0d5)` (**213 bytes / 53
instructions**) and `[0x144b900,0x144bfcb)` (**1,739 bytes / 370
instructions**) total **1,952 bytes / 423 instructions**. Exports retain
contiguous complete byte consumption, original FDE/CIE and body hashes. Selected
operands/calls are instruction starts. Coordinates are ELF VAs; `.text` offsets
are VA minus `0x1000`. No masks.

## Wrapper observations

The wrapper obtains a global object through RELATIVE pointer
`0x576e928 -> 0x577b288`, with an initialization slow path. It formats a suffix
ending `/hyperliquid_data/n_restarts_to_page.json`, using the captured template
at `0x1de68f`. This does not establish an input root argument or the live global
root value. Source Location `0x5666b80` resolves to `base/src/u.rs:549:5`.

It calls `0x144b900`, preserves the returned word across ordinary path cleanup,
then executes `CMP RAX,1; ADC RAX,0`: raw zero becomes one; all other u64 words
are unchanged. This is a conditional return-value primitive, not a guarantee
that every helper/error/unwind path returns normally.

## Shared reader and component choice

The reader first calls bound path/predicate helpers. A false predicate reaches
the captured `missing file` diagnostic path. Under ordinary diagnostic/drop
returns, that path returns zero. Other branches ask `0x4f11400` for a component
candidate and require its selected slice-result tag 9 before extension testing.

For a supplied normal final-component byte slice, the captured test finds its
last dot, requires a nonempty prefix and exactly three following bytes, and
ASCII-folds those bytes before matching `rmp`. Thus `file.RmP` selects the binary
path; `.rmp`, `file.rmp.extra`, absent extensions and other suffixes select the
default text path. Full path expansion/component normalization is outside the
model. The fixed setting filename normally selects the text path; the binary
path belongs to the shared reader, not a claim of an extra setting-file feature.

| Selected path | Read target | Decoder target | Observed success test |
| --- | --- | --- | --- |
| rmp component | `0x4ed97e0` via slot `0x576f640` | `0x13aa0c0` | result byte 9, payload at stack +0x88 |
| default text | `0x4ed9180` via slot `0x576f648` | `0x149e2b0` | RAX low bit zero, payload RDX |

The text path's diagnostic literal names `serde_json::from_str`. It does not
establish a plain decimal `trim().parse()` implementation, as suggested by the
reference's small `read_usize_file`. No complete JSON or MessagePack grammar,
integer boundary admission or private decoder type is recovered here.

Both read-result checks use NEG/JNO: raw INT64_MIN is the selected error word,
not every negative-looking word. Read/parse diagnostic paths format and drop
their errors, then zero EAX under normal helper returns. A successfully decoded
zero and such a zero fallback therefore both become one in the wrapper. Actual
file availability, diagnostics, initialization, allocation, drop and unwind
behavior are outside the result-word model. No reference code is copied/changed.

## Controls and required checks

Six focused methods pass. **768** suffix-byte substitutions and all eight ASCII
case forms cover the component primitive, with dot/hidden/trailing cases.
**4,096** declared codec/predicate/read-word/parser-tag/payload combinations
agree with an independent success/fallback form. Floor checks cover 0..4,095
and four full-width boundary words. Those are conditional primitive domains,
not real file reads, complete parser tests or valid configuration populations.

Actual-capture mutations cover extension length/folding, read/result tags,
decoder calls, global relocation, floor arithmetic, path/JSON labels, source
Location, both FDE extents and identity. Make is absent; required Makefile Python commands were run directly. Full suite:
**363 tests in 107.152 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass
before missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. Those failures are not marked passed.

No live global/root/configuration state, full file predicate/path/decoder grammar,
Rust ABI, helper/error/drop closure, native build/equivalence, imported change,
hosted CI or progress gate. Next question: close the two concrete parsers and
path helpers before implementing a complete configuration reader.
