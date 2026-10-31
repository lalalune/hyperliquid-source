# RE-013: checked UTF-8 byte-span adaptation for visor child arguments

- Component: `visor`; source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Target: captured visor, 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Question: does the actually used child-argument adapter preserve a checked
  byte span, or perform lossy replacement?
- Scope: complete 503-byte validator and 67-byte adapter, all 256 lead-table
  entries, and 92 revisited caller/dispatch bytes. No component gate requested.

[PR #988](https://github.com/lalalune/hyperliquid-source/pull/988) records the
`child-args` path's raw collection and callback words but leaves their semantics
unqualified. Its callback descriptor at `0x7e6aa0` selects `0x48dc00`; the actual
collection dispatches use that pointer. This packet closes that used adapter's
checked-byte-span prerequisite. It does not extend #988's public grammar/type
claims or [#1009](https://github.com/lalalune/hyperliquid-source/pull/1009)'s
separate skip-name lookup. #45's lifecycle and #407's unwind/runtime work stay
outside this scope; the common error helper remains opaque.

## Result and proof boundary

[PROOF.md](PROOF.md) supplies the complete block/cursor/memory induction,
including empty input, the 16-byte ASCII fast scan, low 3-bit alignment versus
full 64-bit cursor, every multibyte guard, first-error ordering and conditional
output fields. Every one of the validator's 57 blocks / 143 instructions and
48 branches is bound to its reviewed transfer. This is a complete static
argument under the explicit valid-memory/nonwrap/nonalias/immutable-image
conditions; it is not an automatic general-purpose semantic verifier.

For the defined domain, the validator reaches its local RET with tag 0 iff the
span is strict UTF-8, returning the original pointer/length. Otherwise it writes
tag 1, the invalid/incomplete sequence's start and a presence flag with conditional
error width. The incomplete count byte and error padding remain unqualified.
The result/active stack must be disjoint from input and immutable image;
return slots are explicitly protected. Actual hardware return also assumes
ordinary valid call/return-state contents. An independent review identified
these domain refinements before implementation; [DOMAIN-REFINEMENT.json](DOMAIN-REFINEMENT.json)
retains the initial negative premise and counterexamples as proof corrections,
not captured-program defects.

The adapter reads the input span, calls the actual relocated validator and
returns that same span on success. Error tag 1 selects the diagnostic
`unexpected invalid UTF-8 code point` and an external helper at `0x49ab50`.
If that helper returns, the normal fallthrough at `0x48dc43` leaves this owned
range. No noreturn, process termination or post-helper memory effect is claimed.
Embedded NUL is valid UTF-8 here; this says nothing about later OS/spawn rules.

## Reproduce

The recorded host is Linux/x86-64, Python 3.12.14, GNU objdump 2.44.
From the repository root with authenticated pinned inputs:

```sh
mkdir -p work/visor-utf8
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/visor_child_args_utf8.py \
  --output work/visor-utf8/record.json
cmp research/work-items/RE-013-visor-child-args-utf8/record.json \
    work/visor-utf8/record.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-013-visor-child-args-utf8/check_packet.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_visor_child_args_utf8.py -v
```

The producer admits one immutable full-target byte snapshot. ELF/FDE/relocation,
source-location and table reads use that same snapshot. GNU receives only private
503- and 67-byte raw slices with explicit x86-64/linked-VA options; it never reopens
the original ELF pathname. All raw rows, boundaries and complete CFG edges are
compared with the admitted bytes, including a restored-wrong-view negative.
Raw native exports, actual commands/version and full input/output hashes are
retained without operand normalization. The private counterfactual seam is not
a CLI re-pin option; rejected inputs cannot overwrite earlier results.

The separate high-level byte-class model can be checked against Python's strict
codec. Those checks support the model, **not target execution or all-input
binary parity**. The full target result rests on the complete static proof,
all reviewed block bindings, graph/write inventories and independent review.
No x86 interpreter, emulator, captured execution, SDK oracle or native program
build is used. Rust reconstruction, compiler/lock provenance, two-build results
and raw/normalized binary comparisons are not yet implemented/measured here.

## Remaining work

Whole collection ownership/order/allocation, private Vec/str/result layouts,
public accepted CLI syntax/defaults/trailing arguments, panic runtime and
spawn/download effects remain unqualified. Original artifacts/imports/reference
pins and generated gates are untouched. No unlicensed inferred reference code
was read or copied.

Next question: establish the collection's allocation/ownership and eventual
consumer contracts before translating this checked span into a full child-
argument or process-launch implementation.
