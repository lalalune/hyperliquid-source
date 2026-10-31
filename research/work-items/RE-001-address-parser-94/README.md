# RE-001: address parser framing and ASCII acceptance

- Component: foundation / address representation. Question: how does the
  `0x1444a00` parser frame its input and fill its successful 20-byte result?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an unlicensed lead only.
- Status: captured field/branch/data observations and conditional ASCII model.
  No reference code is copied or changed; no complete Rust ABI is asserted.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/address_parser_static.py --out work/address-parser-94.json
python -m unittest discover -s tests -p test_address_parser_static.py -v
python research/work-items/RE-001-address-parser-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
Captured code, networking and signing are never executed.

`windows.capstone.txt` retains two complete FDE windows: parser
`[0x1444a00,0x1444d6c)` (**876 bytes / 204 instructions**) and iterator
`[0x4eb64f0,0x4eb68a9)` (**953 bytes / 242 instructions**). Total: **1,829
bytes / 446 instructions**, with contiguous complete byte consumption, original
FDE/CIE records and body hashes. Selected operand checks are instruction starts.
Coordinates are unrelocated ELF VAs; `.text` file offsets are VA minus `0x1000`.
No masks or instruction substitutions are applied.

## Observed framing and result

The entry saves RDI as its output pointer, reads RSI as the byte buffer and RDX
as its byte length. It rejects fewer than two bytes before reading a prefix.
Only little-endian word `0x7830` (`0x`) removes two bytes. Uppercase `0X` is not
that prefix. The remaining byte length must be at least 40.

If longer, the parser splits before the last 40 bytes and requires each scalar
in the leading portion to equal U+0030. The captured diagnostic says `trailing
characters`, but the loop visits the leading portion. Source Locations
`0x566a410` and `0x566a428` resolve through RELATIVE relocations to
`base/src/address.rs:100:14` and `103:18`. These accompany UTF-8 slice-boundary
panic arms; this packet records them without executing or assigning a policy to
arbitrary Unicode inputs.

The final window has another exact `0x` comparison through literal `0x7166d0`.
If matched, only 38 bytes remain. The parser requires **20 tag-2 iterator
results**, then **tag 3** on its additional iterator call. A 38-byte window
cannot provide 20 bytes. Success copies the accumulated 20 bytes to output
offsets `[1,21)`, writes tag byte 0 at offset 0 and returns the original output
pointer in RAX. The error path writes tag byte 1; its allocated payload and
display representation are outside the model.

## Hex iterator and bounded comparison

RELATIVE slot `0x576f580` binds both parser call sites to `0x4eb64f0`. The
iterator's nibble classifiers use wrapping-byte ranges A..F, a..f and 0..9.
Their offsets are respectively -55, -87 and -48, and the pair result shifts
the first nibble left four and ORs the second. Its raw result tags are:

| Tag | Observed role |
| --- | --- |
| 2 | Decoded byte at result +4 |
| 3 | End of input / already exhausted |
| 1 | First nibble without a matching second nibble |
| 0 | Invalid character with additional character/index fields |

Whitespace masks in both nibble paths are `0x100002600`, admitting bytes 9,
10, 13 and 32. That is iterator behavior; it does not make a 40-byte address
window containing whitespace successful, because skipped bytes leave fewer
than 20 decoded bytes. Form feed and vertical tab are not in that mask.

For ASCII input, the independently written framing/nibble model agrees with
the independent full-match language `(?:0x)?0*[0-9a-fA-F]{40}` in the declared
test population. The tests check **10,240** single-position substitutions
(40 positions x 128 ASCII bytes x two prefix forms), plus zero/nonzero padding
lengths 0..96 and lowercase/uppercase/absent prefix probes. Successful payloads
are compared with Python's separate hex decoder. All **256 byte classifier
inputs** and **65,536 byte pairs** also agree with an independent digit lookup.
These counts describe model/primitive checks, not captured calls, exhaustive
string populations or complete binary equivalence.

Assumptions: valid backing memory, ASCII input for the acceptance model and
ordinary returns of out-of-scope error/allocation helpers. The model rejects
non-ASCII bytes as outside its domain. It does not emulate a Rust string object,
error allocation, OOM, invalid backing memory or the Unicode iterator helper.

## Controls and required checks

Six focused methods pass. Actual-capture corruptions cover framing lengths,
prefix, zero-padding comparison, result count/tags, nibble bounds/bias, shift,
whitespace mask, literal/source/call bindings, FDE extent and target identity.
Each enclosing body is separately SHA-256 checked. Make is absent; its required Python commands were run directly. Full suite:
**363 tests in 111.670 seconds; 7 failures, 16 errors, 21 skips**. All six new
tests pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass,
then missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs preserved);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. Full-suite/signature/hosted-CI success is not claimed.

No imported evidence, progress gate, native target execution, build, signing or
hosted-CI claim. The next question is caller/input ownership and complete error
construction before claiming the full Rust parsing interface.
