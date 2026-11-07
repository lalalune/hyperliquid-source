# Corrected TLS coordinates, 2026-11-07

Target remains Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Correction baseline `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The active RE-012 readiness work needs to relate its TLS fields to the existing
LU conversion and cooperative-context records. Those records transcribed the
base as `-0x130`. The original bytes never said that: both
`0x5cf3b94: 48 c7 c3 d0 ee ff ff` and
`0x5cf2d44: 49 c7 c7 d0 ee ff ff` sign-extend the little-endian imm32
`0xffffeed0`, which is -4400 / `-0x1130`. `-0x130` would require immediate
bytes `d0 fe ff ff`. This 0x1000 discrepancy assigns the observations to a
different FS-relative storage location and blocks a sound cross-packet join.

| Observation | Old recorded coordinate | Correct coordinate |
| --- | --- | --- |
| base | -0x130 | -0x1130 |
| state byte, base+0x48 | fs:[-0xe8] | fs:[-0x10e8] |
| route byte, base+0x46 | fs:[-0xea] | fs:[-0x10ea] |
| object pointer, base+0x28 | fs:[-0x108] | fs:[-0x1108] |
| helper word, base+0x44 | fs:[-0xec] | fs:[-0x10ec] |
| helper second byte, base+0x45 | fs:[-0xeb] | fs:[-0x10eb] |

The two packet READMEs/structured records and this packet's EVIDENCE.md are
corrected. All original instruction exports, body hashes, function extents,
call-site records, locations, counts and negative results remain unchanged.
The original wrong values are preserved above; this is a correction of their
coordinate interpretation, not a new recovery claim for either whole function.

Previously the verifiers authenticated the original bytes but did not compare
these recorded TLS coordinates with decoded signed operands. Each now decodes
the observed mov imm32 and FS disp8 encodings and compares the structured record
with those results. The existing diagnostic is corrected as well. The focused
regression controls include the actual record, old metadata, an actual immediate
mutation to -0x130, six displacement mutations, signed-imm32 boundary vectors,
and truncated/wrong-opcode inputs. They run below whole-body hash guards; no
captured instruction is executed or interpreted.

From the repository root with the authenticated target materialized:

```sh
python tools/node115_lu_coop_context.py
python tools/node115_lu_tag_meaning.py
python -m unittest discover -s tests -p test_lu_tls_offsets115.py -v
```

This is the smallest verifier fix needed to prevent the wrong coordinate
interpretation from passing while joining the active readiness task to these
records. Tests of the existing verifiers are also run in an isolated copy so
their historical in-place corruption controls cannot rewrite retained evidence.
Exact results are reported in the PR. There is no Rust reconstruction, actual
TLS execution, concurrency proof, runtime-name/ABI claim, byte-window increase
or acceptance-gate change. The underlying cell's type and lifetime remain open.

Local Windows / Python 3.12.14 results: all eight new regression tests pass.
The cooperative-context verifier and its five original tests pass both before
and after the change. The tag-meaning suite has four passing tests and one
failure both before and after: its positive verifier requires the unavailable
native `readelf`. An isolated checkout of the original HEAD reproduced the
same FileNotFoundError. The standalone corrected cooperative-context verifier
passes against the actual authenticated target. The tag-meaning verifier stops
at readelf, so a complete native pass of that verifier is not claimed. The new
tests exercise its decoded-record binding directly, below the body hash guard.
