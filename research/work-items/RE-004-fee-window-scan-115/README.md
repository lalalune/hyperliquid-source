# RE-001 / fees: exact fee-associated ordered scan with cursor consumption

Node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
base05bc2de303c05525b71e7e257426e741bc66a390. Complete ELF VA owner
`0x36e1b10..0x36e1b81`,113B33instructions. Merged static #2094 and #2153
are credited and preserved. They do not provide a Rust reconstruction; this
packet qualifies actual normal-return instructions and exact cursor mutation,
with a new independent implementation planned only after expectation sealing.

See CONTRACT.md. An ordered next>previous stops the scan true after consuming
that adjacent pair; equality, decreasing values and quietNaN continue. The
stored pointer/count advance on every inspected pair, even the one yielding
true. Width2 is the observed caller value; raw width>=2 controls window count,
not a complete all-elements-in-window comparison. Wider widths are not claimed
as valid production caller inputs. Empty width0/1 returnsfalse unchanged;
nonempty width0/1 reaches an unimplemented diagnostic and is excluded.

The corpus6741 distinct width/raw-bit-array rows spans all four-symbol arrays
through length5, zero/negativezero/one/quietNaN, signed infinities, extreme normal
and subnormal operands, maxwidth, short arrays and deterministic raw-bit rows
through length32. Ordinary UCOMISD return with DAZclear and masked denormal
exceptions is a premise; signalingNaNs are refused. No environment state,
production nonfinite admission or complete fee-table validity is recovered.

`native.py` follows actual instructions with packet-local MOVSD/UCOMISD support,
exact integer-bit floating relations and real RETs. No captured process or
Unicorn executes. All76 normal-return bytes/25starts are visited;37B8starts
of the invalidwidth/nonempty diagnostic route are retained as context only.
There are no qualified calls or fake callback returns. The one uncalled failure
slot, source Location, complete FDE/CIE, realcaller/constantwidth2 and complete
GNU/Capstone-agreed bytes are authenticated by proof.py.

```sh
python3 research/work-items/RE-004-fee-window-scan-115/proof.py --objdump /path/to/objdump
python3 -m unittest discover -s tests -p test_fee_window_scan115.py -v
```

Nine changed actual-byte COWs produce different normal results; three distinct
corruptions are rejected at the diagnostic/footprint/unchanged-width boundary.
Expected outputs are exact AL, consumed-element offset relative to the original
backing origin, and stored remaining count. Width and input bytes are unchanged;
no cursor difference is masked. Original API/ABI, exception/unwind behavior,
full caller checks, fee schedule validity and byte equivalence remain unclaimed.
All92 gates remainfalse; captures, pins and sharedtools are unchanged. New code
MIT, no unlicensed inferred source. Next: trace all caller guards/table construction
and qualify the actual floating environment before composing a full validator.

## Independently authored Rust

Expectations/evaluator/contract were sealed before Rust at
b73a15630a1406d0c9ac9ab1f021f9c856a4c69b. Safe no_std library
`src/node115-fee-window-scan/lib.rs` uses real binary64 ordered comparison and
tracks the exact consumed position/count. No root Cargo graph/dependency or
original ABI is invented. The input-only driver transports decimal raw bits.

```sh
python3 research/work-items/RE-004-fee-window-scan-115/verify-rust.py \
  --rustc /path/to/rustc --out /fresh/output/directory
```

Opt0/3 and same-path opt3 byte/output repetition match all6741 sealed states.
The116-case client fixture is a selection of unchanged sealed rows. Twelve
compiled wrong sources each emit a complete stream and fail ordinary assertions
(exit101). They change numeric order, equality, previous-element selection,
window boundary/width, initial count, early stop, return and cursor coordinates
or total-order treatment of floating bits. No crash is counted as a successful
control. Full receipts/15streams/152commandlogs and the exact fixture are gzip
archived; readable summaries link hashes. Only owned local path prefixes are
projected in command output. The fixture is SHA-checked/decompressed before
builds at its original packet path; actual build/compare functions are unchanged.
See VALIDATION.md for commands, actual results, tool versions and limitations.
