# RE-003: three-byte normal-path certificate for node #115 priority-delay parameters

- Component: serialization/foundation, static fixture selection for delayed-action configuration.
- Target: node **#115**, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Bounded question: does the `PriorityRateDelayParams with 6 elements` diagnostic mean that these byte-fed entrypoints require six values to reach their local normal output path?
- Observation/proof: under the explicit valid-buffer/counter preconditions below, **exactly three u8 values suffice** for that path. The six-element diagnostic alone is not a required input-length contract.
- No full decoder, concrete Rust type, live API, delay policy or reconstruction gate is claimed.

## Evidence identity and completeness

| Entry FDE, half-open VA range | Bytes | Native instructions | Diagnostic fat-string slot |
| --- | ---: | ---: | --- |
| `0x1839480..0x1839913` | 1,171 | 267 | `0x641eec0` |
| `0x2fbf570..0x2fbfa03` | 1,171 | 267 | `0x64644c0` |
| `0x48117a0..0x4811c33` | 1,171 | 267 | `0x64998d8` |

The measured denominator is **three complete FDEs, 3,513 bytes / 801 instructions**.
`records.json` retains body hashes, file offsets, actual FDE/CIE raw bytes and
coordinates. `frames.txt` contains independent GNU readelf confirmations. All
three raw objdump exports start at the actual FDE entry and cover its full body;
they do not start at an interior pattern match or stop at a next-index guess.

The nine diagnostic LEAs (three in each owner) and their RELATIVE pointer/length
slots bind the names to these particular bodies. Original names are stripped;
role descriptions are inferred labels. No inferred reference implementation is
copied or used as a correctness oracle. Existing #94 action-delayer research
(#150, #600) concerns different release-specific delay curves/status routines;
it is not evidence for this #115 input form.

The complete entry prefix `[start,start+0x169)` is **raw equal in all three**,
SHA-256 `b4091a331954a0ae3179501a2950606f7214e9df48ae684be0062a652f0913c2`.
The 15-byte epilogue `[start+0x25e,start+0x26d)` is also raw equal. No normalization
mask is applied to those equalities. The rest of each body is retained but not
claimed equal, helper-closed or behaviorally recovered.

## Preconditions and path proof

The observed RSI state supplies cursor `p` at `+0`, end at `+8`, and item count
`c` at `+0x10`. Assume `p != 0`, end `p+3`, non-wrapping pointer arithmetic,
three readable input bytes and `c <= u64::MAX-3`. Stack, state and output regions
must be valid and nonaliasing, with the observed calling convention. This is an
internal byte-fed input interface, **not** a claim about JSON, MessagePack or
raw production wire acceptance. Flags/rounding do not affect exact conversion
of unsigned bytes to binary64; exceptional machine/environment failures are not
modeled.

Offsets below are relative to each entry:

1. Null/empty tests at `+0x14/+0x21` do not branch. The first byte is loaded with
   MOVZX and converted exactly to binary64 in XMM2. Cursor/count are advanced.
2. The second byte is loaded and converted exactly into XMM3. Both numeric
   validation sequences derive their bits and apply the observed predicate:
   `bits == 0 || (sign_clear && (((bits + 0xfff0000000000000) mod 2^64) >> 53) < 1023)`.
   Each predicate holds for all 256 u8 values. The tool extracts the actual
   addend, shifts and thresholds; this is a finite algebraic certificate over
   two 256-value domains, **not instruction execution or emulation**.
3. The third byte is read into EBP and converted exactly into XMM1 at `+0x132`.
   There is no corresponding numeric rejection branch for this conversion.
   The cursor and counter have become `p+3` and `c+3`. Counter guards at
   `+0x36/+0x93/+0xe6` are not taken under the stated bound.
4. The end tests after the first two values (`+0x82/+0xd5`) are unequal and do
   not take their missing-value branches. After the third, `+0xfc/+0x11b/+0x127`
   compare the cursor with end; all three JNE edges are not taken.
5. The local default path sets ECX=2 and R15D=0, selects R14=0 with CMP/CMOVNE,
   and later sets EAX=2 and selects RCX=0. It writes the defined outputs below,
   then its direct jump at `+0x164` reaches epilogue `+0x25e` and RET `+0x26c`.

GNU decoding independently confirms that the prefix has only the twelve named
conditional branches and final direct jump: **no CALL, indirect jump or RET**.
The epilogue has no call. This certified path therefore needs no opaque helper
assumption. Other length/value/error paths and their helpers are excluded.

The two independent numeric domains and unrestricted third byte cover
`256^3 = 16,777,216` three-value combinations by dataflow/algebra. This is not a
runtime test count or a claim to have run those inputs.

## Defined local output and unspecified bytes

| Output offset | Established store on this path |
| --- | --- |
| `+0x0` | qword 0 |
| `+0x10` | qword 0 |
| `+0x20` | exact binary64 value of first byte |
| `+0x28` | exact binary64 value of second byte |
| `+0x30` | exact binary64 value of third byte |
| `+0x38` | byte 0 |

**Do not compare the whole output buffer.** The stores at `+0x8` and `+0x18`
copy the incoming low XMM4/XMM0 bits without local initialization on this path.
Their concrete values, padding and other bytes are unspecified here. The zero
control words/byte are raw representation observations, not a recovered Option
or Result ABI, semantic field names, or proof that these payloads may be read.
RAX is not used as a claimed success tag. The local state writes are cursor
`p+3` and counter `c+3`; no concrete Rust input type is asserted.

A future approved harness may select examples `[0,0,0]`, `[7,11,13]` and
`[255,255,255]` for this exact interface, checking only the defined stores and
state effects after separately establishing caller reachability. **No such
captured-code execution is performed by this packet.**

## Reproduce and controls

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repo root,
with materialized checksum-pinned inputs and native GNU tools on PATH:

```sh
python3 -B tools/priority_prefix_static.py --output work/priority-prefix-check
# Compare generated files with this packet, except README/manifest.
python3 -B -m unittest discover -s tests -p test_priority_prefix_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-003-node115-priority-prefix && shasum -a 256 -c MANIFEST.sha256)
```

The full input SHA-256 is authenticated before analysis, output or native tools;
native readelf/objdump receive a private byte-identical snapshot. UTF-8/LF byte
writers preserve the retained exports across text newline conventions.

The focused tests regenerate all retained outputs, cover both complete numeric
domains, and change actual predicate immediates to zero. The changed predicate
then accepts only zero instead of all u8s, before the checker rejects it. An
actual final-jump displacement change lands at epilogue+1 and is also rejected.
Further controls alter cursor/counter writes, conversions, default control words,
output destinations, epilogues, all three diagnostic relocations/xrefs and FDE
bounds. Wrong-release, truncated and same-size modified captures fail the public
identity gate before creating output. Below that gate, this is a certificate of
the named obligations, not an arbitrary-byte corruption detector.

## Limits and next question

No captured executable/emulator, configuration submission, delay calculation,
network, wallet, signing or chain action is used. Captures, imported source/pins
and progress gates remain unchanged. Rust reconstruction, execution equivalence,
full optional-suffix semantics, error rendering, incoming caller reachability and
general accepted input lengths remain unproved. Three entries are a declared
measured scope, not a claim that all monomorphizations have been found. No hosted
CI result is claimed.

Next question: which caller supplies this byte-fed interface, and which typed
input path establishes the semantic names/types of its optional suffix?

Observed local validation: six focused tests passed in 46.710s. `make reproduce` passed. Required repository test results are recorded with the submitted PR.
The required `make doctor verify test catalogue-check` run completed successfully:
437 tests passed in 188.926s, all pinned-input/import/signature checks and the
catalogue consistency check passed. Manifest and staged whitespace checks passed.
