# RE-012: node #115 curl builder defaults and argument paths

- Component: foundation / networking support, bounded command-string preparation evidence.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: what default option material is constructed, and how is the separate optional connection-timeout value bound in these four bodies?
- Observation: each first constructs the 15-byte buffer ` --max-time 300`. A nonzero word at incoming `+0` enables a separate ` --connect-timeout ` format path whose value comes from `+8`. These are distinct pieces, not an observed replacement of the max-time constant.
- No command is executed. This is partial static mapping, not a complete returned-command, HTTP/runtime-timeout or reconstruction claim.

## Evidence scope

| FDE half-open VA range | Role | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| `0x15354f0..0x1535927` | builder A | 1,079 | 226 |
| `0x1535930..0x1535d4d` | builder B | 1,053 | 219 |
| `0x4e4bdb0..0x4e4c1e7` | second A-shaped builder | 1,079 | 226 |
| `0x4e4c1f0..0x4e4c60d` | second B-shaped builder | 1,053 | 219 |
| `0x15ebba0..0x15ebbb3` | first pointer/length callback | 19 | 5 |
| `0x1531e10..0x1531e24` | first owned-buffer callback | 20 | 5 |
| `0x5616320..0x5616333` | second pointer/length callback | 19 | 5 |
| `0x4e188d0..0x4e188e4` | second owned-buffer callback | 20 | 5 |

Measured denominator: **eight complete FDEs, 4,342 bytes / 910 native instructions**.
All original FDE/CIE bytes, body hashes, file offsets, complete GNU exports and
native readelf confirmations are retained. Native exports start at the actual
FDE entries, cover every body byte and confirm the selected instruction starts.
No comparison normalization mask is applied; A/B shape labels are not a raw
body-equality or identical-side-effects claim.

The independently extracted scope spec is sealed by SHA-256
`bbd83f7678d32789866a8ff645304bbdca92fb614ecee58e0ebe4c5023a657bd`.
It includes actual native instruction references and direct/RIP call/jump
bindings, not a source-symbol guess. The producer also checks actual source
Location pointer/length/path/line/column: `base/src/curl.rs:55:13`, at slots
`0x63fd790` and `0x649db18`, with two measured references each. Original function
names, generic types and caller reachability remain unresolved. No inferred
reference implementation is copied or used as the expected behavior.

## Default material and connection-value path

Relative to each builder, two MOVABS immediates materialize eight bytes each:

- `+0x49..+0x51`: `time 300`, stored at new-buffer offset 7.
- `+0x57..+0x5f`: ` --max-t`, stored at offset 0.

They agree at their one-byte overlap. The resulting exact 15 bytes are
` --max-time 300`. Allocation size, buffer capacity and length are all 15.
`default_fragment()` reads the actual captured immediate bytes and reconstructs
only that overlap; it is not an instruction emulator. Changing the final zero
to one changes the extracted material to ` --max-time 301` before its checker
rejects the counterfactual. Each of the four bodies is checked independently.

Incoming words at `+0` and `+8` are loaded into R13/R14. The captured TEST/JE
uses the former as the presence gate. In the enabled path the latter is stored
as a formatting argument and paired with the function bound through
`0x64e0a98 -> 0x1689420`. The compact descriptor at `0x43fecd` has literal bytes
` --connect-timeout ` followed by the argument marker. The same initial
buffer is the receiving object passed into the subsequent formatting call.
This establishes local material and argument binding; the opaque formatting
implementation's effects and errors are not fully recovered here.

A runtime curl version is not recorded. No observed HTTP transfer, effective
elapsed timeout, subprocess behavior or whole returned-command equivalence is
claimed from the option names or the literal 300 alone.

## Other bound fragments and callbacks

The four bodies also reference these exact compact descriptors:

| Descriptor VA | Literal material / local role |
| --- | --- |
| `0x440ecb` | ` -o ` plus one argument, gated by incoming `+0x20` nonzero |
| `0x43aafa` | `/tmp/curl.` plus one argument |
| `0x44a8f8` | ` --header 'Content-Type: application/json' --data '@` + argument + `'` |
| `0x4345ba` | `curl -fsS` + options argument + space + incoming two-word argument |

The incoming two-word argument at `+0x10` is preserved for the final format
binding. The `+0x20/+0x28` pair feeds the output-fragment formatter. A raw byte
at `+0x30` is compared with 4 for a body-related path. Its concrete Rust enum,
semantic variant names and payload codec are not recovered. The body-related
paths call **four distinct opaque helpers**, `0x15053f0`, `0x1505080`,
`0x50ddcc0` and `0x50de300`; they are not treated as one closed implementation.
Their actual calls and return checks remain in the full exports/spec.

The first callback pair reads pointer/length at `+0/+8` and `+8/+0x10`
respectively; the second pair has the same measured field accesses. All four
tail-call the relocated output slot `0x64df720 -> 0x167fa70`. Formatter entry
and write/append entry slots `0x64df6e8` / `0x64df6f0` are bound separately.
The first and second formatter objects are **`0x63fd760` and `0x649daa0`**:
their raw 48 bytes and internal RELATIVE slots are retained separately.

These observations do not establish a concrete String/fat-pointer/type ABI,
general URL policy, security property, escaping contract, temporary-file
contents, actual I/O direction or a completed JSON serializer. Caller input
provenance and trust are outside this packet. No security finding is claimed.

## Reproduce and controls

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repository
root with materialized captures and native GNU tools on PATH:

```sh
python3 -B tools/curl_options_static.py --output work/curl-options-check
# Compare generated files with this packet except input spec/README/manifest.
python3 -B -m unittest discover -s tests -p test_curl_options_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-012-node115-curl-options && shasum -a 256 -c MANIFEST.sha256)
```

The full input capture is authenticated before analysis/output/native calls;
native tools receive a private byte-identical snapshot. The sealed spec is
checked before use, and generated text uses UTF-8/LF byte writers. Wrong-release,
truncated and same-size modified captures fail the public identity gate before
output creation.

Six focused tests cover full native regeneration, the actual 300→301 literal
counterfactual and overlap corruption in all four builders, allocation/capacity/
length and connection gate corruption, actual descriptors/LEAs/callback operands,
real code/source/formatter relocation addends and all eight FDE extents. This is
not an arbitrary-byte detector below the public digest gate and the synthetic
literal relation is not captured-code execution.

Exploratory spec construction initially guessed the second formatter object as
`0x649dae8`; native LEAs establish `0x649daa0` instead. The final spec also
includes all four callbacks and distinct payload-helper targets. The obsolete
six-FDE scope was discarded before retained generation and test validation.

No captured executable/emulator, curl command, temporary body file, HTTP request,
user process or network/chain/wallet/signing action is used. Captures, imported
code/source pins and all progress gates remain unchanged. Hosted CI, allocator/
formatter/helper/error/unwind closure and full runtime equivalence are not claimed.

Next question: bind one real caller's input provenance and close its selected
body helper before implementing or executing an offline command harness.

Observed local validation: **six focused tests passed in 65.020s**. Required
`make doctor verify test catalogue-check` passed **437 tests in 226.766s**,
all capture/import/source-pin/signature checks and catalogue consistency.
`make reproduce` passed. The packet manifest and staged whitespace checks passed.
These are local native results, not hosted CI or target execution.
