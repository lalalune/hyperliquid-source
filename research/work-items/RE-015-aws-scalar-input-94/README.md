# RE-015: trace the AwsName-associated scalar input and rejection paths

Node #94 forwards unsigned scalar payloads to a separate numeric visitor but routes signed values through type-error formatting; after successful finite-float formatting it requests a `.0` suffix when the dot-tracking flag stays clear, so reconstruction must preserve the type distinction, cursor updates and formatting failures.

- Component ID: `constants`, task `RE-015`.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: observed instruction/data bytes, FDE extents, local control transfers, relocation addends and stores; inferred input-type and AwsName associations; unresolved caller reachability and the final results of external visitors.
- Scope included and excluded: the scalar dispatcher, eight type-error visitors, selected error-format callbacks and dot-tracking sinks, their selected table slots, full admitted instruction partitions, data and handoff edges. The caller, numeric visitor, shared error constructor and general formatting controller are existing-work boundaries; their bodies, the earlier 76-name table, complete name parsing, #115 and visor are excluded. No full-component gate is requested.

## Reproduce

From the repository root, with the pinned artifacts and Python 3.12.3:

```sh
python3 tools/aws_scalar_input94.py --out research/work-items/RE-015-aws-scalar-input-94
python3 -m unittest tests.test_aws_scalar_input94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-aws-scalar-input-94 && sha256sum -c MANIFEST.sha256)
```

Two independent generations can be compared with relative output directories:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/aws_scalar_input94.py --out work/aws-scalar-first
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/aws_scalar_input94.py --out work/aws-scalar-second
diff -r work/aws-scalar-first work/aws-scalar-second
```

The collector authenticates the whole target before parsing. It uses Python's standard library and the repository's `elf_index` and `fde_extents` readers, excludes NOBITS sections from file-byte mappings, and directly decodes the reviewed instruction encodings and relocation records. Its limited instruction walker was adapted from the separate HlChain-reader study; unsupported encodings, altered selector targets, invalid branches and changed byte contracts fail closed. It invokes no external program and does not execute the captured binary. GNU objdump 2.42 was used only for human inspection, not for generating evidence. Generated records have no time, environment or local absolute paths.

`functions.tsv` gives the selected FDEs and full body hashes; `instructions.tsv` partitions their bytes, and `branches.tsv` records direct intra-FDE transfers. `dispatch.tsv`, `width-guards.tsv`, `visitors.tsv`, `calls.tsv`, `relocations.tsv`, `context.tsv` and `contracts.tsv` retain the scalar observations. `format-dispatch.tsv` and `format-entries.tsv` bind the selected error kinds to complete templates or length-delimited slices; `flow.tsv` joins the selected call and callback witnesses, with dynamic hops explicitly unresolved. `cases.tsv`, `dot-cases.tsv`, `flag-cases.tsv` and `float-cases.tsv` are conditional static models, not captured executions. `summary.json` records the scoped totals; `MANIFEST.sha256` covers all retained work-item files.

## Evidence

All addresses are linked ELF virtual addresses; file offsets appear separately in the generated tables. FDE ends are exclusive unwind extents, not proof of complete source-level function boundaries or a node-wide function census.

### Relation to the existing name evidence

The existing `constants` packet associates the name table and two string parser boundaries with the prior `NvTestnet` value. Three narrow context call instructions belong to the same previously indexed caller FDE: the instruction at `0x13b6566` calls through relocation slot `0x576e7a0` to the selected scalar dispatcher `0x13c1720`; two other calls in that caller reach the previously catalogued name-parser boundaries `0x13f4360` and `0x13f6410`. This supports an AwsName association for the selected reader, but the caller itself is not selected or reconstructed here. The existing address `0x13f6dc0` is a boundary of the earlier constants window; the present packet neither owns nor analyzes that function's body.

The selected function map separates direct calls from callbacks whose invocation depends on external formatting code:

```text
earlier caller [boundary]
  -> 0x13c1720 scalar dispatcher
       -> unsigned value -> 0x13f6dc0 numeric visitor [boundary]
       -> short input -> local cursor update and tag 1
       -> unhandled selector -> local tag 2
       -> other supported type -> one of eight rejection visitors
            -> 0x13b5360 error constructor [boundary]
            -> descriptor: 0x14abd30 expected-type callback adapter
            -> descriptor: 0x4eb8e30 unexpected-value formatter
                 -> float kind: 0x4eb9100 float-format wrapper
                      -> formatting controller [boundary]
                      -> conditional dot-tracking callbacks:
                         0x4eb8970 string, 0x4eb8950 character,
                         0x4eb8af0 nested formatter
                      -> conditional suffix write [external sink]
```

The rejection visitors are `0x1407ff0` (boolean), `0x14081b0` (nil), `0x1408460`, `0x14089b0`, `0x1408bb0`, `0x1408ca0` (signed widths), `0x1408760` and `0x1408850` (float widths). The arrows from a descriptor to a formatter describe installed callbacks, not direct calls. `flow.tsv` retains their specific instruction and relocation witnesses.

The dispatcher receives a selector byte and a separate payload byte. At `0x13c1725` it subtracts `0xc0` in a 32-bit register, compares with `0x20`, and indexes 33 signed relative offsets at `0x215a1c` when in range. The offsets are relative to the table base. Outside that interval, selector zero forwards the payload to `0x13f6dc0`; other selectors reach the local deferred-result store. These are the function's input bytes, not a claim that every possible selector is reachable from the earlier caller or corresponds directly to a wire byte.

| Selector at this boundary | Observed local route |
| --- | --- |
| `0x00` | Zero-extend the payload and call the external numeric visitor; no local range comparison is made. |
| `0xc0`, `0xc2`, `0xc3` | Call the nil or boolean type-error visitor. |
| `0xca`, `0xcb` | Require 4 or 8 bytes, respectively, convert byte order, and call the matching float type-error visitor. |
| `0xcc` through `0xcf` | Require 1, 2, 4 or 8 bytes, respectively, and forward the resulting unsigned value to the external numeric visitor. |
| `0xd0` through `0xd3` | Require 1, 2, 4 or 8 bytes, respectively, and call the signed type-error visitor. |
| `0xe0` | Forward the separate payload byte to the signed 8-bit type-error visitor. |
| Other selector inputs at this boundary | Store local tag 2 followed by the original selector and payload; do not advance the cursor in this FDE. |

The type labels are inferences from the widths, byte swaps, sign extension, float conversion and prepared error descriptors. The 256 selector-domain rows in `cases.tsv` include hypothetical values at this internal interface; they do not assert that 256 wire encodings reach it. In particular, the local code does not establish which payloads the caller supplies for selectors zero or `0xe0`.

### Cursor, handoffs and failure branches

The dispatcher uses cursor words at offsets `+0x10` and `+0x18` as the current pointer and available count. With a complete fixed-width operand it advances the pointer by the operand width and subtracts that width from the count before the visitor call. The 2-, 4- and 8-byte reads use byte swaps or a 16-bit rotate. When fewer bytes are available than required, the 2-, 4- and 8-byte branches advance the pointer to the end of the available bytes and set the count to zero. The one-byte empty path also returns with count zero and no pointer advance. All of these local short-read paths store result tag 1 and a pointer to the descriptor at `0x56668f8`; its relative relocation and length bind the 27-byte text `failed to fill whole buffer` at `0x216949`.

For example, conditional on reaching this function, selector `0xcc` with one byte `20` consumes one byte and forwards unsigned 32 to `0x13f6dc0`. Selector `0xd0` with the same byte consumes one byte and calls `0x1408460`, which sign-extends it and reaches the shared invalid-type constructor. An empty operand instead takes the local tag-1 path. Values 75 and 76 are both forwarded to the numeric visitor by this FDE; its acceptance bound and returned tag are deliberately not inferred. Consequently, the earlier `NvTestnet` default of 32 must not be conflated with a demonstrated successful binary decode here.

The eight selected error visitors create unexpected-kind descriptors: byte 0 for boolean, 7 for nil, 2 for signed values and 3 for floats. Signed 8-, 16- and 32-bit values are sign-extended; 64-bit values are copied. Float32 is widened before storage, whereas float64 is stored directly. Every visitor references the complete template at `0x20193e`, bytes `0e 696e76616c696420747970653a20 c0 0b 2c20657870656374656420 c0 00`, and calls the prior error-constructor boundary `0x13b5360`. The `0xc0` token interpretation follows the separate format-prefix correction. The selected vtable pointer is `0x5668e78`; its callback slot at `+0x18` relocates to `0x1401120`. Open PR #1531 identifies that callback's length-delimited text as `variant identifier`; the text bytes are retained here, but the callback body and final dynamic formatting sink are not selected. The selected adapter `0x14abd30` loads the callback through a vtable `+0x18` field and tail-transfers to it.

The HlChain reader study in open PR #1364 identifies the shared constructor's normal-return tag as 6. This packet verifies the call handoff and visitor arguments, but treats the constructor's allocation, formatting, return and unwind behavior as external. It therefore does not place a result tag on those modeled error cases. The scalar FDE has no LSDA pointer; this does not exclude a callee unwind or prove process-level behavior.

### Error value formatting and dot tracking

Each visitor supplies an unexpected-value formatter through slot `0x576e758`, whose relocation names `0x4eb8e30`. Its indexed table at `0x7c93b4` selects the four tags actually written by the selected visitors. No bound check is visible before this table lookup, so `format-dispatch.tsv` checks only those four producer-backed entries and does not infer the entire table's domain.

| Descriptor tag | Selected formatter target | Data or external callback |
| --- | --- | --- |
| 0, boolean | `0x4eb8e47` | Complete `boolean` template at `0x1e5964`; callback slot `0x576f218`. |
| 2, signed integer | `0x4eb8f4f` | Complete `integer` template at `0x1fd933`; callback slot `0x576e9d0`. |
| 3, floating point | `0x4eb8f8b` | Complete `floating point` template at `0x1ddd32`; callback slot `0x5777088` relocates to `0x4eb9100`. |
| 7, nil | `0x4eb8fca` | The 10-byte slice `unit value` at `0x7c946b` is sent to a dynamic writer. |

The templates have their literal-length bytes, placeholder token and terminator retained in `format-entries.tsv`. The generic formatting controller and final writers remain external, so these are conditional callback paths rather than a claim that a particular diagnostic was emitted at runtime.

The float callback clears the sign bit and compares the remaining binary64 bits with `0x7ff0000000000000`. Magnitudes at or above that value take a direct formatting call and return its status byte; finite values take a dot-tracking writer path. For a finite value, a nonzero first-format status returns 1. On first-format success, a nonzero dot flag returns 0; a zero flag calls the destination writer with the two bytes `.0`, returning 1 if that call reports a nonzero status and 0 otherwise. The model does not predict the bytes emitted by the external numeric formatter or NaN payloads after widening.

The finite path supplies vtable `0x5750f78`. Its three relocated callback slots name a string sink `0x4eb8970`, a character sink `0x4eb8950` and nested formatting adapter `0x4eb8af0`. Both sinks OR a period-detected bit into the writer's byte at `+8` before forwarding to an external writer. They tail-transfer through distinct destination-vtable slots, `+0x18` for strings and `+0x20` for characters: on a normal return the external destination's status is returned directly, including when that destination reports failure. The character sink compares the full input value with `0x2e`; the string sink uses a scalar route through length 15, then an alignment prefix, a 16-byte word filter and a scalar tail. A possible match in the word filter resumes scalar checking. The finite wrapper's flag is therefore cumulative across these callbacks if the external formatter uses them as observed; the exact callback sequence remains outside this packet.

The fast filter cannot skip a block containing a period under the stated valid-memory assumption: at a matching byte, XOR with the repeated period constant gives zero. The subtraction constant has byte zero in the least-significant position and byte one elsewhere; after either possible incoming borrow, the matching result byte has its high bit clear. The corresponding OR operand also has its high bit clear in both word halves. Thus the mask comparison cannot take the block-skip edge for a true match, and the scalar fallback examines it. A false alarm may still cause a fallback.

### Observations and inferences

Observed: selector guard and 33 table entries, target instruction bytes, branch destinations, selected FDE records, the cursor/result stores, visitor calls, complete template and length-delimited error data, and the listed RELATIVE relocations. `instructions.tsv` records encoded bytes and structural operands rather than disassembler text.

Inferred: MessagePack-like type names, AwsName association and the meaning of the two cursor words. The selected code's signed extension and error-constructor handoff are observations; whether the externally called numeric visitor accepts any particular number is not. No unlicensed reference implementation has been copied.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, toolchain and linker provenance, two-build comparison, runtime differential fixtures and binary equivalence: **not yet implemented or measured**. No byte normalization is applied. External helper, callback, relocation/data closure and whole-ELF identity remain open.

The synthetic cases exercise the selector domain, short and exact widths, values around 32 and the earlier 75/76 name bound, signed extremes, unsigned width maxima, selected raw float patterns, callback status branches and dot-search alignments. They are predictions conditioned on valid input memory and the stated external call returns, not runs of captured instructions. Float cases retain the incoming bits and make no claim about the resulting NaN payload.

## Results and limitations

The generated selection contains 15 FDEs and 2,748 body bytes, partitioned into 690 decoded instruction records; 38 direct branches or jumps, 27 calls, 33 scalar selector slots, 4 selected error-kind slots, 10 width guards, 8 rejection visitors, 12 relative relocations, 3 context calls, 27 selected flow witnesses and 46 reviewed byte contracts are recorded. There are 418 scalar, 568 dot-search, 40 flag-update and 72 float-finish synthetic cases, including the full 256-byte selector domain at this internal boundary. These denominators do not measure component or node coverage.

The focused suite passed 57 tests with no skips. Its controls alter the digest, FDE extent, selector target, guard width and polarity, byte order, sign extension, visitor call and tag, relocation, template, float branch, forwarding slots and short-read text; it also checks out-of-range and non-file-backed mappings. Direct branch displacements, RIP-relative destinations and both table-base calculations have independent byte checks. The dot-search model is compared with an independent byte-search oracle for every dot position through length 80 at all eight alignments and for 786,432 two-byte/filler placements. A separate local arithmetic check covers each matching byte position and possible incoming borrow; the finite oracle cases do not prove every longer input. Two generations with distinct hash seeds and time zones matched byte for byte, including with only Python on PATH. Artifact verification, catalogue consistency and the inventory/literal reproduction check passed. The full repository test suite was not run under the memory constraint, and no hosted CI result is claimed.

This packet does not resolve caller marker normalization, the numeric visitor's bounds and result tags, output construction inside the shared error helper, allocator/formatter behavior, runtime memory validity or any whole-component reconstruction gate. All four `constants` gates remain false. Next, after coordinating ownership of the cited numeric visitor and caller, connect a valid caller input through numeric acceptance or rejection and compare an independently implemented reader with authorized target-grounded fixtures.
