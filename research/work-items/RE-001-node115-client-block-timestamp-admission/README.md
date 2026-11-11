# RE-001: node #115 ClientBlock timestamp decoder admission

- Component: ClientBlock header deserialization; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Four complete FDEs: decoder `0x4ece880..0x4eceac3`; header context `0x59d5ea0..0x59d6516`; signed scalar context `0x5659e00..0x5659f65`; nanosecond scalar context `0x5821150..0x5821243`. Exclusive ELF virtual-address ends. Gates remain false.

## Finding

The header calls the timestamp decoder after its address/hash-vector fields and before the BlockParent discriminant. The timestamp is decoded as a little-endian signed-varint seconds value, followed by an unsigned-varint u32 nanosecond value. The already-recovered scalar encodings are context. The new boundary is their ordered admission into the packed date/time representation.

Seconds are split by floor division into an epoch-day index and a nonnegative second-of-day in `0..86399`. The native multiply/shift performs truncating division first, then adjusts a negative remainder. Thus `-1` becomes day -1 / second 86399; `-86400` becomes day -1 / second 0. The day is shifted by 719163 into the calendar helper's CE-day coordinate. A value outside signed32 is rejected before `0x1628f50`; a zero result from that prior-proven Gregorian constructor is also rejected.

Nanoseconds must be at most 1,999,999,999. Values below 1,000,000,000 are accepted at every second. Values from 1,000,000,000 through 1,999,999,999 are accepted only when the second-of-minute is 59. The native multiply/add/rotate predicate is exhaustively compared over every second-of-day with this modulo-60 condition. It does not consult a historical leap-second table.

| Seconds | Nanoseconds | Calendar helper succeeds | Local result |
| --- | --- | --- | --- |
| 0 | 999999999 | Yes | success |
| 0 | 1000000000 | Yes | invalid timestamp |
| 59 | 1999999999 | Yes | success |
| -1 | 1000000000 | Yes | success |
| 59 | 2000000000 | Yes | invalid timestamp |
| Any | Any | No | invalid timestamp |

Success returns raw tag 18 and places the packed date word at output +4, second-of-day at +8 and nanos at +12. A semantic failure formats the original seconds and nanos into a custom error with raw tag 17. Scalar failure tags and their active payloads propagate before semantic checks; reserved/padding bytes are not claimed.

In bounded decoder mode 1, an eight-byte accounting claim happens before reading seconds. Claim overflow rejects without updating the count; exceeding the limit after a nonoverflowing addition leaves the increased count. After seconds succeeds, the u32 wrapper similarly claims four bytes before reading nanos. The accounting charges represent decoded scalar sizes, not the variable number of input bytes. A first-scalar failure prevents the second scalar call. A second-scalar or semantic failure does not roll back bytes already consumed by successful earlier scalar reads. Mode 0 bypasses these accounting claims. Primitive-internal malformed-prefix behavior remains in the prior scalar packets, rather than being redefined here.

## Limits

The Gregorian constructor, scalar integer encoding, error formatting and other ClientBlock fields remain explicit helper boundaries. This packet closes the timestamp caller's predicates, ordering, field placement and preservation of helper consumption; it does not claim complete malformed-varint reconstruction, date arithmetic, BlockParent semantics or full message equivalence. No captured code is executed or emulated.

The relations derive division, nanosecond and modulo constants from native operands, compare signed64 division with independent `divmod`, enumerate all 86,400 seconds-of-day at seven nanosecond boundaries, and probe first-error precedence under supplied helper statuses/consumption. Four actual instruction mutations distinguish the inclusive upper bound, leap-second polarity, date failure branch and day unit.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-client-block-timestamp-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-client-block-timestamp-admission/verify.py --controls
python3 research/work-items/RE-001-node115-client-block-timestamp-admission/relations.py
python3 -m unittest discover -s tests -p 'test_node115_client_block_timestamp_admission.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-client-block-timestamp-admission/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

[PR #2420](https://github.com/lalalune/hyperliquid-source/pull/2420) owns `RE-014-daycount-date-115` and Gregorian constructor `0x1628f50`; [#2802](https://github.com/lalalune/hyperliquid-source/pull/2802) owns epoch/CE-day conversion in the clock producer. Historically observed [#2611](https://github.com/lalalune/hyperliquid-source/pull/2611) owns signed scalars; [#2412](https://github.com/lalalune/hyperliquid-source/pull/2412) owns the u32 primitive, also reconstructed by [#2902](https://github.com/lalalune/hyperliquid-source/pull/2902). [#2808](https://github.com/lalalune/hyperliquid-source/pull/2808) covers leap-second display while leaving constructor checks outside its claim. The timestamp decoder's combined acceptance and failure order are the bounded addition here.

GPT-6.1 Terra searched open and closed PR metadata and available file evidence. The retained audit describes unavailable historical PR content and patch limits; unavailable material prevents an absolute uniqueness guarantee. New analysis and relations are independently authored under MIT; ELF/export/corruption scaffolding adapts existing MIT packets. No unlicensed inferred source is copied or input rights changed. Full component completion, source equivalence and hosted CI are not claimed.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
