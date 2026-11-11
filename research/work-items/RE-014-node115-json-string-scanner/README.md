# Node #115 shared JSON string scanner

Partial HL115-086. Original ELF SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
This packet reads original bytes as data and runs independently authored source;
it does not execute or emulate captured instructions. All component gates are false.

## Prior consumers and new shared dependency

Merged #4236/#3388 and open #4336/#4399/#5088 contain surrounding enum-reader or
caller contracts. In particular #4336 explicitly stubs the shared string parser.
This packet resolves caller slot `0x64e08f8` to `0x5c56b60` and closes its ordinary
strict-mode byte scanning, output ownership, escape decoding and cursor effects.
It does not repeat the enum vocabulary or infer enum policy from a scanner.

The existing margin-mode reader `0x1e201f0` provides a concrete integration:
`0x1e20264` checks the opening quote; `0x1e20277` stores the advanced input cursor;
`0x1e2027b` clears scratch length; `0x1e2028b` calls the shared slot. It treats
scanner result tag 2 as error at `0x1e20291`. The new source starts immediately
after the opening quote, as this consumer does. Caller-specific error finishing
and enum value acceptance remain prior/unclosed scope.

## Borrowed versus scratch output

The reader descriptor is input pointer, byte length, cursor at +0/+8/+0x10. The
scratch descriptor is capacity, pointer, length at +0/+8/+0x10. `0x5c567c0` and
its scalar tail `0x5c569e0` advance to the first quote, backslash, byte below 0x20,
or end. Bytes at or above 0x80 are scanned as ordinary bytes; this function does
not establish that those raw bytes are valid UTF-8.

At a closing quote, the cursor advances past it. If scratch length is zero, the
result is tag 0 with a slice into the original input. Otherwise the pending run
is appended to scratch and result tag 1 points to the complete scratch contents.
The source exposes borrowed slices with lifetimes bound to their actual backing
input/scratch. It preserves a preexisting scratch prefix rather than silently
clearing it; the concrete enum caller clears its own scratch before entry.

At a backslash, the pending raw run is first appended and the cursor advances past
the backslash. `0x5c55f50` consumes the next byte and maps quote, backslash, slash,
b/f/n/r/t to 0x22/0x5c/0x2f/8/12/10/13/9. Its complete jump table is pinned.
A `u` escape calls `0x5c56110` with strict flag 1.

## Unicode and exact error stops

`0x5c571d0` reads four hex digits. With four available bytes it advances by four
**before** rejecting any invalid digit. With fewer than four it moves to end and
reports EOF. Both case variants A..F/a..f are accepted through pinned nibble tables.

Strict mode rejects an initial low surrogate. A high surrogate requires the next
two bytes to be backslash and lowercase `u`, then four more hex digits forming a
low surrogate. A valid pair produces the standard supplementary scalar and four
UTF-8 bytes; ordinary code units produce one, two or three bytes. Permissive mode0
surrogate handling is visible in the original FDE but is outside this selected
scanner contract.

The model returns the raw error code immediately before the native error object
is constructed. It does not implement native allocation, formatting, line/column
calculation or destructor behavior. The important cursor/scratch states are:

| Condition | Code | Cursor | Scratch effect |
| --- | --- | --- | --- |
| EOF during ordinary run | 4 | End | Pending raw run not appended |
| Unescaped byte below 0x20 | 16 | After offending byte | Pending run not appended |
| Invalid simple escape | 12 | After escape byte | Run before backslash retained |
| Invalid four-digit hex | 12 | After all four bytes | No partial scalar appended |
| Short hex escape | 4 | End | No partial scalar appended |
| Initial low / invalid second surrogate | 20 | After that code unit | No scalar appended |
| High surrogate followed by non-backslash | 23 | After that byte | No scalar appended |
| High surrogate followed by backslash, non-u | 23 | After both bytes | No scalar appended |
| EOF after high surrogate or its backslash | 4 | End | No scalar appended |

Prior successfully decoded escapes remain in scratch on later failure. Input and
scratch must be valid, nonoverlapping storage, cursor must be at most input length,
and allocation must succeed. Native allocation growth/failure, SIMD performance
and pointer ABI are not reproduced by the safe scalar implementation.

## Validation

```
python3 research/work-items/RE-014-node115-json-string-scanner/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-json-string-scanner/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-json-string-scanner/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-json-string-scanner/Cargo.toml
cargo +1.95.0 clippy --manifest-path src/node115-json-string-scanner/Cargo.toml --all-targets -- -D warnings
```

Five tests pass in debug/release. The Unicode test checks all 1,112,064 valid
Unicode scalars against Rust's independent standard encoder. The delimiter test
checks all 256 bytes at each offset 0..32 (8,448 cases). Other fixtures establish
borrowed pointer identity, scratch prefix retention, simple escapes, raw high-byte
handling, malformed surrogate/hex input and exact error cursor/scratch states.
Formatting and strict Clippy pass. The static verifier checks 7 windows / 2,694
bytes / 682 instructions, literal tables, shared call binding and 32 semantic
corruptions beyond digest-only guards. Repository checks are reported in the PR.
Static/source agreement is not an executed native equivalence claim.

Source and evidence are independently authored under MIT; no vendored parser
implementation has been copied.
