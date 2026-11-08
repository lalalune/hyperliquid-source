# node-runtime: reconstruct node #115 CLI value-parser callbacks (u64, bool, IPv4, address)

This packet makes the clap value-parser callbacks that RE-012 only located
(`0x56544b0` u64, `0x56547d0` bool, `0x56546c0` IPv4 with its reader `0x167ccb0`,
and the two address wrappers `0x5654920` / `0x5654a90`) reconstructable as
executable Python: exact accept/reject grammar, which of three Rust error texts
is returned, when the owned argument buffer is released, and the call order of
the address wrappers, each replayed from the ELF bytes and compared with the model.

- Component ID: `node-runtime` (Node runtime and gossip; CLI startup path)
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: observation (replay agreement), inference (model grammar, stub semantics)
- Scope: the six function bodies listed under Evidence. Excluded: the address
  parser behind slot `0x64e0b88`, the address Display paths (`0x46ef710`, `0x1456ae0`),
  the common-options helper, clap's use of the callbacks, any Rust source claim.

## Reproduce

From the repository root, with the pinned binary at `artifacts/node/115/hl-node`
(no binary is executed, no `objdump`/`readelf`, standard library plus the shared
`tools/elf_index.py` and `tools/fde_extents.py` only):

```sh
python3 tools/node_runtime_cli_validators_115.py --out research/work-items/node-runtime-cli-value-parsers-115
python3 -m unittest tests.test_node_runtime_cli_validators_115
(cd research/work-items/node-runtime-cli-value-parsers-115 && sha256sum -c MANIFEST.sha256)
```

The tool refuses any input whose SHA-256 differs from the one above. Output is
deterministic (fixed seed 115, no clock, no absolute paths). Peak memory is well
below 1 GB; cases are generated, replayed and compared one at a time.

## Evidence

Coordinates are ELF virtual addresses, `.text`; FDE extents come from
`fde_extents.fde_extents` and are listed in `function-extents.tsv`.

| Function | VA | FDE end | Role |
| --- | --- | --- | --- |
| u64 callback | `0x56544b0` | `0x56546c0` | `u64::from_str` style check, result discarded |
| IPv4 callback | `0x56546c0` | `0x56547cc` | length gate (<=15), reader call, end-of-input test |
| IPv4 reader | `0x167ccb0` | `0x167d082` | 978-byte dotted-quad reader, returns bool |
| bool callback | `0x56547d0` | `0x5654913` | exact `true` / `false` |
| address wrapper A | `0x5654920` | `0x5654a8d` | slot `0x64e0b88` parse, error path with tag `0xb3` |
| address wrapper B | `0x5654a90` | `0x5654bea` | slot `0x64e0b88` parse, error path formats then drops |

Observed by replay (every number below is a measurement of the bytes, the
agreement counts are in `summary.json` and `measure.json`):

1. **Result convention.** Success writes `0x8000000000000000` to the first output
   word and nothing else; the parsed value is not returned. Failure writes a
   24-byte `String` (cap, ptr, len; cap == len after the message is appended).
   The input `String` is released through the allocator slot `0x64df4a0`
   (`0x635de30`) as `(ptr, cap, 0)` exactly when its capacity word is non-zero,
   on success and on failure alike. Replay checks this for every case with
   capacity 0 and 32/24/48.
2. **u64.** Empty input: "cannot parse integer from empty string" (`0x479018`, 38).
   One optional leading `+`; `-` is not special (it is an invalid digit). A lone `+`
   or `-` is "invalid digit found in string" (`0x47903e`, 29). After the sign,
   fewer than 17 bytes take a digits-only loop (always `ok`); 17 or more take a
   checked loop: `acc * 10` overflow (`mul`, `jo`) classifies the byte already
   loaded (digit -> "number too large to fit in target type" `0x47905b`, 38;
   non-digit -> invalid digit), then `acc + d` carry -> too large. So
   `18446744073709551615` and any run of leading zeros ahead of it pass, while
   `...616`, `...620` and `...6150` are too large, `...6150a` is too large (the
   multiply overflows on the `0` before `a` is read) and `9999999999999999999x`
   is an invalid digit.
3. **bool.** Length 4 with dword `0x65757274`, or length 5 with dword `0x736c6166`
   plus byte `e`; anything else gives "provided string was not `true` or `false`"
   (`0x478fe8`, 41). All single-byte mutations of both words are rejected.
4. **IPv4.** Lengths above 15 skip the reader. The reader accepts exactly four
   decimal octets of 1-3 digits, value <= 255, no leading zero unless the octet is
   `0`, separated by `.`, with nothing left over (callback tests `rax & (len == 0)`).
   Failure returns the 16-byte fixed text `NodeIpParseError` (`0x453ab0`), built
   through the reserve helper `0x5963a10` and a 16-byte `movups`.
5. **Address wrappers.** Both call the same `RELATIVE` slot target `0x150d640`; its
   result byte `1` means error. Wrapper A (`0x5654920`): drop the error object via
   its vtable slot 0, rewrite the result tag to `0xb3`, format with `0x46ef710`
   into a fresh `String`, drop the result with `0x5630000`. Wrapper B (`0x5654a90`):
   format the error object with `0x1456ae0` first, then drop it through the vtable.
   A formatter failure reaches the `unwrap` panic call (`0x1680c30`) followed by `ud2`.
6. **Branch coverage.** `branch-coverage.tsv` lists every conditional jump the
   replay of the first four bodies took and did not take. Five jumps are never
   taken one way: the allocation-failure/format-failure edges of the u64 and bool
   callbacks (`0x565460c`, `0x5654856`), the empty-after-sign short-loop edge
   `0x5654529` (unreachable: handled earlier) and two reader edges
   (`0x167cd3c`, `0x167ce22`). They are unresolved, not claimed.

## Implementation and comparison

`tools/node_runtime_cli_validators_115.py` contains three parts.

* **Interpreter.** A decoder/executor for the exact x86-64 subset in these bodies
  (ALU, `lea`, `mov`/`movzx`, `mul`, `neg`/`not`, shifts, `cmov`, `setcc`, `jcc`,
  SSE `movups`/`movaps`, direct and `RELATIVE`-slot indirect calls, vtable calls)
  with real flag semantics. Unknown opcodes raise `Unsupported`; an indirect call
  through a slot that is not a `RELATIVE` relocation is refused. The step limit
  catches infinite loops.
* **Stubs (assumptions).** Callees outside the bodies are replaced: `0x167fa70`
  (appends the message to the `String` in the formatter), `0x635de30` (records the
  release), `0x5963a10` (reserve), `0x1680c30` (panic -> `Unsupported`), and for
  the wrappers the parser, both formatters, the result drop and the vtable drop,
  each with a scripted outcome. Their real bodies are not analysed here.
* **Models.** `model_u64`, `model_bool`, `model_ip` + `parse_ipv4`, `model_wrapper`
  are written from the observations above, not copied from any source tree.

Generated cases (`DEFAULT_COUNTS`, seed 115): u64 6,400, bool 1,800, IPv4 6,400,
wrapper A 1,500, wrapper B 1,500 (17,600 total). u64 verdicts: ok 2,718, big 1,558,
digit 2,089, empty 35. IPv4: accept 1,398, reject 5,002. Each case runs with and
without an owned buffer.

Negative controls (52, all detected, in `negative-controls.tsv`): 23 wrong models
(accepts `-`; `MAX-1` limit; no `+`; signed range; wrong empty text; case-insensitive
bool; prefix bool; `1`/`yes` accepted; IPv4 length gate 14; octet 256; leading zeros;
trailing dot; three octets; wrapper call-order swaps; missing result drop; tag
`0xa0`; no release on error; format failure ignored), 23 single-byte damages to the
retained bodies (limit constants, compare bytes, branch polarity, message pointer),
and 6 range/input controls (digest mismatch, address outside alloc sections, address
beyond the image, unknown opcode, non-`RELATIVE` indirect slot, step limit).

## Results and limitations

`measure.json`: cases 17,600, negative controls 52, detected 52, mismatches 0.
Unit tests: 34, no skips. This claims that the six bodies behave as modelled on
the generated inputs under the stated stubs; it does not claim byte identity of a
rebuilt function, the address grammar behind `0x150d640`, Display text of address
errors, or how clap orders its calls. Equivalent mutants were removed from the
control list rather than counted. Rust ABI shapes (`String` triple layout) are inferred from
the writes. No progress gate is requested.

Next question: replay `0x150d640` (the address parser) and its two formatters so the
wrapper stubs become real callees.
