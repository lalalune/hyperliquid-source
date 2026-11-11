# RE-012: follow the node #115 `info` string through `%s` formatting to its selected buffer callback

- Component ID: node-runtime (RE-012, APIs/gossip/startup)
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: **static observations** of a selected caller, format string,
  variadic bridge, `%s` dispatch/body and callback. No source ownership, CLI
  behavior, completed output, or reconstruction claim is made.
- Scope: resolve the first `%s` argument in the selected format call, identify
  the machine-code branch for the `s` conversion, and trace the selected
  callback through its bounded temporary-buffer formatter to its accumulator.
- Excluded: the second `%s` value's semantics, full format grammar, callback
  destination after accumulation fills, source/dependency ownership, CLI
  reachability, and execution of the captured target.

## Reproduce

All analysis is static. The exact captured target and the separate visor both
passed signature verification in `make verify`; pinned imports also passed.
`make reproduce` regenerated both imported inventories byte-for-byte. The
recorded environment is macOS arm64, Python 3.14.3, Apple LLVM
`llvm-objdump` 21.0.0, and xcrun at
`/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.

```sh
make verify
make reproduce
python3 tools/fde_extents.py --release 115 --output-dir work/info-format-verification
xcrun llvm-objdump -d --start-address=0x63d4cc0 --stop-address=0x63d4d38 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x63d3d27 --stop-address=0x63d3d66 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x63d3bd3 --stop-address=0x63d3c92 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x63bf52c --stop-address=0x63bf5b6 artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x63be94e --stop-address=0x63bf47c artifacts/node/115/hl-node
xcrun llvm-objdump -d --start-address=0x636c530 --stop-address=0x636c612 artifacts/node/115/hl-node
python3 -B research/work-items/RE-012-node115-info-string-format-sink/verify.py
```

The reproducible verifier checks the full target digest, exact `.eh_frame`
extents, raw code/data exhibits, the NUL-terminated `info` and format literals,
and the signed relative jump-table calculation for `s`. `make doctor` was run;
it returned nonzero because GNU `objdump` and `readelf` are absent from this
macOS environment. Apple LLVM was used directly for the retained disassembly.
No tool install or target execution was performed.

The packet verifier also flips the low bit of a synthetic copy of the table
displacement and confirms that the corrupted value no longer resolves to the
recorded `s` branch. This is a data-corruption control; it does not emulate the
formatter.

## Evidence

Coordinates are ELF virtual addresses. The exact FDE parser found 135,313 FDEs
and 135,313 unwind-table entries with no parse errors or unmatched records; its
documented limit remains that an FDE is an unwind extent, not a proven source
function boundary. Relevant extents:

| Role | FDE range | Bytes | FDE record |
| --- | --- | ---: | --- |
| selected context owner | `0x63d4bbe..0x63d5428` | 2,154 | `0x103a7cc` |
| format-key helper | `0x63d3d27..0x63d3d66` | 63 | `0x103a49c` |
| variadic bridge | `0x63d3bd3..0x63d3c92` | 191 | `0x103a424` |
| callback dispatcher | `0x63bf52c..0x63bf5b6` | 138 | `0x1037b10` |
| custom formatter | `0x63be94e..0x63bf47c` | 2,862 | `0x1037aa8` |
| selected buffer accumulator | `0x636c530..0x636c612` | 226 | `0x102f078` |

In the selected caller, `0x63d4cd8` loads callback address `0x636c530` into
the context object at stack offset `0xa8`; the adjacent field at `0xb0` holds
the output context pointer. At `0x63d4d18`, a RIP-relative `lea` resolves to
the NUL-terminated `info` bytes at `0x4312f2`. The caller passes that pointer
through helper `0x63d3d27`.

That helper retains the input pointer in `rbp`, then places it in `rdx`; it
places the format literal at `0x449912` in `rsi` and a conditional string
pointer in `rcx`. The format bytes are `"%s":%s\0`. It calls
`0x63d3bd3` with `eax=0`. The variadic bridge saves `rdx` and `rcx`, sets the
SysV `va_list` general-register offset to `0x10` and floating-register offset
to `0x30`, then calls `0x63bf52c`. Under that saved argument order, the first
unnamed general-register argument is the saved `rdx` value, the `info` pointer.

The selected caller initializes the callback/context fields consumed by the
bridge. The dispatcher receives `0x636c530` as its callback and a 4,096-byte
temporary formatting buffer. It calls `0x63be94e` with the format and
`va_list`, then invokes the selected callback with the context and formatted
buffer pointer.

For the `s` conversion, the formatter subtracts ASCII `c` (`0x63`) from the
conversion byte, uses that index to load a signed 32-bit relative offset from
the table at `0xb9e790`, adds the offset to the table base, and jumps. The
index is 16; the retained table entry at `0xb9e7d0` resolves to `0x63bf226`.
That branch advances the `va_list` by one general-purpose slot and loads the
string pointer. The format contains an unqualified `%s`; the parser's no-
precision path stores `-1`, which reaches the branch that calls `strlen` and
copies the resulting bytes into the temporary formatter buffer. This establishes
the first formatted field consumes the `info` pointer.

The selected callback at `0x636c530` measures the formatted string, copies it
into an accumulator, advances its length field, and, when that accumulator
reaches its capacity, terminates it and calls a function pointer stored in the
accumulator object. This packet does **not** establish which destination that
later function pointer reaches or that the selected record completed output.
It does not claim that the surrounding operation is CLI dispatch or that the
formatted bytes are a JSON document.

Related work: merged #2829 binds the `info` literal to its format-key consumer;
#2363 records its literal reference; #2863 includes the large owner FDE in a
separate bin-table caller analysis but does not claim this formatting path.
Those works are cited to mark overlap boundaries; this packet claims only the
formatter's `%s` dispatch and the selected callback chain described above.

## Implementation and comparison

Not implemented or measured. No Rust reconstruction, source map, compiler
claim, or byte comparison against rebuilt source exists. No component gate is
requested or advanced.

## Results and limitations

- One target literal (`info`) is followed through one recorded caller and one
  selected callback path; one of the format's two `%s` conversions is resolved.
- The `%s` branch is selected by one checked table entry out of the formatter's
  17-entry `c` through `s` dispatch range. This denominator is only that table
  span, not all formatter conversions or all consumers.
- No captured executable, visor, service, network, or chain action was run.
- FDE boundaries do not prove source-level functions. The format grammar,
  second string's meaning, callback's terminal destination, external callers,
  and source ownership/licensing remain unknown.
- This packet keeps all reconstruction gates false.

Next question: identify the selected callback object's terminal function
pointer and output destination from its actual initialization and consumers,
without inferring a CLI or JSON role from the text.
