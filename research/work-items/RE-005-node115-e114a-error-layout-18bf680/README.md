# RE-005: bound the E114A helper result at `0x18bf680`

- **Component:** `action-dispatch`; bounded helper contract under [issue #3924](https://github.com/lalalune/hyperliquid-source/issues/3924).
- **Target:** Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Source/reference revision:** repository base `cd73b12bb15ca9a27dbc539bb532d13f3d2c533d`; no external source or reference was used.
- **Claim status:** exact target-byte observations for two FDE bodies and a `.rodata` span; bounded layout interpretation from their direct dataflow. Source-level enum names, payload meaning and callback semantics remain unknown.
- **Scope:** the 118-byte helper FDE `0x18bf680..0x18bf6f6`, its 154-byte constructor FDE `0x18be120..0x18be1ba`, the relocated 408-byte formatter-wrapper FDE `0x141e3a0..0x141e538`, and the 32-byte format-text witness at `0x44f07a`. No other E114A helpers, full Action path, runtime values or completion gate are claimed.

## Reproduce

Validated on macOS 27.2 arm64 with Python 3.14.3 and GNU binutils 2.47.20260726. From the repository root:

```sh
python3 tools/re010_e114a_error_layout_18bf680.py --out research/work-items/RE-005-node115-e114a-error-layout-18bf680/records.json
python3 -m unittest tests.test_re010_e114a_error_layout_18bf680 -v
objdump -d -M intel --start-address=0x18bf680 --stop-address=0x18bf6f6 artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x18be120 --stop-address=0x18be1ba artifacts/node/115/hl-node
readelf -rW artifacts/node/115/hl-node | rg '64dfed0|64df6e8|64df480|64df508|64df498'
sha256sum -c research/work-items/RE-005-node115-e114a-error-layout-18bf680/MANIFEST.sha256
```

The collector authenticates the complete ELF before parsing section headers, requires the exact FDE extents, checks the SHA-256 of each complete FDE body, checks the literal bytes, and parses the required `.rela.dyn` entries. It does not execute or emulate the node. `raw-disasm.txt` preserves all three complete FDE disassemblies; `relocations.txt` preserves the matching relocation rows.

## Evidence

All addresses are ELF virtual addresses. The collector maps `.text` and `.rodata` through ELF section headers and stores complete function bytes and their hashes in `records.json`.

1. The existing [variant payload-dispatch packet](../RE-010-variant-payload-dispatch-115/README.md) maps 17 E114A variants (2, 7, 8, 12, 14, 16, 17, 19, 20, 21, 70, 71, 75, 92, 100, 102 and 109) to direct helper `0x18bf680`. That packet treats payload helpers as opaque contracts and names neither the enum nor payload type; the new collector checks this crosswalk list remains stable.
2. At `0x18bf680`, the incoming output pointer is retained in `rbx`; the helper passes `out+8`, format-text address `0x44f07a`, and a stack descriptor to `0x18be120`. After that call it stores the 64-bit value `1` at `out+0` and returns the original output pointer.
3. At `0x18be120`, the constructor writes byte `6` at its output base and stores three qwords at offsets `+8`, `+16`, and `+24`. Since its output base is `out+8`, these stores account for the remaining 32 bytes of the helper's 40-byte result.
4. In the low-bit-set branch, the constructor shifts the input word right by one. For a nonzero resulting length, it allocates that many bytes and copies from the saved pointer through the `memcpy` relocation; for zero length it uses pointer sentinel `1`. It then stores `(length, pointer, length)` in the three qword slots. The branch where the low bit is clear calls GOT slot `0x64df6e8`; the relocation resolves to `0x141e3a0`.
5. At `0x141e3a0`, the formatter wrapper computes a buffer size from the input format bytes, allocates a buffer, builds a local three-qword string record, and calls the relocated formatter at slot `0x64df6f0` (target `0x1680500`) with the local record, static data and descriptor. If the formatter returns zero, it copies the local string record into the caller-provided output; the nonzero branch calls a separate error routine and traps. Its overflow cleanup path frees the temporary record's allocation and resumes unwinding. This closes the callback target and immediate call flow, but not the semantics of `0x1680500` or the exact formatted string.
6. `.rodata` at `0x44f07a` begins with bytes `0e 69 6e 76 61 6c 69 64 20 74 79 70 65 3a c0 0b 2c 20 65 78 70 65 63 74 65 64 20 c0 00 2f 68`. This is a byte witness for a tagged formatting template; the `0xc0` bytes are retained as raw data and are not interpreted as ordinary text.

The combined layout is therefore observed as an outer 8-byte value `1`, followed by an inner 32-byte object with leading tag byte `6` and three constructor-produced qwords. For one constructor branch the qwords have length/pointer/length dataflow. These observations do **not** prove Rust `Result`/enum type names, the meaning of tag `6`, ownership semantics, the final formatted text, or the semantics of the delegated callback.

## Results and limitations

- `python3 tools/re010_e114a_error_layout_18bf680.py ...`: expected to regenerate the target-bound `records.json` byte-for-byte.
- Focused tests verify record regeneration, reject a changed target digest, reject corruption in each full FDE, reject the `0x64df6e8` relocation addend changing, and reject a changed format-text byte.
- No binary execution, ABI runtime comparison, or source-level payload implementation is included. Formatter target `0x1680500`, runtime reachability, and semantic enum names remain open. No component gate is requested.
- **Next question:** inspect formatter target `0x1680500` to establish which descriptor fields and format arguments determine the emitted bytes, then identify E114A arms that consume this exact result.
