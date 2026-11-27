# EVM JSON bytes writer: `0x`-prefixed serialization in node #115

- **Component:** `evm`; bounded contribution to the existing EVM JSON path.
- **Task context:** the `evm-send-to-evm-data-json-115` packet left bytes writer `0x25ce7e0` as a recording stub and named it as its next question. This packet traces that writer into the existing hex formatter and JSON string escaper.
- **Target:** Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Source revision:** `ec87b0e812f363a43abaa26e6c9c4c808bf9a285`.
- **Claim status:** static observations for exact call sites, FDE extents, relocations, and the lowercase hex alphabet; inference for the successful JSON value produced by combining those helpers. Allocation/error and runtime configuration behavior remain unresolved.
- **Progress:** no component gate is requested or advanced.

## Reproduce

From the repository root, with the pinned node #115 artifact:

```sh
python3 tools/evm_json_bytes_writer_115.py --out research/work-items/evm-json-bytes-writer-115
python3 -m unittest discover -s tests -p 'test_evm_json_bytes_writer_115.py' -v
sha256sum -c research/work-items/evm-json-bytes-writer-115/MANIFEST.sha256
```

The collector checks the target size and SHA-256, parses `.eh_frame` and `.rela.dyn`, verifies exact instruction and rodata bytes, and writes `records.json`. It reads the ELF only; the captured executable was not run or emulated. `disassembly.txt` retains GNU binutils 2.47.20260726 output for the three relevant FDE ranges.

## Evidence

Addresses are ELF virtual addresses. File offsets are derived from the file-backed `.text` and `.rodata` section headers. FDE ranges are unwind extents, not source-level function-boundary claims.

1. The existing `evm-send-to-evm-data-json-115/callees.tsv` records the call from entry writer `0x2591f70` at `0x2591fba` to bytes writer `0x25ce7e0`. The target bytes at `0x2591fb0` show the value pointer, length and serializer being passed.
2. The FDE `[0x25ce7e0, 0x25ce8cb)` calls formatter `0x2a315b0` with the input slice. The formatter computes `2 * length + 2`, writes bytes `0x`, then converts each byte to two hex digits through lookup table `0x455d40`.
3. `0x455d40` contains `0123456789abcdef`. The scalar path at `0x2a31660` uses this table for low and high nibbles. A configuration bit mask `0x200` selects the vectorized helper at `0x2a31790`; that helper also loads the same lookup table. The purpose and live value of the configuration bit are not identified.
4. After the temporary string is prepared, `0x25ce7e0` appends an opening quote to the serializer Vec, calls the existing JSON escape helper `0x25bf330` with the temporary string pointer/length, and appends a closing quote. It reserves one byte before either quote when the Vec is full. The temporary String is freed on the observed normal and unwind-cleanup paths when its capacity is nonzero.
5. Relocation witnesses bind allocator, allocation-error, deallocator and formatter-configuration slots to the recorded relative addends. Existing work item `evm-send-to-evm-data-json-115` covers the shared escaper; this packet does not re-claim its body.

### Inference and limits

On the successful formatting path, the helper produces `0x` followed by two lowercase hexadecimal digits per input byte. An empty input therefore formats as `0x`. The bytes writer wraps that ASCII string in JSON quotes and sends it through the JSON string escaper; those characters need no JSON escaping. This supports the successful JSON value `"0x<lowercase hex>"`.

This does not establish allocation-failure behavior, the complete `Result` contract, the configuration bit's meaning, or runtime reachability. The upstream entry writer ignores the bytes writer's return value; that is not proof that every allocation or output path succeeds.

## Checks

- `make doctor`: passed; `analysis_ready=true`, `exact_rebuild_ready=false` because recovered manifests/locks, exact Linux build flags/fork provenance and an accepted reconstruction/harness remain missing; Java/Ghidra unavailable.
- `make verify`: passed after initializing the pinned `upstream/*` submodules; artifact signatures, 32 imports and 4,850 evidence-packet manifests / 34,470 entries verified.
- `make catalogue-check`: passed before packet changes.
- Focused tests, final result and `make test` status are recorded in `runtime.log`.
- No captured executable was run or emulated.

Next question: establish the serializer error/return contract under controlled offline evidence and determine whether the configuration bit has a supported runtime value, without claiming a full EVM component gate.
