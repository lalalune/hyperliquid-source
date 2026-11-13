# EvmState completion-marker write boundary

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. This is partial HL115-012 / RE-017 research. No captured program was executed or emulated.

Two selected node paths construct the typed `CHECKPOINT_COMPLETE_EvmState` path and pass it to a file helper with an empty payload. On the helper's selected absent-file path, the existing temporary-file writer runs before a separate adapter constructs an `mv` command from the temporary and destination paths. Both selected callers dispose of a nonzero returned error object before continuing. This identifies a marker write boundary and error handling, not a guarantee of a valid or durable checkpoint.

## Prior work and new observation

[#4127](https://github.com/lalalune/hyperliquid-source/pull/4127), `RE-017-node115-restore-marker-paths`, owns restore's regular-file admission checks and identifies selector 2 as `EvmState`; it does not establish publication order. `RE-009-abci-state-export-115` separately establishes that `0x15024a0` writes a supplied buffer to a generated temporary path through `0x5ca5110`, then reaches `0x1502da0` on the selected normal continuation. [#3538](https://github.com/lalalune/hyperliquid-source/pull/3538) maps a separate fsync boundary. Those observations are credited and reused, not claimed as new.

The new join is the actual typed-marker caller → absent-marker helper → empty temporary-file write → move-command boundary, plus the callers' returned-error handling. It does not yet bind preceding checkpoint output, flush/close, all error arms, crash behavior, or the externally executed command's actual effects. Existing markers and partial checkpoint directories can predate this call. Restore contents are not authenticated by this result.

## Typed path and selected calls

At `0x2ad9724`, the first selected caller obtains a path-shaped value via `0x25d3e50`, then calls `0x1696b90` with selector 2 at `0x2ad9749`. A second caller obtains a path-shaped value at `0x2cb11ad` and makes the same selector-2 call at `0x2cb11cf`. The formatter uses selector-indexed pointer/length tables: selector 2 identifies the eight bytes `EvmState`; its format record is the typed `/CHECKPOINT_COMPLETE_` suffix. Both callers forward the resulting pointer and length to `0x1505a50`, at `0x2ad9768` and `0x2cb11e8` respectively.

If this helper returns a nonzero pointer, each caller loads its first word and invokes that object's first virtual method; both proceed to local path cleanup. This records selected returned-error disposal rather than proving why the helper returned nonzero or what the virtual method does.

## Absent-marker helper and move boundary

`0x1505a50` first calls the regular-file-shaped predicate `0x1500d20`. A true result returns zero without reaching the write boundary. On the selected absent-file path, after its path checks and preparation return normally, it calls `0x15024a0` with first arguments `rdi=1`, `rsi=0` and the typed destination path in `rdx/rcx`: an empty byte span. The helper's checks, invalid paths, filesystem state and exceptional behavior are not modeled as unconditional success.

The already studied `0x15024a0` creates a generated path-shaped value, calls `0x5ca5110` with that path and the supplied buffer/length, and branches on its result. Only its zero-result continuation reaches `0x1502da0` with the generated path followed by the original destination. The latter's selected body constructs a vector with literal `mv` of length 2 followed by those two pointer/length pairs and calls command boundary `0x15b0450` at `0x1502e49`. The command runner, external `mv`, and operating system are explicit dependencies; this static ordering neither proves command success nor atomic rename, directory synchronization, or durability.

The evidence supports a particularly narrow failure observation: even when `0x1505a50` returns nonzero normally, these two callers invoke the returned object's virtual method and continue along their local cleanup. It does not establish that every filesystem failure returns through that path, that a marker exists afterward, or that all checkpoint data has been flushed before the attempt.

## Validation

The verifier binds six windows, 1,986 bytes / 473 instructions, 66 facts and 56 changed-byte controls to the full artifact digest, including the formatter's selector tables and the file/move call chain. The controls detect selected byte drift; the pathname and ownership interpretation relies on the described static dataflow and credited prior evidence. No durability or crash-recovery fixture is asserted.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-017-node115-evm-marker-writer/verify.py --target /path/to/original/hl-node
```
