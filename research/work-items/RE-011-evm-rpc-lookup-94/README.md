# RE-011: bind one node94 EVM RPC method lookup to its callback

Component `evm-rpc`; target node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

The prior `RE-011-evm-rpc-method-path` packet left the indirect call at
`0x2027d3d` and a concrete method association unresolved. This packet binds
that call to dynamic symbol `bcmp`, derives the 40-byte key/value record
from the insertion and lookup operands, and follows the `eth_blockNumber`
registration descriptor to a concrete vtable callback and its direct callee.
The relation is conditional on successful new-entry storage, preserved table
transport and memory, an ordinary runtime comparator binding, and normal
callee preservation. It does not establish an end-to-end RPC request.

| Edge / representation | Target evidence |
| --- | --- |
| Registered name | `0x27ab667` loads `eth_blockNumber` at `0x3f05a2`; `0x27ab671` sets length 15 |
| Registration descriptor | FDE `0x1f6d8a0..0x1f6d97d` builds `(tag=0, data=P, table=0x5691990)` |
| Insertion | Slot `0x5770950` RELATIVE addend `0x2a484d0`; new-entry stores key/length at A/A+8 and descriptor at A+16..A+40 |
| Key preservation | FDE `0x2a48ad0..0x2a48c6a` returns the original supplied key/length on its new-entry path |
| Candidate success | Equal length at `0x2027d14`, key comparison at `0x2027d3d`, EAX zero branch `0x2027d52 -> 0x2027fed` |
| Comparator identity | Slot `0x576e378`: `R_X86_64_GLOB_DAT`, symbol 11 `bcmp`, addend 0 |
| Value dispatch | Tag 0 reads preserved data/table and calls table+0x28 at `0x20280d0` |
| Concrete callback | `0x56919b8` RELATIVE addend `0x1f702c0`, complete FDE ending `0x1f704a8` |
| Direct callee | Callback `0x1f702f9 -> 0x27b8410`, complete FDE ending `0x27b86e8`; observed capture dereference and +16 argument |

`PROOF.md` separates native observations, the local normal-path argument and
the table/callback premises. No nominal Rust layout, public endpoint result,
all-method mapping, full hash/probe/growth contract, reconstructed build,
normalized identity or component gate is claimed. New recovered-byte credit
is zero; existing owner/table ranges are credited as prior context.

## Reproduce

From repository root with the authenticated captured node94 materialized:

```sh
packet=research/work-items/RE-011-evm-rpc-lookup-94
python3 -B "$packet/collect.py" --output work/re011-lookup-fresh
python3 -B "$packet/verify.py" --output work/re011-lookup-check.json
python3 -B -O "$packet/verify.py" --output work/re011-lookup-check-optimized.json
cd "$packet" && sha256sum -c MANIFEST.sha256
```

Both scripts accept `--target` and `--objdump`. Production admission requires
the complete size/SHA-256 before parsing. Native GNU disassembly receives an
inert mode-0400 copy named `node.elf`. Only GNU binutils and Python standard
library code run. No captured process, instruction evaluator, network service,
live chain, key material or unlicensed inferred implementation is used.

The flat root test `tests/test_evm_rpc_lookup_static.py` runs the full static
verifier and controls in ordinary test discovery. It passes normally and
under Python `-O`; `make doctor` and `make verify catalogue-check reproduce`
also pass. The coordinated complete repository suite is pending integration;
no full-suite or hosted-CI result is claimed here.

`observed/` contains eleven native corridors across seven validated FDEs.
Records retain full-FDE body hashes, original file offsets, raw CIE/FDE/index
bytes, corridor/export hashes, and relocation/symbol records. The 257 frozen
instruction witnesses cover the local obligations; no full containing-function
proof is claimed. `CONTROLS.tsv` records all corruption results.
`VALIDATION.json` records commands, versions, outcomes and remaining gaps.

## Scope and next question

This extends the current main packet's explicit next question. Live full-body
PR searches for RE-011, blockNumber and the selected owner/handler addresses
found no competing open claim in the checked snapshot. Open #1367 is the
different bloom prefilter at `0x27c1710..0x27c347f` and explicitly leaves method
routing unresolved. `SCOPE-CHECK.json` records queries and their limitations.

Next: prove which concrete constructor/request state transport preserves this
registered table and descriptor, including the map sharing/growth helper at
slot `0x57735a0`, before dropping the conditional association premise. The
method-associated direct callee's locking/timing/helpers and public RPC return
semantics remain unresolved. All component gates remain false.
