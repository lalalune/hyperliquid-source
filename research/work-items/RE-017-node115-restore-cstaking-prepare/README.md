# RE-017 #115 restores the c_staking history in two passes

The [state-load chain](../RE-016-state-load-chain-115/README.md) identifies two initialization calls on the same restored-state subobject and leaves them as stubs. To reproduce ordinary checkpoint restore beyond those stubs, this packet traces their separate inputs and iteration shapes. The [state-field projection](../RE-008-abci-state-fields-115/README.md) associates the subobject at state `+0xd88` with the serialized field `c_staking`.

Target Linux x86-64 node #115 with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Selected restore path

Once the loaded height check succeeds, the loader reads state `+0x30`, stores that word at state `+0xdf0` and passes the same value as the second argument to `0x420b9c0` at `0x3c12923`. Its first argument is state `+0xd88`. The MessagePack [round-source packet](../RE-017-node115-checkpoint-round-source/README.md) identifies the word at state `+0x30` as the restored round. The subsequent call `0x3c1292b` passes the same subobject through the relative slot `0x64e4f08` to `0x3c374e0`. The loader then reloads state `+0x30`.

| Pass | Selected data flow |
| --- | --- |
| Round-aware preparation at `0x420b9c0` | The primary descriptor word at subobject `+0x10` picks a normal descriptor or the signed-minimum sentinel. Normal calls `0x457f2f0` with that descriptor. Sentinel with nonzero `+0x28` and an available `+0x18/+0x20` pair calls `0x3920a30`, otherwise the selected zero-count branch initializes the empty stack output. Subobject `+0x30/+0x38/+0x40` supplies a separate optional collection. The call at `0x420baff` forwards subobject `+0x48`, the restored round and both prepared collections to `0x3cdba10`. |
| Selected follow-up loop in the first pass | The unsigned comparison of subobject `+0x60` and `+0x78` enters the loop when the former is greater. Each iteration calls `0x3ceb5a0` with subobject `+0x48`, processes any selected non-2 result and reloads both bound words. |
| Ring projection at `0x3c374e0` | In the ordinary non-sentinel arm, the qwords at subobject `+0xd0/+0xd8/+0xe0/+0xe8` supply capacity, data base, cursor and length. The head subtracts capacity once when the cursor is at or above capacity. A wrapped range produces spans from the adjusted head to the backing end and then from the backing start for the remaining rows. The three pointer scales are `0x70`. A zero length supplies empty spans. This descriptor is sent to `0x451d9a0`. |
| Key projection in the second pass | Call `0x3d6eee0` receives additional words from subobject `+0x180..+0x190`, the first helper's result and a pointer at `+0x1e8`. When the returned count is positive, the normal loop copies each 20-byte item into a stack key and passes it with subobject `+0x180` to `0x39038f0`. The stride is `0x14`, independent of the input ring's `0x70`. A zero returned count bypasses this loop. |

The verified instructions and branch/call targets are in [instructions.tsv](instructions.tsv). The first pass and second pass operate on the same pointer but take distinct descriptor routes. A positional restore fixture needs to preserve the restored round through the first call and distinguish the second pass's record stride from its projected key stride. The helpers' inner mutation routines, the second pass's signed-minimum variant and eventual root effect remain open.

## Reproduce offline

From repository root:

```sh
python3 -B research/work-items/RE-017-node115-restore-cstaking-prepare/verify.py
```

The verifier checks the ELF digest, three unwind ranges, selected instruction bytes, direct edges and the relative call slot. It compares the derived ordinary ring projection against independent row-by-row iteration over empty, contiguous, wrapped and full ring cases, all using synthetic in-memory inputs. It does not execute captured code or establish real checkpoint materialization. See the [offline log](offline-log.txt).
