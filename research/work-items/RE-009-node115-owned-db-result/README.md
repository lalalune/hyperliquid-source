# RE-009: owned database open's selected result handoff

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is partial static evidence for [storage issue #3910](https://github.com/lalalune/hyperliquid-source/issues/3910), not a database implementation or a checkpoint restore. The [owned-db open budget packet](../RE-009-node115-owned-db-open-budget/README.md) identifies caller `0x4524660`, its arguments and 80-byte handoff but leaves the callee result and selected object's `+0x18/+0x20` qwords unresolved. This packet joins the selected no-extra-entry path to the callee's result construction and back to that caller.

At `0x452486b..0x4524882`, the caller supplies the selected object's qwords `+0x18` and `+0x20` as arguments 3 and 4, sets argument 5 to zero, and calls `0x3d5ed10` with a stack result at `rsp+0x68`. The callee saves those arguments as source pointer and length (`0x3d5ed27`, `0x3d5ed30`). Its zero argument 5 selects an initially empty temporary vector. It passes zero as the first argument of `0x37bee70`; that helper's zero branch writes the initial zero count back unchanged. Consequently the later `rbp` count is zero and the branch at `0x3d5f0b2` selects `0x3d5f2a8`, provided preceding helpers return normally and the earlier conversion and preparation checks take their continuation arms.

At `0x3d5f2c3`, relocation slot `0x64e6f90` resolves to `0x5d33cb0`. A zero out-error word proceeds to test that call's return in `rax`. If the return is nonzero and source length is nonzero, the code allocates a length-sized buffer and copies the original argument-3 bytes into it. With length zero, it uses pointer value 1 and skips the copy. The normal result builder writes:

| Result offset | Observed value on this path |
| --- | --- |
| `+0x00`, `+0x10` | original argument-4 length |
| `+0x08` | copied original argument-3 bytes, or pointer value 1 for zero length |
| `+0x18..+0x2f` | three qwords from the earlier prepared local record |
| `+0x30` | nonzero return of `0x5d33cb0` |
| `+0x38..+0x4f` | three qwords from helper `0x5c409d0`'s local result |

The source pair is therefore copied as an owned byte sequence on this selected route, rather than merely passed through. Its semantic path or schema is not determined here. The two three-qword fields are intentionally left unnamed. If the call's out-error word is zero but its return is zero, the callee instead constructs a result whose first word is `0x8000000000000000` and includes the literal `Could not initialize database.`. This does not cover the nonzero out-error branch or other earlier failures.

After return, `0x4524889` compares the first word with zero and uses signed overflow to select its existing error arm; on the normal non-sentinel arm, `0x4524894..0x45248c6` copies the 80-byte result to the caller's output and `0x45248c9` stores the selected object's pointer at `+0x50`. The proof assumes valid nonaliasing input/output, a source length distinct from the sentinel, normal helper returns, and successful allocation/copy. It does not show actual filesystem effects, RocksDB open success, persistent formats, cleanup on every error or runtime reachability of a concrete database.

## Reproduce

From the repository root, using Capstone 5.0.7 and the authenticated target:

```sh
PYTHONPATH=tools python3 research/work-items/RE-009-node115-owned-db-result/verify.py
```

The verifier checks the digest, three indexed FDE boundaries and complete disassembly partitions (87, 1,249 and 264 instructions), 181 selected instruction records, 76 explicitly pinned instructions, 11 call/branch targets, four relocations, the `memcpy` import, the error literal, and five byte-corruption controls. These are static observations; no captured code is executed or emulated. The selected instruction denominator is not a component-completion percentage. The earlier budget arithmetic and byte-key descent are prior evidence, not newly claimed work. Storage component gates remain false.
