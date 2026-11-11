# RE-017 · Source of the node #115 initial replay key

- Component: ABCI restore and replay startup.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. The authenticated capture is the only binary input.
- Scope: the selected completed-result path in startup parent B and the initializer of upper continuation field `+0x9a8`. The initializer is distinct from the previously documented callback capture. The compact byte record covers three indexed unwind ranges.

## Selected data flow

1. Parent B stages the loaded-state pointer in `[rsp+0x30d0]` at `0x2cbeb6c`. The selected parent output copy at `0x2cbc559` starts at `rsp+0x2d50` and copies `0x3b8` bytes. The pointer is therefore at result `+0x380`. The [loader handoff packet](../RE-017-abci-loader-handoff-115/README.md) establishes the earlier loader and returned pointer.
2. Upper continuation call `0x2cb7771` passes `rsp+0x730` as the output. A returned first dword of 2 goes through `0x2cb7784` to the early return path, bypassing initialization. On the selected other arm, `0x2cb77a4` loads RBP from `[rsp+0xab0]` (result `+0x380`). The nearby `0x380`-byte copy excludes the pointer itself.
3. At `0x2cb7976` the continuation loads 16 bytes from `[rbp+0x28]` and at `0x2cb797a` stages them at `rsp+0x2f0`. A direct qword load at `0x2cb7993` also reads `[rbp+0x30]` and stores it at `rsp+0x178`. The branch at `0x2cb7953` through `0x2cb9c2f` rejoins before the 16-byte staging load.
4. The later compare at `0x2cb8017` branches to `0x2cb8039` for R12 different from 2. The other arm leaves before the store. At `0x2cb80be` and `0x2cb80c6`, the selected arm copies the staged 16 bytes to `[rbx+0x9a0]`. The low qword comes from loaded-state `+0x28`. The high qword, from loaded-state `+0x30`, initializes parent `+0x9a8`. The instructions perform no arithmetic on either copied word.
5. The [callback capture packet](../RE-012-snapshot-replay-callback-capture-writer-115/README.md) follows the later read at `0x2cb983e` to callback `+0x708` when allocation succeeds. The [initial expected-key packet](../RE-012-snapshot-replay-initial-expected-key-115/README.md) follows it to the worker. Those downstream edges are retained as context.

## Relationship to the checkpoint selector

In the selected loader lane, `0x3c128ca` reads loaded-state `+0x28` and `0x3c128d4` compares it with the request word. On the accepted arm the loader increments a different field, `+0x18`, with saturation at all ones. It also copies the value of `+0x30` into `+0x20`. This separates the checkpoint comparison, the increment and the replay initializer into three independently addressable fields. Establishing a numeric relationship between the persisted `+0x30` and the checkpoint key requires the producer of `+0x30` or a paired real fixture.

The source relation assumes the selected path, normal helper returns and no intervening alias writes to the staged stack window or parent field. The packet does not cover all writes through aliases, the other startup lane, a real queue position or a state root. No progress gate is requested.

## Reproduce

Run from the repository root with the authenticated artifact available.

```sh
python3 research/work-items/RE-017-node115-replay-key-source/verify.py
objdump -d -M intel --insn-width=16 --start-address=0x2cb6500 --stop-address=0x2cbbbdf artifacts/node/115/hl-node
llvm-objdump -d --x86-asm-syntax=intel --start-address=0x2cb6500 --stop-address=0x2cbbbdf artifacts/node/115/hl-node
```

Use the `fde_start` and exclusive `fde_end` columns in [instructions.tsv](instructions.tsv) for the parent and loader ranges. The TSV preserves the selected raw bytes, GNU Intel-syntax decode, linked ELF VA and file offset. The same 41 instruction starts and byte spans were observed with GNU objdump 2.45 and LLVM objdump 23.1.4. The Python verifier uses the existing ELF and FDE readers to authenticate and check each exact byte span and reject a mutation in each one. These are selected static checks. No captured code was executed and no node reconstruction is claimed.
