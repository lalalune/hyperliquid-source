# Address-09 output installation into the parent frame

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. This is partial HL115-074 / RE-011 research. The original executable was disassembled, never executed or emulated.

The selected successful address-09 precompile path transfers the same 32-byte buffer descriptor from the callback, through its provider and the frame-call result, into the remaining parent frame at `+0x150..0x16f`. The parent drops its previous descriptor first. It retains the entire 64-byte return buffer even when the requested output-memory range is shorter, and copies only the bounded prefix. No buffer-clone call appears in this selected transport and installation chain.

## Prior work and precise addition

[#5900](https://github.com/lalalune/hyperliquid-source/pull/5900) owns the BLAKE2F callback `0x5c16650`, including its 64-byte allocation and gas contract. [#2049](https://github.com/lalalune/hyperliquid-source/pull/2049) owns BLAKE lookup/status conversion, including `0x5be6a80`. [#2104](https://github.com/lalalune/hyperliquid-source/pull/2104) and [#2168](https://github.com/lalalune/hyperliquid-source/pull/2168) establish provider and nested-input routing. [#2177](https://github.com/lalalune/hyperliquid-source/pull/2177) owns the buffer vtables, clone/drop operations, and RETURNDATA consumers. These are dependencies, not newly discovered leaf implementations.

The new result binds the actual callback-produced descriptor to `0x29653c9` / `0x29653ea` / `0x29653f0` and the memory copy at `0x29654f5`. It replaces a previously assumed relationship between child output and the parent buffer with a concrete caller/callee and stack-slot chain. The adjacent frame reserve fold in [#6644](https://github.com/lalalune/hyperliquid-source/pull/6644) is separately credited; this packet does not reconstruct that arithmetic again.

## Selected path and premises

The proof selects a valid nested call reaching `0x29837a0` from `0x2964ff6`, with the built-in provider enabled, the direct input-buffer arm of `0x2a6ab20`, and the twenty-byte address ending in `09`. Its callback returns normally after accepting input length 213, a final flag below 2, and sufficient supplied gas for the big-endian round count. Allocation, crypto backend, journal/cleanup and inspector helpers are assumed to return normally on valid, nonaliasing objects. A remaining parent frame and prepared output memory are required. These are explicit path premises, not a proof that every RPC request reaches this path.

At `0x46a0f81`, lookup selects row `0x6492ff8`; relocation `0x6493010` binds the callback to `0x5c16650`, and row word `+0x20` is 10. The callback is passed `floor(call_input[+0x80] / 10)` gas. Its already-studied successful output is:

| Callback offset | Value carried |
| --- | --- |
| `+0x00` | Vtable selected from `0x64040c0` / `0x64040e8` by allocation-pointer low bit |
| `+0x08` | Fresh allocation pointer |
| `+0x10` | Length 64 |
| `+0x18` | Tagged backing/owner word |
| `+0x20` | Round count |

The 64 bytes written into this allocation are the callback's post-compression state. This packet reuses the callback contract; it does not independently establish the cryptographic algorithm or all backing modes.

## Descriptor identity across the provider and call result

At `0x2a6b07d`, the indirect callback writes to local `rsp+0x40`. A nonzero first word selects its successful descriptor arm. The three following words are staged through `rsp+0x100/0x110` and `rsp+0xe0/0xf0`, then placed at wrapper input `+0x20..0x37`. The original first word is placed at wrapper input `+0x18` (`0x2a6b1be`). The intermediate tag at `+0x00` is `0x8000000000000024`, not the callback's vtable. Scaled gas consumption is placed at `+0x38`.

`0x5be6a80` recognizes that intermediate tag, selects status 2 on the affordable normal arm, and returns the original descriptor as its first 32 bytes. It computes remaining gas as the original call-input gas minus ten times the round count. For this callback, rounds are `u32`, and its prior quotient comparison prevents underflow. The descriptor is copied through registers and local stack storage; it is not cloned by a buffer vtable.

`0x29837a0` receives that provider output in `rsp+0x90` at `0x2984373`. Status 2 takes the `<5` continuation; this path sets its outer result vector to `(0, 8, 0)`, not a sentinel frame-creation result. The identity transport is:

| Provider field | Preserved local/register | Final 144-byte result field |
| --- | --- | --- |
| vtable `+0x00` | `r12` | `+0x18` (`0x2985177`) |
| data `+0x08` | `r14`, then `rsp+0x130` | `+0x20` (`0x2985187`) |
| length `+0x10` | `rsp+0x210`, then `+0x4f0`, `+0x90`, `+0x4e0` | `+0x28` (`0x2985197`) |
| owner `+0x18` | second word of the same 16-byte local | `+0x30` (`0x2985197`) |
| remaining gas `+0x38` | `rsp+0x38` before final assembly | `+0x50` (`0x29851ce`) |
| status `+0x58` | `rsp+0x20` | `+0x70` (`0x2985233`) |

The intermediate journal-processing interval `0x29852a2..0x29856e3` operates on other stack records and preserves this result descriptor. The inspector call at `0x29856fe` receives the result address as its fourth argument; `0x22d94a0` reads its outer tag and updates a separate inspector timing record, without writing the result descriptor. The final 144-byte copy at `0x2985718` returns it to the original output pointer. This is a static dataflow conclusion under normal helper/valid-object premises, not a claim about arbitrary aliasing or exceptional paths.

## Parent replacement, output memory, and returned gas

The caller receives the result at `rsp+0x210`, stages it at `rsp+0x760`, and selects the remaining 512-byte frame. If the current frame's `+0x1f8` flag is set, the index is decremented before selection. The call-result arm, distinct from the minimum-sentinel creation-result arm, reaches `0x296532d`.

At `0x29653c9`, the old parent descriptor's actual vtable method `+0x20` is called with its data pointer, length and owner-word address. Only after normal return does `0x29653ea/0x29653f0` copy the incoming descriptor to parent `+0x150..0x16f`. The new pointer, length, vtable and owner word therefore match the address-09 callback output. These writes do not call clone or increase a buffer reference count. The old descriptor's drop implementation and subsequent parent lifetime are separate dependencies; this is not a proof of every later drop or shared-owner state.

The requested range comes from result words `+0x78` and `+0x80`. The copy count is `min(64, end.saturating_sub(start))`; the full 64-byte descriptor remains installed regardless of that count. Selected status 2 passes the `0x3f001e` mask, adds returned gas to parent `+0x188` with an overflow branch, and then reaches the output copy. A positive copy uses parent buffer `+0x158` as source and parent memory object's `+0x20` backing plus parent `+0x18` memory base plus `start` as destination. The native code checks offset additions for overflow; zero count skips this copy. It does not establish memory expansion here, so prepared memory is a premise. The memory borrow word is temporarily set to `-1` and incremented after the copy returns.

Thus the selected address-09 return preserves all output bytes for subsequent RETURNDATA consumers while writing at most the requested prefix into the call's output region. This is return-side gas restoration, not whole-transaction gas finality. Reserve/refund folding, failures, revert, unwind, other provider/input modes, overlapping memory/alias fixtures and complete nested-call runtime equivalence remain open.

## Validation

`records.json` binds 21 windows, 5,427 bytes / 1,006 instructions, 257 facts and 257 changed-byte/relocation controls to the full original artifact digest. Re-run with:

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-011-node115-child-result-install/verify.py --target /path/to/original/hl-node
```

The controls check recorded instructions, relocations and data against targeted corruption; they do not execute the native target or independently prove semantics. This contribution is a reproducible static join, not a complete implementation of HL115-074.
