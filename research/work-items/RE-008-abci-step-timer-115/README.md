# RE-008: node #115 block-step timer, its five call sites and the tag each passes

- Component ID: abci. Question: which code calls the block-step host `0x4da7e20`, which tag byte does each caller pass, and what value does it hand on with that tag?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). The step names for tags 0 to 5 and the host body up to `0x4da7ff7` are the subject of open PR #4460; this packet does not depend on that PR's files. It continues the lead "A second specialization at `0x5b2a130` is an unclaimed lead" in `research/work-items/RE-001-node115-group-sampler-gates/PROOF.md`.
- Claim status: call sites, immediates, relocations, the clock import, constants and stores are observations. "Elapsed seconds between block steps" is an inference from the arithmetic and the `Duration`-like layout; it is not a measured unit.
- Scope included: recorder FDE `0x5b2a130..0x5b2aa61` from entry to the slot call at `0x5b2a24c` (window ends `0x5b2a252`); the five direct call sites, their guards and tag immediates; the two checkpoint creations; the ordered-path stores of the difference helper `0x5c84210`. Scope excluded: the recorder after `0x5b2a252` (the collection gate and record scan that the group-sampler packet maps for its own specialization), the bodies of `0x4dc50c0` and `0x1547530`, the host after `0x4da7ff7`, and what calls the two caller functions. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_timer_115.py --check
python3 -m unittest tests.test_abci_step_timer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The two `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence: who calls the host

In E8/E9 rel32 instructions across `.text`, exactly one names `0x4da7e20`: the call at `0x5b2a232`. No `R_X86_64_RELATIVE` relocation has addend `0x4da7e20`. That call is inside FDE `0x5b2a130..0x5b2aa61` (the recorder).

In the same census, exactly five instructions call the recorder, all E8, and no relocation names it:

| Site | Caller FDE | Tag instruction | Tag | Checkpoint |
| --- | --- | --- | --- | --- |
| `0x5486544` | `0x54864a0..0x548660e` | `0x5486542` `xor esi, esi` | 0 | `rsp+0x60` |
| `0x5a067ec` | `0x5a06600..0x5a07eb6` | `0x5a067e7` `mov esi, 1` | 1 | `rsp+0x1b8` |
| `0x5a06b29` | `0x5a06600..0x5a07eb6` | `0x5a06b24` `mov esi, 2` | 2 | `rsp+0x1b8` |
| `0x5a06e11` | `0x5a06600..0x5a07eb6` | `0x5a06e0c` `mov esi, 3` | 3 | `rsp+0x1b8` |
| `0x5a0784c` | `0x5a06600..0x5a07eb6` | `0x5a07847` `mov esi, 4` | 4 | `rsp+0x1b8` |

Each site passes `rdi = object + 0x12a0` (`add rdi, 0x12a0` seven bytes before the checkpoint `lea`) and is skipped when the qword at `object + 0x12a0` equals `0x8000000000000001` (`cmp [rdi+0x12a0], rax; je`). The tag-0 site loads that value with `movabs` at `0x5486523`. The block FDE builds it once (`movabs rax, 0x8000000000000000` at `0x5a067b2`, `inc rax` at `0x5a067bf`), stores it at `rsp+0x118` and reloads it for the later three sites. Inference: the recorder state is optional and `0x8000000000000001` is its `None` niche.

No site passes 5. With the encodings above, tag 5 never reaches the recorder or the host; its host arm has no direct path in this census. Register, vtable or other dynamic dispatch is not ruled out.

In the block FDE the four sites rise in address with their tags 1, 2, 3, 4. Both caller functions create their checkpoint with the same clock helper: `mov edi, 1; call 0x5c842e0` and two stores (`0x54864ba` to `rsp+0x60/+0x68`; `0x5a06624` to `rsp+0x1b8/+0x1c0`). Review only (objdump, not pinned by the tool): between the tag-0 checkpoint and its site there is one call, `0x5486507 -> 0x564bab0`; in the block FDE the only instructions that name `rsp+0x1b8` are the checkpoint store and the four `lea rdx` at the sites.

## Evidence: what the recorder hands on

Entry: `rdi` (state) is saved in `rbx`, `esi` (tag) in `ebp`, `rdx` (checkpoint pointer) in `r14`. The checkpoint is read as a qword at `+0` and a dword at `+8`.

1. `0x5b2a150..0x5b2a155`: `mov edi, 1; call 0x5c842e0`. That helper (FDE `0x5c842e0..0x5c843a9`) calls through slot `0x64e1248`, an `R_X86_64_GLOB_DAT` relocation to the dynamic symbol `clock_gettime`. So clock id 1 is passed to `clock_gettime`; on Linux that is `CLOCK_MONOTONIC`.
2. `0x5b2a18e`: `call 0x5c84210` with `rdi = rsp+8`, `rsi = &now`, `rdx = &checkpoint`. On its ordered path the helper (FDE `0x5c84210..0x5c842d6`) stores seconds at `+8` (`0x5c8427e`), nanoseconds at `+0x10` (`0x5c84282`) and a zero byte at `+0` (`0x5c84285`).
3. `0x5b2a193..0x5b2a1e6`: if the byte at `rsp+8` is not zero, the value stays `0.0`. Otherwise the value is the qword at `rsp+0x10` converted as an unsigned integer (constants `0x451210`, `0x450170`) plus the dword at `rsp+0x18` divided by `1e9` (`0x458d50`). If it compares equal to `+inf` (`0x459010`) or unordered, it stays `0.0`. The result goes to `rsp+0x70`.
4. `0x5b2a1ec..0x5b2a1f9`: a second `clock_gettime(1)` result overwrites the checkpoint qword and dword. Each call therefore measures from the previous checkpoint and restarts it.
5. `0x5b2a1fd`: the tag byte is stored at `rsp+0xe0`. `0x5b2a21a` calls `0x4dc50c0(rsp+8, state, tag)`.
6. `0x5b2a232` calls the host `0x4da7e20(rsp+8, &tag at rsp+0xe0, rsp+0x98)`. The host reads the tag with `movzx eax, byte [rsi]` at `0x4da7e67`.
7. `0x5b2a24c` calls slot `0x64e1010` (`R_X86_64_RELATIVE` addend `0x1547530`) with `rdi` = host result, `esi = 1`, `rdx = 0x64bca88` and `xmm0` = the value from step 3. `0x64bca88` is a Location record: `R_X86_64_RELATIVE` to `0x431e32` = `node/src/group_and_seq_sampler.rs`, length 33, line 169, column 10. The group-sampler packet binds the same Location in the first specialization `0x5b298d0`.

Inference: for each block step, the recorder hands the step's elapsed time since the previous step, in seconds, together with the tag-selected host result, to the routine at `0x1547530`.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes, the FDE index and relocations, and checks the clock import name in `.dynsym`/`.dynstr`. Negative controls in `tests/test_abci_step_timer_115.py` change one tag immediate (2 to 5), the second clock id, the nanosecond divisor displacement, the checkpoint reset store, the Location line, the host tag load, one block guard offset, and add an extra E8 call to the recorder in padding. Each change fails the check (11 tests pass on the real image).

## Results and limitations

Counts: 5 of 5 recorder call sites bound (denominator: E8/E9 rel32 calls in `.text` plus `R_X86_64_RELATIVE` addends); 1 of 1 host call site; tags passed `{0,1,2,3,4}`; tag 5 passed 0 times in that denominator. No progress gate is requested.

Unknown: what `0x4dc50c0` and `0x1547530` do with their arguments (a keyed metric or histogram record is a guess, not shown), what the host returns, what the `esi = 1` argument means, who calls the two caller functions, and whether tag 5 (`RespHashCheck` in #4460) is used anywhere through dynamic dispatch.

Next question: what `0x1547530` does with `(host result, 1, Location, seconds)`, and whether any indirect call reaches `0x5b2a130` or `0x4da7e20` with tag 5.
