# RE-016: node #115 composer 0x434b9f0, which wraps a moved state value with a 0x1b20-byte block

With this packet, the one callee of the materializer constructor `0x3c2e860` that builds the `0x1b20`-byte block
(call site `0x3c2ec16`) can be rebuilt as a byte-exact Rust function. Its output value is a pure layout of
(a) the block written by the `.got 0x64e9528` builder `0x38c2690` and (b) every byte `0x000..0xbb4` of the moved
`0xbb8`-byte input value, placed at fixed and partly reordered offsets up to `out +0x26d4`. It also consumes the
borrowed byte vector: the buffer is freed only when the capacity is non-zero, with size = capacity. The
reconstruction (`model()` in the tool and `layout.tsv`) matches the real machine code in all 6,000 cases, and all 24
negative controls are detected.

- Component ID: `abci` (work item RE-016, state materializer call chain; the base packet `RE-016-state-chain-94` is a #94 lead only)
- Target release and full SHA-256: `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: main `7ff06a097` (no source; binary-only)
- Claim status: reconstruction of the normal-return behaviour of `0x434b9f0`, validated against the evaluated #115 machine code. The callees it calls are stubbed, and their meaning is not claimed. The role names "state value", "hash block" and "materializer" are inferences.
- Scope: included the complete FDE `[0x434b9f0, 0x434bd95)` (933 bytes, 176 instructions). The normal path `0x434b9f0..0x434bcf3` has 143 instructions, all executed. Also included: the output layout, the call trace (order and arguments), the deallocation rule, the register and return contract, the only rel32 caller site, and the GOT slot targets. Excluded: the internals of `0x38b3830`, `0x44681e0`, `0x38b3ad0`, the block builder `0x38c2690` (mapped in `RE-001-node115-hash-diagnostic-snapshots`) and the deallocator `0x635de30`, plus the landing pad `0x434bcf4..` (drop calls are listed, not evaluated). This packet also does not cover the body of the caller `0x3c2e860`, which RE-017 packets report as the materializer constructor.

## Reproduce

Working directory: repo root. Python 3, stdlib only, plus the shared `tools/elf_index.py` and `tools/fde_extents.py`. No external program is called, and the binary is never executed.

```
python3 tools/re16_state_compose115.py --out research/work-items/RE-016-state-compose-434b9f0-115
python3 -m unittest tests.test_re16_state_compose115
```

The tool checks the input SHA-256 first. It writes `cases.tsv`, `constants.json`, `instructions.tsv`, `layout.tsv`, `negative-controls.tsv`, `outcome-classes.tsv` and `summary.json`. Two regenerations with different `PYTHONHASHSEED` and `TZ` values are byte-identical. It takes about 11 s.

## Evidence

All coordinates are virtual addresses in node #115. `.text` maps VA = file offset + 0x1000. Every number in the evidence files comes from ELF bytes read with `struct`: `.rela.dyn` RELATIVE/GLOB_DAT entries, the FDE from `.eh_frame`, and code bytes. Instruction forms come from fixed byte patterns decoded by the tool's evaluator.

- **Entry contract.** rdi = out, rsi = in, rdx = vec (capacity at +0, pointer at +8), rcx = ctx. They are kept in rbx/r14/r13/rbp (`0x434ba3d 48 89 cd`). The frame is 4 probed pages + 0x238 (0x4268 bytes with the pushes). It returns out in rax (`0x434bcdf`).
- **Only caller.** A byte scan of every `.text` offset as `e8 rel32` finds exactly one site, `0x3c2ec16`, inside FDE `[0x3c2e860, 0x3c2f45b)`. No RELATIVE addend names `0x434b9f0`. At that site the caller passes `in = r14 + 0x1108` and `out = rsp + 0x15b0`. That excerpt comes from objdump and is for reading only; it is not in the evidence files.
- **Call trace** (pinned per case in `compare()`):
  1. memcpy x3: `rsp+0x100 <- in+0x000 (0x378)`, `rsp+0x478 <- in+0x388 (0x3b0)`, `rsp+0x828 <- in+0x738 (0x3b0)`. These stack copies are read only by the landing-pad drops.
  2. `0x38b3830(rsp+0xa0, ctx)`.
  3. `0x44681e0(rsp+0xd0, vec, rsp+0xa0, 1)`.
  4. `h = 0x38b3ad0(rsp+0xd0, 0)`.
  5. `[.got 0x64e9528] = 0x38c2690(rsp+0x2718, h, vec, 0)`, which writes the 0x1b20-byte block.
  6. memcpy `rsp+0xbd8 <- rsp+0x2718 (0x1b20)`.
  7. If `vec.cap != 0`: `[.got 0x64df4a0] = 0x635de30(vec.ptr, vec.cap, 0)`.
  8. memcpy x3 `in -> out`, then memcpy `out+0 <- rsp+0xbd8 (0x1b40)`. This last copy picks up the 0x20 bytes of `in+0xb38` that `0x434bb79..0x434bb9d` placed right after the block.
- **Output layout** (`layout.tsv`): out `+0x0000` block (0x1b20); `+0x1b20` in `+0xb38` (0x20); `+0x1b40` in `+0x000` (0x378); `+0x1eb8` in `+0x378` (0x10, read before the calls); `+0x1ec8` in `+0x388` (0x3b0); `+0x2278` in `+0x738` (0x3b0); `+0x2628` in `+0xae8`; `+0x2640` in `+0xb00`; `+0x2658` in `+0xb18` (0x20); `+0x2678` in `+0xb58` (0x20); `+0x2698` in `+0xb78`; `+0x26b0` in `+0xb90` (0x20); `+0x26d0` the low 4 bytes of in `+0xbb0`. In that last field, `movsd` loads 8 bytes at `0x434baf9` but `movss` stores 4 at `0x434bcd7`. The input bytes `0xbb4..0xbb8` and the output bytes `0x26d4..0x26d8` are never touched. `tests` assert that the input rows cover `0x000..0xbb4` exactly once and the output rows cover `0x0000..0x26d4` exactly once.
- **GOT slots** (`constants.json`): `0x64df508` is GLOB_DAT `memcpy` (dynsym name checked); `0x64df4a0` is RELATIVE `0x635de30`; `0x64e9528` is RELATIVE `0x38c2690`; `0x64df4c0` is RELATIVE `0x1680cab`, which is called only after the landing pad (role unresolved).
- 22 checked byte strings, each with its meaning, are in `constants.json` `checked_bytes`.

## Implementation and comparison

`model(c)` in `tools/re16_state_compose115.py` is the reconstruction. It is a pure function from (in bytes, block bytes, prior out bytes, vec, ctx, h) to (out bytes, symbolic call trace, return value). The comparison side evaluates the real #115 bytes of `0x434b9f0` with the tool's concrete x86-64 evaluator, which is reused from the earlier #115 handler packets and extended with memory `movsd` loads and `movss`/`movsd` stores. The stubs are:

- memcpy, which copies for real;
- the three prep callees and the block builder, which write deterministic case bytes;
- the deallocator, which only records its arguments.

Every stub scrambles rax/rcx/rdx/rsi/rdi/r8-r11 and all xmm registers. That proves the body keeps the pre-call reads of `in+0x378` and `in+0xbb0` on the stack (`rsp+0x30`/`+0x20`) rather than in registers. Each case requires all of the following:

- the output bytes equal the model, including the untouched padding and slack;
- the call trace equals the model exactly, in order and with arguments mapped to (region, offset);
- in and vec are unchanged;
- rbx/rbp/r12-r15 and rsp are restored;
- rax = out.

Cases are 6,000 deterministic SHA-512 stream cases in 11 distinct modes (random, capacity 0/1/2^64-1, zero or all-ones input, a byte ramp that makes every input offset distinct, zero block, h = 0 / 2^64-1, null pointer with capacity 0).

## Results and limitations

- 6,000 / 6,000 cases match, with 0 mismatches. 143 / 143 normal-path instructions were executed (`instructions.tsv`). There are 13 outcome classes (`outcome-classes.tsv`): 1,203 cases skip the deallocation and 4,797 call it.
- Negative controls, 24 / 24 detected (`negative-controls.tsv`):
  - 11 wrong models: the 0xb38/0xb58 swap, f32 copied as f64, a 0x370 source for out +0x1eb8, an untouched trailing field, zeroed padding, ctx and vec swapped, the prep-b flag set to 0, the block flag set to 1, dealloc always / never, and size x 0x38;
  - 11 code-byte mutants;
  - a flipped `.text` byte (digest rejected) and an address past `.text`.
- Inferred, not proven:
  - `0x3c2e860` is reported by RE-017 packets as a materializer constructor, and this function builds a sub-value of its output.
  - The 0x1b20-byte block is a state hash. Its size equals the LtHash block that the #94 packet `RE-016-state-chain-94` saw copied by #94 `0x326e460`. That is a #94 clue only; this packet does not map the #94 functions to #115.
  - vec looks like a `Vec<u8>`, because the deallocation size equals the capacity.
- Not claimed:
  - what the three prep callees or the block builder compute;
  - what any input field means;
  - landing-pad behaviour;
  - aliasing between in and out (the cases use disjoint buffers);
  - other releases.

Next question: what do `0x38b3830`/`0x44681e0`/`0x38b3ad0` derive from ctx and vec, i.e. what is `h`, the second argument of the block builder?
