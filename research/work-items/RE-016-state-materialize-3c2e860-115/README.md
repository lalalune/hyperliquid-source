# RE-016: node #115 materializer 0x3c2e860 widens a 0x27a8-byte state value to 0x42c8 bytes by inserting a 0x1b20 block

With this packet, the node #115 materializer constructor `0x3c2e860` (reached only through `.got 0x64e9630` from
`0x3c13610`) can be rebuilt as a byte-exact Rust function. It is a pure layout transform with exactly one
non-import callee. It hands the `0xbb8`-byte sub-value at `in +0x1108`, plus its own third and fourth arguments
unchanged, to the composer `0x434b9f0`. It then emits `out[0x0000:0x1108] = in[0x0000:0x1108]`, `out[0x1108:0x37e0]` =
the `0x26d8`-byte composer result, and `out[0x37e0:0x42c5] = in[0x1cc0:0x27a5]`, which is the whole suffix shifted by
exactly `+0x1b20`. So the only structural change from the input to the output state value is the `0x1b20`-byte
block that the composer adds inside the sub-value at `+0x1108`. Every other field keeps its relative order. The
reconstruction (`model()` in the tool, `layout.tsv`, `copies.tsv`) matches the real machine code in all 6,000 cases,
and all 20 negative controls are detected.

- Component ID: `abci` (work item RE-016, state materializer call chain; the base packet `RE-016-state-chain-94`, removed from main by the migration commit `8fd8db680`, is a #94 lead only)
- Target release and full SHA-256: `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: main `7ff06a097` (no source; binary-only)
- Claim status: reconstruction of the normal-return behaviour of `0x3c2e860`, validated against the evaluated #115 machine code. The composer is stubbed and its meaning is not claimed here. The role names "state value", "materializer", "composer" and "hash block" are inferences.
- Scope:
  - Included: the complete FDE `[0x3c2e860, 0x3c2f45b)` (3,067 bytes, 493 instructions). Its normal path `0x3c2e860..0x3c2f2d4` has 422 instructions, all of them executed. Also included: the output layout, the 16 memcpy calls and the composer call (order and arguments), the register and return contract, the caller links (one RELATIVE `.got` slot, one call site in `0x3c13610`), and four size bytes in that caller.
  - Excluded: the composer body `0x434b9f0` (reconstructed in our separate draft `RE-016-state-compose-434b9f0-115`), and the landing pad `0x3c2f2d5..` (its 29 drop targets are listed, not evaluated).
  - Context only, owned elsewhere: `0x3c13610`, which is reported by `RE-017-abci-loader-handoff-115`. That packet lists `0x3c2e860` only as a `.got` target. `RE-017-scheduled-cancel-state-115` projects one field pair (`in +0x2488 -> out +0x3fa8`) and states that it makes no claim on this FDE. Both rows are reproduced by the suffix rule here (`0x2488 + 0x1b20 = 0x3fa8`).

## Reproduce

Working directory: repo root. Python 3, stdlib only, plus the shared `tools/elf_index.py` and `tools/fde_extents.py`. No external program is called, and the binary is never executed.

```
python3 tools/re16_state_materialize115.py --out research/work-items/RE-016-state-materialize-3c2e860-115
python3 -m unittest tests.test_re16_state_materialize115
```

The tool checks the input SHA-256 first. It writes these files:

- `cases.tsv`
- `constants.json`
- `copies.tsv`
- `instructions.tsv`
- `layout.tsv`
- `negative-controls.tsv`
- `outcome-classes.tsv`
- `summary.json`

Two regenerations with different `PYTHONHASHSEED` and `TZ` values are byte-identical.

## Evidence

All coordinates are virtual addresses in node #115. `.text` maps VA = file offset + 0x1000. Every number in the evidence files comes from ELF bytes read with `struct`: `.rela.dyn` RELATIVE/GLOB_DAT entries, the FDE from `.eh_frame`, and code bytes. Instruction forms come from fixed byte patterns decoded by the tool's evaluator.

- **Entry contract.**
  - Registers: rdi = out, rsi = in (kept in r14), rdx = a, rcx = b.
  - `a` and `b` are stored at `rsp+0`/`rsp+8` (`0x3c2e8a3 48 89 14 24`, `0x3c2e89e 48 89 4c 24 08`) and reloaded unchanged as rdx/rcx for the composer.
  - Frame: three probed pages + `0xc88` (`0x3c2e86a`, `0x3c2e897`), so `0x3c88` below the pushes.
  - Returns out in rax (`0x3c2f2c0 48 89 d8`).
- **Callers.**
  - Trying every `.text` byte offset as `e8 rel32` finds no direct call to `0x3c2e860`.
  - Exactly one RELATIVE addend names it: `.got 0x64e9630`.
  - Inside FDE `0x3c13610`, the only call through that slot is `0x3c13665`.
  - Pinned context bytes in that caller:
    - it passes out = its own stack and in = its rdi;
    - it then allocates `0x42c8` bytes (`0x3c1366b bf c8 42 00 00`) and copies `0x42c8` bytes into them (`0x3c1367e`);
    - it frees the input allocation with size `0x27a8` (`0x3c1368f be a8 27 00 00`).

  So the input value is `0x27a8` bytes and the output value is `0x42c8` bytes. The difference is `0x1b20`.
- **Composer link.** `0x3c2ec16 e8 d5 cd 71 00` is the only `e8` site that targets `0x434b9f0`, and it is the only direct call before the `ret`. Its arguments are `rdi = rsp+0x15b0`, `rsi = in+0x1108` (`0x3c2ec06`), `rdx = a`, `rcx = b`. The result (`0x26d8` = `0xbb8 + 0x1b20` bytes) is copied to `out+0x1108` by `0x3c2f1ac..0x3c2f1c0`.
- **Copies** (`copies.tsv`, pinned per case):
  - The first six memcpy calls copy `in` pieces to the stack: `+0xba0 (0x1e8)`, `+0xd88 (0x360)`, `+0x2278 (0xb8)`, `+0x2330 (0xb8)`, `+0x1de8 (0xf8)`, `+0x000 (0xba0)`. On the normal path these six stack copies are never read again; only the landing-pad drops use them. The output takes those ranges from `in` directly. Some smaller fields, by contrast (for example `in +0x2638 -> rsp+0x10 -> out +0x4158`), are saved on the stack before the call and stored from there afterwards.
  - Nine memcpy calls copy `in -> out`.
  - One memcpy copies the composer result.
  - The remaining fields move through `movups`/`mov`/`movsd`/`movss`. For example, the 4-byte `in +0x278c` goes to `out +0x42ac` via `movss`, and the 21-byte tail `in +0x2790..+0x27a5` goes to `out +0x42b0..+0x42c5` as an overlapping 16-byte + 8-byte pair (`0x3c2f285`, `0x3c2f28c`, `0x3c2f293`).
- **Output layout** (`layout.tsv`):
  - Three rows cover `out 0x0000..0x42c5` exactly once.
  - The `in` rows cover `0x0000..0x1108` and `0x1cc0..0x27a5` exactly once (asserted by tests).
  - `in 0x1108..0x1cc0` is never read by this body; it is the composer's input.
  - `in 0x27a5..0x27a8` and `out 0x42c5..0x42c8` are never touched (padding).
- **Landing pad** (`constants.json` `calls`, `landing_pad_drop_targets`): 29 distinct drop targets plus `_Unwind_Resume`. They are listed, not evaluated.
- 18 checked byte strings, each with its meaning, are in `constants.json` `checked_bytes`.

## Implementation and comparison

`model(c)` in `tools/re16_state_materialize115.py` is the reconstruction. It is a pure function from (in bytes, composer result, prior out bytes, a, b) to (out bytes, in bytes after the call, symbolic call trace, return value). The comparison side evaluates the real #115 bytes of `0x3c2e860` with the tool's concrete x86-64 evaluator, reused from our composer and RE-011 handler packets without changes. Stubs:

- `memcpy` (GLOB_DAT `0x64df508`, dynsym name checked) copies for real.
- The composer stub writes deterministic case bytes as its `0x26d8`-byte result and overwrites the `0xbb8` input bytes it is given, modelling a move.

Every stub scrambles rax/rcx/rdx/rsi/rdi/r8-r11 and all xmm registers. That proves that the fields read before the call survive on the stack and in callee-saved registers, not in scratch registers.

Each case requires all of the following:

- the output bytes equal the model, including untouched padding;
- the 0x40 bytes of slack after the output are unchanged;
- the input after the call equals the model;
- the 17-entry call trace equals the model exactly, in order and with arguments mapped to (region, offset);
- rbx/rbp/r12-r15 and rsp are restored;
- rax = out.

Cases are 6,000 deterministic SHA-512 stream cases in 10 modes:

- random;
- zero or all-ones input;
- a byte ramp that makes every input offset distinct;
- zero or all-ones composer result;
- a = b = 0 and a = b = 2^64-1;
- zero or all-ones prior output.

## Results and limitations

- 6,000 / 6,000 cases match, with 0 mismatches. 422 / 422 normal-path instructions were executed (`instructions.tsv`). There are 10 outcome classes (`outcome-classes.tsv`), and every case returns.
- Negative controls, 20 / 20 detected (`negative-controls.tsv`):
  - 8 wrong models: prefix 8 bytes short, suffix 1 byte short, shift `0x1b00`, composer result ignored, zeroed padding, no stack copies, a/b swapped, composer source `+0x1110`;
  - 10 code-byte mutants, covering copy sizes, source and destination displacements, the composer argument and the rcx save slot;
  - a flipped `.text` byte (digest rejected) and an address past `.text`.
- Inferred, not proven:
  - The `0x1b20` block inserted by the composer is a state hash. Its size equals the LtHash block that the #94 packet `RE-016-state-chain-94` saw copied by #94 `0x326e460`. That is a #94 clue only, and this packet does not map #94 functions to #115.
  - "Materializer" follows the RE-017 naming.
- Not claimed:
  - the meaning of any field;
  - what the composer computes, or what a/b are;
  - landing-pad behaviour;
  - aliasing between in and out (the cases use disjoint buffers);
  - other releases.
- Read order not separated: the composer stub overwrites only the sub-value it is given. This packet therefore does not separate which suffix fields are read before the call and which after it; both orders give the same bytes.

Next question: what are the composer's `a`/`b` arguments? They are the rdx/rcx of `0x3c13610`, and they become the `vec`/`ctx` of the block builder. This is the input side of `0x3c13610` (RE-017 context).
