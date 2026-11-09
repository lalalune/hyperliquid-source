# RE-008: node #115 output flags (16th stage): the fast_abci_engine step and the block-step sampler gate

- Component ID: abci. Question: #5916 found that the engine value of the runner `fast_abci_engine` holds the box (the 0x4e38-byte allocation with the output setter's result at `+0x7c0`) at `+0x450`, and that `0x5a08720` tests box `+0x28` for a multiple of 10000. It left open the rest of that test, what reads box `+0x1c58` / `+0x1c60`, and who reads the setter's two optional values at box `+0x12a0` / `+0x12d8`.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5908 and #5916, and ties the output-flag series to the block-step sampler of #4718. It does not depend on their files.
- Claim status: instruction bytes, offsets, immediates, strings, relocations, the Location record and call or displacement censuses are observations. "Box", "engine value", "height", "freeze height", "snapshot", "sampler", "Some" and "None" are inferred labels from the assertion text, the strings, the sizes and the niche values. The binary was not executed.
- Scope included: `0x5a08720` from entry to the label choice (`0x5a08720..0x5a08878`) and its panic arm `0x5a08dc3..0x5a08df5`; the call chain `0x56186c0 → 0x5a06600 → 0x5a08720`; the five sampler sites and their None checks; the setter's `+0x18` branch `0x51d0856..0x51d08d5`. Scope excluded: what `0x5a08720` does with the label after `0x5a08878`, the use of box `+0x4538`, the bodies of `0x5a06600` beyond the pinned instructions, the runner's poll function above `0x56186c0`, and any reader of box `+0x12d8`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/fast_abci_engine_115.py --check
python3 -m unittest tests.test_fast_abci_engine_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The six `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the step's two triggers

`0x5a08720` loads the box from engine value `+0x450` (`0x5a08737`) and box `+0x28` into `r15` (`0x5a0873e`). After the multiple-of-10000 test (#5916) it reads an optional value from the box:

- `0x5a08763` `cmp dword [rsi+0x1c58], 1`: present when the dword is 1.
- `0x5a0876c` `cmp [rsi+0x1c60], r15`, then `jb 0x5a08dc3`. At `0x5a08dc3` the code loads `0x929b14` with length 62, `assertion failed: freeze_height >= self.locus.context.height()`, and Location `0x64aa278` (`l1/src/exchange/exchange.rs`, line 607, column 17), and calls the panic slot `0x64df730`. So box `+0x1c60` is `freeze_height` and box `+0x28` is the height (`self.locus.context.height()`).
- `sete bpl` / `sete r13b` record "at the freeze height".

The trigger `bpl` is set by the 10000 test or the freeze height. When the engine tag dword at `[r14]` is 2, the step stores `0x8000000000000000` to its result and returns (`0x5a0877d .. 0x5a0879b`). When no trigger holds, the step divides the height by box `+0x4538` and skips to `0x5a08bb1` on a nonzero remainder (`0x5a087e5 .. 0x5a08803`).

With a trigger, it selects a label: `lea rcx, [rax*2+6]` with `al = r13b ^ 1` gives length 6 or 8, and `cmovne rdx, rax` selects `0x93a687` `freeze` at the freeze height, else `0x458f30` `periodic` (`0x5a08853 .. 0x5a08874`). Reading the step as a snapshot writer is an inference from these labels; the use of the label is not mapped here.

## Evidence 2: the call chain

E8 rel32 census over `.text`:

| Target | Callers |
|---|---|
| `0x5a08720` (step) | `0x5a077e1` in `0x5a06600`, `0x5a6c16a` in `0x5a6bfb0` (#5916) |
| `0x5a06600` (driver) | `0x5618710` in `0x56186c0` |
| `0x54864a0` (tag-0 function) | `0x5a06af4` in `0x5a06600` |
| `0x5b2a130` (sampler, #4718) | `0x5486544`, `0x5a067ec`, `0x5a06b29`, `0x5a06e11`, `0x5a0784c` |

`0x5a06600` saves its `rsi` in `r15` (`0x5a06614`) and reads box `+0x1c58` / `+0x1c60` through `[r15+0x450]` (`0x5a06687 .. 0x5a06695`), the same freeze fields as the step.

## Evidence 3: the setter's first optional value gates the block-step sampler

#4718 bound five calls to the block-step sampler `0x5b2a130` with tags 0 to 4, each guarded by `cmp [object+0x12a0], 0x8000000000000001; je skip`. This packet binds the object:

- At the tag-1 site, `lea rbx, [r15+0x450]` (`0x5a067a0`) and `mov rdi, [rbx]` (`0x5a067bc`) load the object from engine value `+0x450`. That is the box (#5916). In address order no instruction writes `r15` between `0x5a06614` and `0x5a067a0` (first rewrite `0x5a068d4`); back edges into that range were checked by hand only.
- Box `+0x12a0` is setter result `+0xae0` (#5908: result at box `+0x7c0`), the first of the setter's two optional values (#5902).
- The setter (`0x51cf360`) tests its byte `+0x18` copy at `rsp+0x13` (`0x51d0856`). Clear: `lea rax, [rbp+1]` with `rbp = 0x8000000000000000` (`0x51cfde6`) stores `0x8000000000000001` as the first qword of both values (`0x51d08c5` `rsp+0x218`, `0x51d08cd` `rsp+0x250`). Set: it stores 0 and the f64 15.0 at `+0x20` of each (`0x51d0874 .. 0x51d08b8`).

So the value the sampler sites skip on is exactly the value the setter stores when `+0x18` is clear. #5892 showed that both setter callers pass 0 in `+0x18`. Inference: on the `run-validator` / `run-non-validator` paths mapped in #5892 to #5916, the block-step sampler (#4460, #4718) is skipped at all five sites.

A displacement census finds 9 `+0x12a0` displacements in `0x5a06600`, 2 in `0x54864a0`, none in `0x5a08720`, and no `+0x12d8` displacement in any of the three.

## Implementation and comparison

The tool pins 60 instruction byte runs, 15 RIP-relative or rel32 references, four strings, one Location record, the 15.0 and niche constants, and recomputes the call and displacement censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (9 mutation tests). Alternatives considered: a full data-flow proof of `r15` and `r14` in `0x5a06600` (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the engine step snapshots at heights that are multiples of 10000 (`periodic`) and at an optional freeze height (`freeze`), and panics when the freeze height is below the height (`exchange.rs:607`). The setter's first optional value is the block-step sampler's state, and setter byte `+0x18` decides whether it exists.
- Limits: the E8 census does not cover indirect calls. The object at the tag-0, tag-2, tag-3 and tag-4 sites is not traced to the box here (the tag-0 function gets it as `[r14]` from `0x5a06af1`). What reads box `+0x12d8` (the second optional value) and what 15.0 means inside `0x5b2a130` are open. The use of the `freeze` / `periodic` label, the divisor at box `+0x4538`, and the runner's poll function above `0x56186c0` are not mapped.
- Next lead: map `0x5b2a130`'s use of its state's `+0x20` (the 15.0), and the use of the snapshot label after `0x5a08878`.
