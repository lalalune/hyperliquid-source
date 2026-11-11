# RE-016: node #115 extension-dispatched loader 0x422e410 (the "lookup" of the state-load chain) reconstructed as one flow

With this packet, the function `0x422e410` that the RE-016 state-load chain calls from its boundary `0x3c13520` can be rebuilt as a Rust
function with fully known control flow: it is not a keyed lookup but a loader that clones its `(ptr, len)` argument, resolves it, and
dispatches on the **file extension** of the resolved string (`rmp`, ASCII case-insensitive, taken after the last `.`, rejecting `..` and
a dot at index 0) to one of two load-and-decode paths, returning `(0, value)` or `(1, error)`; its third argument (`0x64767a8` at the
chain's call site) is never read. The reconstruction (`model()` in the tool) is compared with the real machine code of the function
(including the real case-insensitive comparison `0x159fca0`) in 14,000 cases with 0 mismatches, and all 33 negative controls are detected.

- Component ID: `abci` (work item RE-016, state-load chain; callee of the boundary `0x3c13520`, see the earlier RE-016 chain packet)
- Target release and full SHA-256: `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: main `0781ce048` (no source; binary-only)
- Claim status: reconstruction of the control flow, the extension rule and the error/ok result protocol of `0x422e410` as evaluated on #115 machine code. The nine helpers (clone, validity test, resolve, two loaders, two decoders, four error wrappers, format and wrap) are stubs; their meaning is not claimed. All role names are inferences.
- Scope:
  - Included: the complete FDE `[0x422e410, 0x422e72c)` (796 bytes, 191 instructions), all 19 call sites with slot and resolved target, the eight constants/byte windows that define the rules, the 4 direct callers, and the real execution of the extension comparison `0x159fca0`.
  - Excluded: bodies of the stubbed helpers; the 18 landing-pad instructions at `0x422e6f0..0x422e72c` (never executed by design); the three other callers `0x2ae4f0b`, `0x2cdf007`, `0x564a68c`.
  - Context: the chain packet RE-016-state-load-chain treats this function as a stub named `lookup`; this packet replaces that guess for the callee.

## Reproduce

Working directory: repo root. Python 3, stdlib only, plus `tools/elf_index.py`, `tools/fde_extents.py` and the merged `tools/re16_state_materialize115.py` (its x86-64 evaluator). No external program is called and the binary is never executed.

```
python3 tools/re16_path_loader115.py --out research/work-items/RE-016-path-loader-115
python3 -m unittest tests.test_re16_path_loader115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool refuses to run unless the input SHA-256 equals the value above. `MANIFEST.sha256` lists every file here except itself.

## Evidence

All numbers come from ELF bytes read with Python (`struct`); `objdump` is not used by the tool. Coordinates are virtual addresses.

Observed (static, `constants.json`, `calls.tsv`):
- FDE `0x422e410..0x422e72c`, 796 bytes, 191 instructions. The three-byte constant at `0x7c95c0` is `72 6d 70` (`rmp`); it is passed as `rdx` with `ecx = 3` to `0x159fca0`, whose short path (length 3) compares byte by byte after OR-ing `0x20` into bytes in `A..Z` (`lea r-0x41; cmp 0x1a; setb; shl 5; or`), i.e. ASCII case folding.
- GOT/RELATIVE slots used: `0x64e0948 -> 0x1500c10`, `0x64e0950 -> 0x1500d20`, `0x64e0938 -> 0x5cab560`, `0x64e09b8 -> 0x5ca4d50`, `0x64e09c0 -> 0x5ca4940`, `0x64df6e8 -> 0x141e3a0`, `0x64df4a0 -> 0x635de30`; direct calls `0x43030c0`, `0x159fca0`, `0x422ecc0`, `0x422eb70`, `0x3ef18b0`, `0x422ebf0`, `0x3266520`, `0x422eac0`.
- Direct callers (byte scan of every `e8`): `0x2ae4f0b 0x2cdf007 0x3c13536 0x564a68c`; no RELATIVE addend equals `0x422e410`.
- The resolve request is a stack record: `{ptr, len, tag byte 6 at +0x10, flags word 0x0201 at +0x38, is_abs byte at +0x3a}`; the result tag byte 9 means "string ok".
- 14 byte-exact windows (`constants.json`, `checked_bytes`) pin the `/` test, the request constants, the `..` test (`66 81 39 2e 2e`), the backward scan, the `ecx = 3` length, and the two `jno` tests (`word0 == i64::MIN`).
- `instructions.tsv`: 173 of 191 instructions are executed by at least one case; the other 18 are exactly the landing pad `0x422e6f0..0x422e72c`.

Reconstructed flow (`model()`; `flow.tsv` has one symbolic trace per call-shape):
1. `S = clone(ptr, len)` into a `(cap, ptr, len)` owner on the frame.
2. `valid(S.ptr, S.len)` false -> `format` with the template at `0x43b857` and a two-argument record, `wrap` -> return `(1, wrapped)`; the clone is freed if `cap != 0`.
3. `is_abs = len != 0 && S.ptr[0] == '/'`; `resolve(request{S.ptr, len, 6, 0x0201, is_abs})`.
4. Result tag != 9 -> the "other" branch. Tag 9 -> string `T`: `T == ".."` -> other; scan `T` backwards for the last `.` (no path-separator awareness); none or index 0 -> other; extension length 3 and `eq_ignore_ascii_case(ext, "rmp")` -> **rmp branch**, anything else -> other.
5. rmp branch: `load_rmp(S)` returns three words `(w0, w1, w2)`; `w0 == i64::MIN` is the error arm (`0x422ecc0(w1)`, return `(1, e)`); otherwise decode with `0x3266520` over a record `{w1, w2, w1, w2, 1, 0x20, 0}`; result tag byte 9 -> `(0, value)`, else `0x422eac0` converts the four result words into the error `(1, e)`; `w1` is freed with size `w0` when `w0 != 0`.
6. other branch: `load_other(S)` (same three words), `w0 == i64::MIN` -> `0x422eb70(w1)`, `(1, e)`; otherwise decode with `0x3ef18b0` over `{w1, w2, 0, 0, w1, w2}`; returned `rax == 1` -> `0x422ebf0(rdx)` gives `(1, e)`, else `(0, rdx)`; `w1` freed when `w0 != 0`.
7. Every path ends with: free the clone when `cap != 0`; return `(rax = 0|1, rdx)`.

Inferred (not proven): that the second branch is a text format (it is not `rmp`), that `valid` is a UTF-8 or path validity test, that `resolve` normalises the path, that the loader reads a file.

## Implementation and comparison

Implementation is a pure Python `model()` plus the concrete x86-64 evaluator reused from the merged `tools/re16_state_materialize115.py`. This packet adds the `66`-prefixed 16-bit immediates of `c7 /0` and `81 /n` to its decoder and one instruction form (`shl r9b/r10b, 5`, checked against the exact bytes `41 c0 e1 05` / `41 c0 e2 05`). No Rust path is claimed yet; each branch of `model()` maps to one Rust `match` arm. No Rust build, so no Cargo.lock/two-build results.

Comparison per case: the ordered symbolic call trace (every stub call with decoded arguments, the stack record contents, the traced arguments of the real `0x159fca0` call), return `rax`/`rdx`, and callee-saved registers plus `rsp` restored.

14,000 deterministic cases (SHA-512 stream, a 12-slot mode cycle): path strings with and without leading `/`, invalid UTF-8, empty; resolved strings with every extension shape (`rmp`, `RMP`, `rMp`, `rm`, `rmpx`, `xrmp`, `json`, empty, `..`, `.`, hidden `.rmp`, nested dots); tag 9 and eight other tags; loader word0 = `i64::MIN`, `MIN±1`, 0, `u64::MAX`; decoder results with every tag. `cases.tsv` records every case (outcome, call count, rax). Outcome classes (`outcome-classes.tsv`): early/err 2802, other/err 2935, other/ok 5563, rmp/err 1313, rmp/ok 1387.

Negative controls (33, all detected): 8 model mutants (no `..` rule, wrong dot character, hidden file accepted, case-sensitive compare, inverted validity, always-absolute, swapped branches, `i64::MIN` ignored); 22 one-byte code mutants (request tag and flags, tag-9 tests, `..` length and bytes, scan byte, extension length, five branch senses, the two `jno` tests, return values, decode `rax == 1`); a flipped `.text` byte (input hash), an address past `.text`, and an out-of-range read.

## Results and limitations

Machine-readable metrics: `summary.json`, `measure.json` (14,000 cases, 0 mismatches, 33 of 33 controls detected, 5 outcome classes).

Limits:
- Helper behaviour is not reconstructed; the function is proven only relative to the stub interface (arguments, return registers, the stack record contents).
- Unwinding (landing pad) paths are not evaluated.
- The tool executes in the order of 100 MB; the data files are dominated by the per-case table (`cases.tsv`), so the data ratio is above the 0.6 target.
- No gate is requested; the `abci` component remains partial.

Next question: reconstruct the sibling family `0x422ed40`/`0x422f030` (same extension rule plus a nine-byte device-path special case, `rmp` constant at `0x4659e5`) and the two loader slots `0x5ca4d50` / `0x5ca4940`.
