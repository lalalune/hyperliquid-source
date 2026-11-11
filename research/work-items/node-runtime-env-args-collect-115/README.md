# node-runtime: reconstruct node #115 process-argument iteration (std::env::args) from the ELF bytes

- Component ID: node-runtime (Node runtime and gossip; startup argument path)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main at the time of writing; no external source copied
- Claim status: observation (bytes run in an evaluator and compared with a written rule list); names such as "collector" and "drop" are inferences
- Scope included and excluded: the four bodies that turn the two startup argument cells into checked strings (collector `0x5c9a530`, next `0x5caa830`, UTF-8 validator `0x16815e0`, string-vector drop `0x5c73990`) with allocator, copy, length and panic edges replaced by recording stubs. Excluded: the initializer that stores the cells (`0x5ca55c0`, covered elsewhere), the build-mode consumer of the iterator (`0x1568de0`), the lowercase transform `0x150caf0` (its decoder coverage is incomplete here) and any CLI flag parsing after the arguments are collected.

**What this lets us reconstruct.** The whole life of the process argument vector can now be written as a few lines of Rust-equivalent logic and is proven against the bytes: `argc`/`argv` cells become an owning iterator of `(capacity, pointer, length)` strings (capacity equals length, empty arguments use the dangling pointer 1, a null entry ends collection early, a null `argv` yields the empty iterator with buffer 8 and capacity 0, and a count above `0x555555555555555` is an allocation error); `next` advances its cursor *before* testing the element, treats a capacity of `0x8000000000000000` as `None`, and otherwise validates UTF-8 and panics through `unwrap_failed` with a 43 byte message; the validator is exactly the Rust `str::from_utf8` rule and returns `(valid_up_to, Option<error_len>)`.

## Reproduce

From the repository root with Python 3.11+ (standard library only) and the pinned node binary materialized:

```sh
python3 tools/node_env_args_115.py --out research/work-items/node-runtime-env-args-collect-115
python3 -m unittest tests.test_node_env_args_115
(cd research/work-items/node-runtime-env-args-collect-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the binary SHA-256 first, never executes it, and calls no external program. Output is byte-identical across runs (checked twice, with different hash seed and time zone). Peak resident memory is below 1.5 GB (cases are generated, run and compared one at a time; only the 977 detection cases are kept).

## Evidence

All numbers come from reading ELF bytes with `tools/elf_index.py` / `tools/fde_extents.py` through the shared evaluator of `tools/bole_rate115.py`. Addresses are ELF virtual addresses.

- `functions.tsv`: FDE extents, byte sizes, instruction counts, executed counts and SHA-256 of each body (collect 473 bytes, next 204 bytes, validate 503 bytes, drop 134 bytes).
- `coverage.tsv`: every decoded instruction with its raw bytes and whether any case executed it.
- `slots.tsv`: the seven GOT slots used by the four bodies, their relocation type (8 = relative, 6 = glob-dat) and the role each recording stub models. The roles are inferences from argument registers, not symbol names (only `memcpy` and `strlen` carry dynamic symbol indices 7 and 9).
- `constants.tsv`: the unwrap message (43 bytes at `0x949294`), its panic Location (`library/std/src/env.rs:864:51`), and the relative relocations binding the iterator constructor slot `0x64e1290`, next slot `0x64e1298` and validator slot `0x64dfca8` to the three bodies.
- `samples.tsv`, `summary.json`, `controls.tsv`, `measure.json`: sampled outcome digests, totals, and every negative control with its verdict.

Observed behaviour, each point proven by the comparison below:

1. Collector `0x5c9a530(out)`: reads count cell `0x6500000` and pointer cell `0x6500008`. Null pointer: out = (8, 8, 0, 8). Count above `0x555555555555555`: `handle_alloc_error(0, count*24)`. Count 0: out = (8, 8, 0, 8) without allocating. Otherwise allocates `count*24` (alloc failure: `handle_alloc_error(8, size)`), then for each index calls `strlen`, stops at the first null entry, allocates `len` bytes (failure: `handle_alloc_error(1, len)`; zero length skips allocation and uses pointer 1) and copies; each row is (len, ptr, len). Out = (buffer, buffer, capacity, buffer + 24*rows).
2. Next `0x5caa830(out, iter)`: if cursor == end, out[0] = `0x8000000000000000`; else advance the cursor by 24, and a first word of `0x8000000000000000` also gives `None`; otherwise call the validator through slot `0x64dfca8`; Ok copies the triple, Err calls `unwrap_failed(msg 0x949294, 43, &triple, vtable 0x64c3290, Location 0x64c3240)`.
3. Validator `0x16815e0(out, ptr, len)`: tag 0 for valid text, else tag 1, `valid_up_to` at +8, and a presence byte at +16 with `error_len` at +17.
4. Drop `0x5c73990(vec)`: frees every row whose capacity is non-zero as `(ptr, cap, 0)`, then the buffer as `(buffer, cap*24, 0)` when its capacity is non-zero.

## Implementation and comparison

`tools/node_env_args_115.py` contains (a) an independent rule list in plain Python (`Spec`, `utf8_error`) written from the Rust semantics, (b) the evaluator harness that runs the *real bytes* of the four bodies with stubs for allocate, deallocate, `handle_alloc_error`, `memcpy`, `strlen` and `unwrap_failed`, and (c) deterministic case streams. After each case the harness checks that the heap outside the result and the allocations is unchanged, that callee-saved registers and the stack balance are preserved, and compares the rule list's prediction for the result and for the entire call log.

- Cases: 12000 total: collector 735, next 770, validator 9722, drop 773. Mismatches: 0. Outcome counts: collect/ok 593, collect/panic 142, drop/ok 773, next/none 362, next/panic 160, next/some 248, validate/err 8894, validate/ok 828.
- Validator coverage: all 256 one-byte inputs, all pairs and triples over a 20 byte boundary alphabet, four-byte lead tails, 60 long inputs (8-87 bytes, varied alignment) and a random tail.
- Negative controls: 167 counted, all detected. Byte edits of the real code (condition flips, immediates, displacements of every executed instruction that the decoder can edit): 142 detected of 163 tried; 15/15 deliberately wrong rule variants; 10/10 structural controls (digest change, non-function addresses, wrong slot, corrupted argv, boundary count).
- Edits that survived the 977 detection cases are listed in `controls.tsv` and `summary.json` and are **not** counted: 21 edits (mostly validator arms for the longest inputs and rarely used immediates). They may be equivalent or may need cases this packet lacks; they are reported as unresolved.
- Outcome stream SHA-256 (all 12000 rule predictions): `f1c88dbe8cc587829c35840f6e899cd4176e506ffc4e9813151e79b8844893bf`.

Recording stubs are the main assumption: allocation is a bump allocator that fails for sizes above 0x4000, `memcpy`/`strlen` have C semantics, and `unwrap_failed`/`handle_alloc_error` never return. The meaning of the grow slot `0x64eb000` is not established; the evaluator halts if it is reached and it was never reached.

## Results and limitations

- Passed: 12000/12000 cases; 167/167 counted controls.
- No Rust implementation is claimed and no acceptance gate is changed. The packet reconstructs behaviour of four bodies, not the process startup or any flag parsing.
- The Rust source names, the claim that capacity equals length for every row, and the stub roles are inferences. The evaluator is a small x86-64 subset interpreter; instructions outside it make a case halt rather than pass.
- Not covered: the lowercase transform and the build-mode initializer that consume the iterator, the panic machinery behind `unwrap_failed`, unwinding landing pads, and multi-threaded access to the argument cells.

## Next question

Run the lowercase transform `0x150caf0` (needs a decoder for the `0f` opcode at `0x150cc8c`) and the build-mode initializer `0x1568de0` on top of this iterator to reconstruct the whole selection of the cached build-mode string.

## Instructions no case executed

Listed from `coverage.tsv` (function, address, bytes, operation); these are the paths the 12000 cases did not reach (unwinding paths, `ud2` traps and growth are likely members; not classified).

- collect 0x5c9a60f `90` nop
- collect 0x5c9a67e `eb10` jmp
- collect 0x5c9a690 `488d7dc0` lea
- collect 0x5c9a694 `ff1566098500` calli
- collect 0x5c9a69a `488b55c8` mov
- collect 0x5c9a69e `e96dffffff` jmp
- collect 0x5c9a6cc `0f0b` ud2
- collect 0x5c9a6ce `4889c3` mov
- collect 0x5c9a6d1 `4d85e4` test
- collect 0x5c9a6d4 `7422` jcc
- collect 0x5c9a6d6 `4c89ef` mov
- collect 0x5c9a6d9 `4c89e6` mov
- collect 0x5c9a6dc `31d2` xor
- collect 0x5c9a6de `ff15bc4d8400` calli
- collect 0x5c9a6e4 `488d7dc0` lea
- collect 0x5c9a6e8 `e8a392fdff` call
- collect 0x5c9a6ed `4889df` mov
- collect 0x5c9a6f0 `e85b637500` call
- collect 0x5c9a6f5 `4889c3` mov
- collect 0x5c9a6f8 `488d7dc0` lea
- collect 0x5c9a6fc `e88f92fdff` call
- collect 0x5c9a701 `4889df` mov
- collect 0x5c9a704 `e847637500` call
- next 0x5caa8da `0f0b` ud2
- next 0x5caa8dc `4889c3` mov
- next 0x5caa8df `488b75c8` mov
- next 0x5caa8e3 `4885f6` test
- next 0x5caa8e6 `740c` jcc
- next 0x5caa8e8 `488b7dd0` mov
- next 0x5caa8ec `31d2` xor
- next 0x5caa8ee `ff15ac4b8300` calli
- next 0x5caa8f4 `4889df` mov
- next 0x5caa8f7 `e854617400` call
- validate 0x168161e `6690` nop
- validate 0x1681648 `0f1f840000000000` nop
- validate 0x1681683 `666666662e0f1f840000000000` nop
- validate 0x16817a3 `b303` mov
- validate 0x16817a5 `eb17` jmp
- drop 0x5c739bb `0f1f440000` nop
