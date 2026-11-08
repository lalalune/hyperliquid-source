# RE-016: node #115 state-file writer pair 0x422ed40 / 0x422f030, its parent-path precheck, error wrappers, context builder and the three-field serializer 0x38c20b0 reconstructed as one write flow

With this packet the counterpart of the RE-016 loader `0x422e410` can be rebuilt as Rust: `0x422ed40` (and its byte-twin `0x422f030`) is a **writer** that returns early for the exact nine-byte path `/dev/null`, resolves the path, picks the binary serializer when the resolved name's extension is `rmp` (ASCII case-insensitive, last dot, `..` and a leading dot rejected) and the text serializer otherwise (a fresh 0x80-byte buffer), and then writes the buffer behind a precheck (`0x15020f0`, reconstructed here: it resolves the path, optionally replaces it by the result of a lookup/convert pair, and creates the directory with mode `0x1ff` and a recursive flag when an existence test fails), mapping every serializer failure through two context wrappers (`0x422f670` for boxed errors, `0x422f740` for inline errors with an `i64::MIN` niche encoding). Twin B's binary serializer `0x38c20b0` is a three-field struct writer (header, three named fields at value offsets `+0`, `+0x810`, `+0x1020`, stop at the first failure) and is run as real code inside twin B. The reconstruction (pure-Python models) is compared with the real machine code of seven functions in 17,400 cases with 0 mismatches, and all 131 negative controls are detected.

- Component ID: `abci` (work item RE-016, state-load chain; the writer is the sibling of the loader `0x422e410` and is called from the same two large callers `0x2ae4f3f` and `0x2cdf03b`)
- Target release and full SHA-256: `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: main `0781ce048` (no source; binary-only)
- Claim status: reconstruction of control flow, extension rule, result protocol and call-argument shapes of five #115 functions as evaluated on machine code. The callees listed under "stubbed" are not reconstructed and their meaning is not claimed. All role names are inferences; `0x422ed40` was only mapped before (RE-009-abci-state-export-115 `format_router`, RE-011 `write_file` for `0x422f030`), neither packet reimplements it.
- Scope:
  - Included: complete FDEs `[0x422ed40, 0x422f024)` and `[0x422f030, 0x422f314)` (740 bytes each), `[0x422f670, 0x422f735)` (197), `[0x422f740, 0x422f7f9)` (185), `[0x38c20b0, 0x38c2224)` (372), the precheck `[0x15020f0, 0x15021c2)` (210) behind GOT `0x64e0028`, and the context builder `[0x43034f0, 0x430352a)` (58) that both wrappers call; every call site with slot and resolved target; the real execution of the extension comparison `0x159fca0`; 635 instructions.
  - Excluded (stubbed with exact argument capture): the resolver `0x5cab560`, binary serializer `0x3c13960` (7,009 bytes, twin A), text serializers `0x3c136f0` / `0x38c2230`, headers `0x3d4f6d0` / `0x3d50270`, field writers `0x41c6110` / `0x36c5b50`, the precheck helpers `0x64e09b0` / `0x64dfca8` / `0x64e0928` / `0x64e0940` / `0x1500b90`, the context builder callees `0x141e3a0` / `0x43030c0` / `0x4303130`, the drop helpers `0x4232440`, allocation, buffer write `0x64e09e8` and the deallocator; unwinding landing pads.

## Reproduce

Working directory: repo root. Python 3, stdlib only, plus `tools/elf_index.py`, `tools/fde_extents.py` and the merged `tools/re16_state_materialize115.py` (its x86-64 evaluator, used through `mat.fde_rows`, `mat.sweep_padded`, `mat.call_sites`, `mat.caller_scan`). No external program is called and the binary is never executed. About 28 s and 340 MB resident.

```
python3 tools/re16_state_writer115.py --out research/work-items/RE-016-state-writer-115
python3 -m unittest tests.test_re16_state_writer115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool refuses to run unless the input SHA-256 equals the value above. `MANIFEST.sha256` lists every file here except itself.

## Evidence

All numbers come from ELF bytes read with Python (`struct`); `objdump` is not used by the tool. Coordinates are virtual addresses.

Observed (static; `constants.json`, `calls.tsv`):
- The two writers are byte-twins: after normalising rip-relative displacements they differ only in the two serializer calls (`0x3c13960` / `0x3c136f0` in A, `0x38c20b0` / `0x38c2230` in B).
- Both start with `cmp $9, rdx` and `movabs $0x6c756e2f7665642f` (`/dev/nul` little endian) xor-compared with the first 8 bytes plus `xor $0x6c` on the ninth byte: exact equality returns `0` before any helper runs. Any other length-9 path continues (`is_abs` is then taken from the first byte).
- Resolver request (GOT `0x64e0938`): `{ptr, len, tag byte 6 at +0x10, flags word 0x0201 at +0x38, is_abs byte at +0x3a}`; result tag byte 9 means "string ok" and carries `(ptr, len)`; any other tag goes straight to the text branch.
- Extension rule: `len == 2 && == ".."` rejected, backward scan for `0x2e`, index 0 rejected, remaining bytes compared by the real `0x159fca0` with `rdx = 0x4659e5` (`72 6d 70` = `rmp`) and `ecx = 3`.
- Binary branch: Vec `{cap 0, ptr 1, len 0}` at `rsp+0`, options at `rsp+0x88` `{vec ptr, dword 0x01000400, byte 0}`, call with `rdi = out (rsp+0x38)`, `rsi = value`, `rdx = options`; the result is Ok iff word0 equals `0x8000000000000004` (`movabs 0x8000000000000000; or $4`). Failure frees the Vec when `cap != 0` and passes the three result words to `0x422f740`.
- Text branch: allocation of 0x80 bytes (GOT `0x64df480`); null ends in the noreturn handler `0x64df498(1, 0x80)`; Vec `{0x80, ptr, 0}`, options `{vec ptr, 0x7c809e, 2, 0, 0}` (`0x7c809e` holds the two bytes `20 20`, i.e. two spaces: the text serializer is handed a two-space indent, which suggests pretty-printed text; that reading is an inference); a nonzero return is an error pointer for `0x422f670` after freeing the Vec; `neg cap; jo` routes `cap == i64::MIN` to `0x422f670` with the buffer pointer.
- Write phase: GOT `0x64e0028(path, len)` (precheck) – on 0 GOT `0x64e09e8(buf, len, path, plen, extra)` supplies the result, otherwise the precheck result is returned; the Vec is freed when `cap != 0` with the result kept in `rbx`.
- Precheck `0x15020f0(path, len)`: same resolver request as the writer (`is_abs`, tag 6, flags 0x0201); result tags 7..9 (`add $0xf9; cmp $3`) call GOT `0x64e09b0(&request)`, a nonzero result goes to GOT `0x64dfca8(&record, result)` and a record whose first dword is not 1 replaces `(ptr, len)` with its words at `+8` / `+0x10`; GOT `0x64e0928(ptr, len)` with `al != 0` returns 0; otherwise GOT `0x64e0940({dword 0x1ff, byte 1}, ptr, len)` returns 0 or an error pointer that `0x1500b90` wraps. What the three helpers compute (parent lookup, existence test, recursive create) is inferred from the constants only.
- Context builder `0x43034f0(a, b)`: bit 0 of `b` set -> tail call `0x4303130(a, b >> 1)`; clear -> `0x141e3a0`-style format into a 0x20-byte frame buffer (GOT `0x64df6e8`) and `0x43030c0` wrap. Both wrappers always pass an aligned record pointer, so the format arm is the one they reach.
- Wrapper `0x422f670` (boxed error, 0x28-byte box): builds a four-word context record `{slot, 0x46dd7f0, &err, GOT 0x64e01a8 value}` for `0x43034f0` with template `0x44e417`; word0 == 1 drops the nested value at `+8`, word0 == 0 frees `(ptr +8, cap +0x10)` when `cap != 0`, then frees the 0x28-byte box; returns the context result.
- Wrapper `0x422f740` (inline error): same context call with GOT `0x64e0a48`; class = `w ^ i64::MIN` for negative `w`, otherwise 4; classes 1..3 own nothing, class 0 drops the nested value at `+0x10`, everything else frees `(ptr +8, cap w)` when `w != 0`.
- `0x38c20b0`: options byte `+0xb == 0` selects header `0x3d50270`, otherwise `0x3d4f6d0` (count 3); header tag 2 is Ok, otherwise result `(i64::MIN, tag, w1)`; with `+0xb == 1` each field is preceded by a name (`0x7a1422/0xd` = `accounts_hash`, `0x7a142f/0xe` = `contracts_hash`, `0x7a143d/0xc` = `storage_hash`, bytes read from the ELF, a return of 2 is Ok, otherwise `(i64::MIN, rax, rdx)`); each field value is `0x36c5b50(&tmp, value + {0, 0x810, 0x1020}, options)` and Ok iff word0 == `0x8000000000000004`; the first failure is copied out, success writes only word0.
- 32 byte-exact windows (`constants.json`, `checked_bytes`) pin the `/dev/null` immediate, request constants, the `..` test, the extension length, the options dword, the Ok marker, buffer size, `neg/jo`, the wrapper class constants and the flag-byte tests.
- The wrappers have one more caller each outside the writers (`0x422f606` for `0x422f670`, `0x422f5a1` for `0x422f740`, in the code after `0x422f314`); those are not re-owned here.
- Direct callers of the two writers appear in `constants.json` (`direct_callers`); the earlier RE-009 packet's call sites `0x2ae4f3f` / `0x2cdf03b` call `0x422ed40`, the RE-011 packet's `0x38c263b` calls `0x422f030`. Those callers are not re-owned here.
- `instructions.tsv`: 584 of 635 instructions are executed by at least one case. The 51 others are exactly the unwinding landing pads and the tails after noreturn calls (A `0x422eff1..0x422f024`, B `0x422f2e1..0x422f314`, wrapper bodies after the last `ret`).

Reconstructed writer flow (`model_writer()`; `flow.tsv` has one symbolic trace per call shape):
1. path == `/dev/null` (9 bytes): return 0.
2. `resolve(request)`; tag 9 -> `ext_of(resolved)`; extension length 3 and `eq_ignore_ascii_case(ext, "rmp")` -> binary branch; else text branch.
3. Binary: serializer; word0 != Ok marker -> free Vec if cap, `0x422f740(&slot{path,len}, &result)` and return its value.
4. Text: alloc (null -> noreturn); serializer; error pointer -> free Vec if cap, `0x422f670(&slot, err)`; `cap == i64::MIN` -> `0x422f670(&slot, ptr)`.
5. `precheck`; if 0 `write_buffer`; free Vec if cap; return the result.

## Implementation and comparison

Implementation is pure-Python models (`model_writer`, `model_wrap`, `model_ser`) plus the concrete x86-64 evaluator of the merged `tools/re16_state_materialize115.py`. This packet adds the `66`-prefixed 16-bit immediates of `c7 /0` and `81 /n` to its decoder and the one `shl r9b/r10b, 5` form inside `0x159fca0` (checked against `41 c0 e1 05` / `41 c0 e2 05`). No Rust path is claimed yet; each branch of the models maps to one Rust `match` arm. No Rust build, so no Cargo.lock/two-build results.

Comparison per case: the ordered symbolic call trace (every stub call with decoded argument words, the stack records read by the stub, the traced arguments of the real `0x159fca0` call), the return register, callee-saved registers plus `rsp` restored, and for `0x38c20b0` the out words and the Vec words. Stubs scramble all caller-saved registers.

17,400 deterministic cases (SHA-512 stream): writer A 2,800 and writer B 2,800 (16-slot mode cycle: `/dev/null` and near misses of length 9, tag 9 with every extension shape, eight other tags, serializer Ok/failure words, Vec words with `cap` in `{0, 1, 0x80, i64::MIN, i64::MIN+1, u64::MAX, random}`, allocation failure, error pointer, precheck failure), wrapper `0x422f670` 2,400, wrapper `0x422f740` 2,400 (word0 over every class boundary `i64::MIN..i64::MIN+5`, 0, 1..5, `u64::MAX`), precheck 2,600 (path shapes, result tags 0..0xff incl. 7/8/9 and high-byte noise, lookup null / non-null, converted dword 0/1/2/`0x1_0000_0001`, existence word with only a high byte set, mkdir null / error), context builder 1,600 (bit 0 set and clear), struct serializer 2,800 (flag byte `0, 1, 2, 0x7f, 0xff`, header tag, per-name and per-field failures, Vec rewrites). `cases.tsv` records every case; columns a/b/c are path length / resolved name hex / resolver tag for writers, path length / tag / lookup-and-convert state for the precheck, bit 0 for the context builder, word0 hex / cap-nonzero / `-` for wrappers and flag / header tag / ok-name-and-field counts for the struct serializer. Outcome classes: `outcome-classes.tsv` (51 trace shapes, e.g. twin B reaches the full Ok path through all three fields in 79 cases and each early-exit position at least 25 times).

Negative controls (131, all detected): 32 model mutants (no `..` rule, wrong dot char, hidden file accepted, case-sensitive compare, always-absolute, swapped branches, `/dev/null` shortcut removed, Ok test inverted, precheck ignored, free skipped for both writers; wrapper tag swap / cap ignored / niche ignored; header swap, names always, Vec not updated; precheck tag window / convert ignored / exists ignored; context builder bit swapped / shift missing); 96 one-byte code mutants (28 writer-A sites applied to both twins = 56, 4 boxed-wrapper, 6 inline-wrapper, 11 struct-serializer, 16 precheck and 3 context-builder sites); a flipped `.text` byte (input hash), an address past `.text`, and an out-of-range read.

## Results and limitations

Machine-readable metrics: `summary.json`, `measure.json` (17,400 cases, 0 mismatches, 131 of 131 controls detected, 584/635 instructions executed).

Limits:
- Stubbed helpers are not reconstructed; each function is proven only relative to the stub interface (argument registers, the stack records the stubs read, return registers). The meaning of the resolver, the precheck helpers and the buffer write is not claimed.
- Unwinding (landing pad) paths and the noreturn tails are not evaluated.
- Twin A's binary serializer `0x3c13960` and the text serializers remain unreconstructed; only twin B's `0x38c20b0` is covered.
- Data files are dominated by the per-case table (`cases.tsv`), so the data ratio is above the 0.6 target; the code is an evaluator-driven reconstruction, not a Rust implementation.
- No gate is requested; the `abci` component remains partial.

Next question: the precheck helpers `0x64e09b0` / `0x64dfca8` / `0x64e0928` / `0x64e0940`, the field writers `0x41c6110` / `0x36c5b50` and headers `0x3d4f6d0` / `0x3d50270` (the byte layout the struct serializer drives), and the buffer write `0x15024a0` behind GOT `0x64e09e8`.
