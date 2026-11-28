# Node #115 selected vault-weight snapshot and writeback

Partial HL115-063, pinned to node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Prior [#3945](https://github.com/lalalune/hyperliquid-source/pull/3945) traces the admitted vault value transfer. This packet now covers the positive-delta prepass and the selected normal snapshot/writeback continuation of `0x44ad9e0`; it does not name the owner state, financial units or complete transfer semantics from these offsets.

## Boundary and selected continuation

The function takes signed `initial` (RCX) and `delta` (RDX), adds them with a signed-overflow diagnostic branch, and derives `max(initial + delta, 0) / 1e6` as the denominator. For `delta <= 0`, it skips the prepass. For `delta > 0`, it calls `0x44a9430` for the owner's 20-byte address at `owner+0x8c`. If the low dword at `owner+0` is `2` and the child collection's root (`owner+8`) and count (`owner+0x18`) are nonzero, it walks the collection's key/parent/edge fields, copies each 20-byte key, and calls `0x44a9430` for that key. The returned signed values are accumulated with signed saturation; an overflow reaches the diagnostic call through slot `0x64e4ea8` with the location pointer `0x648b9c0`, then iteration continues on the normal callback return.

At the join `0x44adce7`, the helper overwrites the accumulator register `r12` with `0x8000000000000000`, restores the original `initial` from `[rsp+8]`, the original signed sum from `[rsp+0xa0]`, and its nonnegative clamp from `[rsp+0x98]`. The snapshot then converts the restored `initial` at `0x44add34`. Therefore the prepass aggregate does not feed the later weight calculation; the observed remaining effects are the helper calls and any overflow diagnostics. The prepass's motivation and any side effects inside its callees remain unknown. The owned model's input map represents the state at the snapshot boundary. Signed overflow and non-returning helpers are explicit stop boundaries.

### Raw-byte witnesses for the prepass boundary

These selected rows are copied from the pinned ELF's `.text` bytes (addresses are ELF virtual addresses). They make the branch, call, accumulation, and join claims reviewable without relying on the retained JSON instruction table. They are local witnesses, not a substitute for the complete-window verifier or the case results.

| Address | Bytes | Decoding / role |
| --- | --- | --- |
| `0x44ada21` | `4d 85 ed` | `test r13,r13` — signed delta is checked at `0x44ada24`; `jle` at `0x44ada29` bypasses the prepass for nonpositive delta. |
| `0x44ada49` | `49 8d b7 8c 00 00 00` | `lea rsi,[r15+0x8c]` — owner key passed to the first amount call. |
| `0x44ada53` | `e8 d8 b9 ff ff` | direct call to `0x44a9430`. |
| `0x44ada58` | `41 83 3f 02` | `cmp DWORD PTR [r15],2` — mode check before child traversal. |
| `0x44ada6a` | `48 8b 41 08` | load child collection root from `owner+8`; the following instructions also require nonzero root and count. |
| `0x44adc47` | `48 8d 04 92` | `lea rax,[rdx+rdx*4]`; followed by `mov edx,[rcx+rax*4+0x18]` and `movupd xmm0,[rcx+rax*4+8]` to copy the selected 20-byte key. |
| `0x44adc67` | `e8 c4 b7 ff ff` | direct call to `0x44a9430` for the copied child key. |
| `0x44adc6c` | `4c 89 e1` | `mov rcx,r12`; next `add rcx,rax` at `0x44adc6f`, with `jo` at `0x44adc72` selecting the overflow diagnostic. |
| `0x44adce7` | `4c 8b 7c 24 68` | join reloads owner, then `movabs r12,0x8000000000000000`; original inputs are reloaded at `0x44adcfb`, `0x44add00`, and `0x44add08`. |
| `0x44add34` | `f2 48 0f 2a c1` | `cvtsi2sd xmm0,rcx` — snapshot converts the restored original `initial`, not the prepass aggregate. |

The bytes can be checked directly against the target with `objdump -d -Mintel --start-address=0x44ada21 --stop-address=0x44add39 artifacts/node/115/hl-node`; the verifier independently checks the target digest and all selected windows.

`0x3bcc440` calls the collector `0x3dda220`, which maps the existing 72-byte keyed rows to 32-byte rows: 20 key bytes and a binary64 value equal to the existing row value at +0x18 multiplied by `initial / 1e6`. The flat path uses a 72-byte stride; helper entry and comparator windows identify 20-byte key comparisons and 32-byte temporary rows. The selected entry call `0x3cd3dd0` / `0x3f170d0` obtains or inserts the target in this temporary map with zero on vacancy, then adds `delta / 1e6` to its stored value. Normal allocation, logical key uniqueness and native tree/ring iteration are premises; physical balancing and unwind are outside scope.

For every temporary value, the original emits zero if it is strictly less than `1e-7` (equality passes this threshold), is nonfinite, or the denominator is below `1e-15`. Otherwise it divides by the denominator and replaces a positive-infinite quotient with zero. The denominator is derived from a nonnegative signed integer divided by `1e6`, so a positive value is at least `1e-6` in this modeled domain; the native denominator test is therefore equivalent to checking for zero. Exact constants and both branches are retained in the packet. Normal binary64 rounding and a standard floating-point environment are premises.

The `0x3cd3550` / `0x3f19c20` entry path writes the result back into the corresponding original keyed row. For an occupied entry only the first binary64 word of its 48-byte value is written; the rest is preserved. A vacant entry starts with 24 zero bytes followed by two copies of the supplied 12-byte seed, and the first word is then overwritten with the ratio. The model preserves the remaining 40 bytes. It does not claim to close allocator failure, diagnostics, synchronization, rollback, durability or the source's original field names.

## Validation

`python3 research/work-items/RE-001-node115-vault-weight-update/verify.py` checks the target digest, 15 selected windows (2,993 bytes / 711 instructions), four float constants, the prepass and writeback call/operand rows, and 42 semantic corruption controls. No captured instruction is executed or emulated. Five Rust tests cover existing and vacant entries, preserved tails, signed overflow stop, zero denominator, NaN/infinity, the floating threshold and its adjacent representable values, and quotient overflow. Both `cargo test --offline --locked --manifest-path src/node115-vault-weight-update/Cargo.toml` and its `--release` variant passed (5 tests each).

`make doctor` reported `analysis_ready=true`, `exact_rebuild_ready=false`; it executed no captured binary. `make index` succeeded and generated 135,313 unwind entries, but this is not a complete function census and did not create `work/index/node-115-fde.tsv`. `make verify`, `make reproduce`, and `make catalogue-check` passed. The full `make test` run completed all 1,741 test files but exited nonzero: 98 files failed. The log is `/tmp/hls-vault-prepass-make-test-after-index.log`. Of the failed files, 54 reported a missing `work/index/node-115-fde.tsv`; other observed failures include a missing `bwrap` isolation facility on this macOS arm64 host and byte/manifest checks in unrelated packets. After that run, `make fde-index` generated 135,313 FDE extents and the affected vault closure check, `python3 -m unittest discover -s tests -p test_vaults_closure_115.py -v`, passed (2 tests). The other full-suite failures were not rerun, so the repository-wide run remains non-passing. These failures do not establish a defect in this selected-window packet. The packet's own verifier and focused Rust tests passed independently. The release test emitted a `rust-objcopy` warning because this host lacks its `libLLVM.dylib`; compilation and all five release tests still succeeded.
