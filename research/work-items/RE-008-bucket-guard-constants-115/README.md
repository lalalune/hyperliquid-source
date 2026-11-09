# RE-008: node #115 `bucket_guard/{}` constants: where `a` and `b` go, and what the record path reads

- Component ID: abci. Question: each `bucket_guard/{}` getter receives a name and two f64 values, `a` and `b` (open PR #5859 lists them per site; most sites pass `(0.01, 0.05)`). Where do the two values go, and does the observer's record path use them?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5839 (observer stage 2: constructor, window, the `+0x238` field) and #5859 (bucket_guard names). It does not depend on their files.
- Claim status: instruction bytes, relocations, call censuses, constant bytes and the operand scan are observations. "Getter", "observer", "count", "limit", "window record", "rollover" and the `Option` reading of `+0x0`/`+0x8` are inferred labels. The binary was not executed.
- Scope included: the vacant path of the four getters (`0x26d4660`, `0x3704070`, `0x4770930`, `0x51eaff0`), the constructor `0x1548bb0` stores that involve its f64 input, `+0x0` and `+0x238`, the record entry `0x1547530` (whole FDE, for operands on the observer register), the helper `0x1570f30`, and the 50 bucket_guard record calls. Scope excluded: callees of the record entry, any other reader of the observer map, the factor table values (RE-015) and the per-site pair values (#5859). No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/bucket_guard_constants_115.py --check
python3 -m unittest tests.test_bucket_guard_constants_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. `sites.objdump.txt` beside this record was made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read it.

## Evidence 1: the getter changes exactly three fields of the constructed observer

In each getter's vacant path (shown for `0x51eaff0`; the other three differ only in addresses, and `0x4770930` uses `[rsp+0x60]`/`[rsp+0x2c8]`, `r15` and a spill at `[rsp+0x58]`):

- `mov rcx,[rsi+0x8]; mov r14,[rsi+0x10]; movsd xmm0,[rcx]; movsd [rsp],xmm0` (`0x51eb03e`..`0x51eb04a`): `*a` is spilled, `b`'s pointer kept in `r14`.
- `lea rdi,[rsp+0x58]` (`0x51eb081`), `movsd xmm0,[rsp]` (`0x51eb088`), `call [0x64e1020]` (`R_X86_64_RELATIVE` to the constructor `0x1548bb0`): `*a` is the constructor's only f64 input.
- After the return: `movsd xmm0,[r14]; mov qword [rsp+0x58],1; movsd [rsp+0x60],xmm0` (`0x51eb096`..`0x51eb0a4`): the constructed value gets `1` at `+0x0` and `*b` at `+0x8`.
- `memcpy([rsp+0x2b8], [rsp+0x58], 0x238)` through GOT `0x64df508` (`0x51eb0aa`..`0x51eb0bc`), then two 16-byte copies from `[rsp+0x298]`/`[rsp+0x2a8]` to `[rsp+0x4f8]`/`[rsp+0x508]` (source and destination `+0x240`..`+0x25f`), and `mov qword [rsp+0x4f0],0xa` (`0x51eb0e2`, destination `+0x238`).

So the value inserted into the map equals the constructed observer except `+0x0` = 1, `+0x8` = `b` and `+0x238` = 10. The constructed `+0x238` is not copied. Inference: `+0x0`/`+0x8` is an `Option<f64>` set to `Some(b)`.

## Evidence 2: the constructor stores `a × factor` at `+0x218`, 0 at `+0x0` and 1000 at `+0x238`

- `movsd [rsp+0x10],xmm0` (`0x1548bc7`) saves the input.
- `call [0x64e1008]` (`0x1548cb6`, `R_X86_64_RELATIVE` to `0x15474d0`), then `movsd xmm2,[rsp+0x10]; mulsd xmm2,xmm0` (`0x1548cbc`, `0x1548cc2`). The selector reads configuration byte `+0x48` through slot `0x64e0918` and loads `[0x4671d0 + 8·byte]` (`0x15474e3`..`0x15474ee`). RE-015-scheduled-observer-115 maps that table (1.0 or 5.0 by network name) and the bit checks between `0x1548cc6` and `0x1548d21`; this packet does not re-prove them.
- The checked product is saved at `0x1548d25` and stored by `movsd [r14+0x218],xmm0` (`0x1548dd2`).
- `mov qword [r14],0` (`0x1548e12`) and `mov qword [r14+0x238],0x3e8` (`0x1548e30`).

So for a bucket_guard observer, `+0x218` holds `a` times the network factor.

## Evidence 3: the record entry reads neither `a` nor `b`

The 50 bucket_guard record calls are `call [0x64e1010]` (`R_X86_64_RELATIVE` to `0x1547530`) within 48 bytes after a getter call (census 11, 8, 1, 30). Before each one the tool finds `mov rdi,rax` (the getter's return) and `mov esi,1`. Inference: every bucket_guard sample has count 1.

The record entry copies `rdi` to `rbx` at `0x154754d`. `rbx` is not written again before the landing pads at `0x1548acb`.. (objdump, `sites.objdump.txt` covers the copy; the full FDE listing was checked by hand). The tool scans every byte offset of the FDE `0x1547530..0x1548ba3` for a ModRM operand with base `rbx`/`r11` (direct or SIB) and displacement 0x8, 0x218 or 0x238. Because it scans offsets, not decoded instructions, it can over-report but cannot miss. Result:

| Displacement | Field | Hits |
|---|---|---|
| `0x8` | `b` | 0 |
| `0x218` | `a × factor` | 0 |
| `0x238` | limit | 1, the ModRM byte of `cmp r12,[rbx+0x238]` at `0x15486ee` |

The scan does not decide `[rbx]` (`+0x0`): its byte pattern also occurs inside unrelated instructions. The objdump listing of the FDE shows no `[rbx]` operand; the tool does not prove this.

## Evidence 4: the `+0x238` compare has no visible effect

- `mov r12,[rbx+0x58]; cmp r12,0xa; jb 0x1548657` (`0x1547f47`..`0x1547f4f`). `0x1548657` stores the date at `+0x250`/`+0x258` and returns, so no window record is built when the count is below 10. (By hand from objdump: the only path from earlier code into the record-building region passes this compare. The other jumps into it go to `0x1548238`/`0x1548260`/`0x154828a`, whose block ends `jmp 0x1547be2`, or to the epilogue.)
- `cmp r12,[rbx+0x238]; jbe 0x1548712` (`0x15486ee`). When the count is above the limit: `lea rdi,[rsp+0xd8]; lea rsi,[rsp+0x60]; movsd xmm0,[0x459568]` (binary64 600.0) and `call [0x64e1018]` (`R_X86_64_RELATIVE` to `0x1570f30`).
- `0x1570f30` writes only `[rdi]` (8 bytes, `0x1571040`) and `[rdi+0x8]` (4 bytes, `0x157103a`) through `rbx = rdi` (`0x1570f37`). Its callees do not store through the incoming `rdi`: `0x15ed960` (and its callee `0x63efe40`) and `0x16290d0` have no store outside their own stack, and `0x162a9a0` writes through `rdi = rsp` of `0x1570f30` (objdump, checked by hand over their FDEs). Inference: the input time plus 600 s, or the far-future tuple `0x4679d0` on failure.
- No operand in `0x1548712..0x1548764` addresses `[rsp+0xd8..0xe3]` (tool scan of every offset). `mov [rsp+0xd8],rax` (`0x1548764`) and `movsd [rsp+0xe0],xmm0` (`0x1548771`) overwrite all 12 bytes before the record goes to the writer `0x14c3370` (`call` at `0x15489bb`).

So whether the count exceeds the limit (10 for bucket_guard, 1000 by default) changes no stored or written value in this function. Inference: a dead store left by the compiler, or a branch whose result is no longer used.

## Result

- `a` is multiplied by the network factor and stored at observer `+0x218`.
- `b` is stored at `+0x8` with `+0x0` = 1.
- The bucket_guard getters also lower the `+0x238` limit from 1000 to 10.
- In the record entry, none of the three changes anything that is stored or written: `+0x8` and `+0x218` are never read, and the only read of `+0x238` decides a call whose result is overwritten.
- Each bucket_guard sample is recorded with count 1, and a window is written only after at least 10 samples (fixed immediate, not `+0x238`).

## Limits

- Callees of the record entry receive pointers to `+0x40`, `+0x60`, `+0x70`, `+0x98`, `+0x148`, `+0x190` and `+0xe0` of the observer (objdump). From those, `+0x218` is reachable at a positive offset. The callees were not traced. Other code that walks the observer map (for example a periodic reporter) was not searched. A reader of `a`, `b` or `+0x0` may exist there.
- The meaning of `a` and `b` (threshold, sampling rate, bucket width) is not decided by this packet.
- The configuration byte `+0x48` is a runtime value; which factor applies depends on the network (RE-015).
- The control-flow statements about the record-building region and the `rbx` lifetime were checked by hand on the objdump listing. The tool pins the instructions but does not decode control flow.

## Gates

- `python3 -m unittest tests.test_bucket_guard_constants_115`: 13 tests, OK. Mutations in a copied image: constructor store offset, getter limit and tag immediates, count-gate immediate, an unpinned `[rbx+0x218]` operand, a `[rsp+0xd8]` read in the dead window, a record call with count 2, the 600.0 constant, the `0x64e1018` relocation, a removed getter call and a damaged digest.
- `make doctor`, `make verify`: pass. `make catalogue-check`: fails only on the work-item count, which this packet raises by one; the catalogue refresh is left to the maintainer, as in the earlier packets of this series.
