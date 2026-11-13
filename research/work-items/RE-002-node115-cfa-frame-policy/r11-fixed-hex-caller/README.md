# RE-002: direct caller of the selected node #115 R11-CFA interval

- Component ID: foundation, as a bounded provenance/function-map allocation. Source ownership is not assigned.
- Target: Linux x86-64 node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository base: `a8616af9432b8d8517b2af677880e117b7c28ef3`.
- Claim status: static observations. The original source/type owner remains unresolved.
- Question: which direct E8 sites reach the CFA packet's selected interval `0x298af40..0x298b04d`, and which input-stride instructions surround those calls?
- Included: two native-qualified direct edges and the complete 372-byte caller interval. Excluded: source/type attribution, independent source-level function boundaries, delimiter values, runtime behavior and arbitrary indirect incoming references.

## Reproduce

The original collection is [hosted run 42886723454](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/42886723454), control commit `c8a4700c83f811e6f7fe1074f796345a245b93d2`, tree `a91897eda42769b0132aba75e56a80a43b516698`. The job completed in 14 seconds in one attempt. There was no compiler/package installation, repository-code execution or captured-code execution.

The immutable collection sources are retained as text in `producer/`, with original paths, links and SHA-256 values in `evidence.json`. The workflow, bootstrap and isolation sources specify acquisition and the rootless Linux environment. `receipts/prepared.json` records the input URL and exact capture identity. `receipts/commands.json` retains every actual native command, working input path, output length, exit code and hash; `receipts/versions.json` retains the actual GNU, LLVM and Python versions. These are original receipts, including their ephemeral Linux paths, not claims of a fresh local reproduction.

Acquisition authenticated the full capture before making it readonly and nonexecutable. Analysis ran as uid/gid 65534 with no groups, zero capability sets and no-new-privileges, in a separate network namespace containing only loopback. Frozen inputs were readonly and the working mount nonexecutable. `receipts/qualification.json` records the observed environment.

The selected interval and each caller interval were exported with both GNU `objdump -d -z --insn-width=16` and LLVM `llvm-objdump -d --disassemble-zeroes`, with explicit start/stop virtual addresses. GNU readelf and LLVM dwarfdump independently exported the FDE headers. Their complete working outputs were compared by the producer and retained by hash and size in `receipts/commands.json`; the approximately 310 MB of full FDE working text is not committed here. The packet includes both complete caller disassemblies and both complete selected-callee disassemblies.

To replay the bounded result from an authenticated local copy, use the following from the repository root with GNU and LLVM objdump available. The replay uses the repository's ELF and frame readers, matches both fresh native byte partitions to the retained rows, and writes the selected FDE/CIE records, body identities and control results under the output directory.

```sh
python3 -I -B research/work-items/RE-002-node115-cfa-frame-policy/r11-fixed-hex-caller/reproduce.py \
  --binary artifacts/node/115/hl-node --out work/r11-caller-replay
```

## Evidence

Coordinates are linked ELF virtual addresses before load bias. File offsets were not retained for the new caller and are not inferred from an assumed address bias. FDE-described extents are interval evidence, not proof of independent source-level function boundaries. The stripped binary's nearest-symbol labels in disassembler output are not ownership labels.

| Role | Interval | Bytes / native instructions | Body SHA-256 |
| --- | --- | ---: | --- |
| Caller | `0x250ecd0..0x250ee44` | 372 / 100 | `2932c0a51fa7c21e24c078a45e3b2638807d30a254546ddec98710500be7d3a6` |
| Selected R11-CFA interval | `0x298af40..0x298b04d` | 269 / 70 | `9573b1ff5c818a9efc8f841b1b4d5c5627cc4f5c1b966de2220341b358e2d84c` |

The executable-section E8 scan yields two candidates whose signed relative operands resolve to entry `0x298af40`. Both are actual instruction starts in the complete GNU and LLVM partitions. Both lie in the same caller interval:

| Call site | Original bytes | Independent address calculation |
| --- | --- | --- |
| `0x250ed83` | `e8b8c14700` | next instruction VA plus signed rel32 = `0x298af40` |
| `0x250edd0` | `e86bc14700` | next instruction VA plus signed rel32 = `0x298af40` |

`evidence.json` separates ten pinned observations from the limited inference. The main context is:

| Classification | Fact or interpretation | Supporting sites / limit |
| --- | --- | --- |
| Observation | Load r14 from rcx+8 and r13 from rcx+0x10 | `0x250ecf4`, `0x250ecf8`; no source-level field labels |
| Observation | Test r13 before the first call; the zero branch bypasses it | `0x250ed78..0x250ed7b` |
| Observation | At both calls, rdi is r14 and rsi is rbx | setup immediately before `0x250ed83` and `0x250edd0` |
| Observation | On the path where rax is zero after the first call, shift r13 left by 17, advance r14 by 0x20000 and subtract 0x20000 from r13 | `0x250ed88..0x250ed98`; no source-level success meaning assigned |
| Observation | The repeated path advances r14 and subtracts the same stride from r13 | `0x250edd5`, `0x250eddc` |
| Inference | This is consistent with repeated processing at a fixed 128 KiB stride under suitable validity/non-overflow premises | It does not recover a container, element type, field name or runtime length contract |
| Unknown | Original source/type owner, data referenced at 0x5f1452/54/55/56, arbitrary register-computed callers and runtime behavior | Not established by this collection |

The producer found no `R_X86_64_RELATIVE` addend exactly equal to entry `0x298af40`. Its selected RIP MOV/LEA/FF scans did not add another qualified reference. Those scans are explicitly limited to the entry, selected pointer slots and aligned potential table bases, with at most one REX prefix. They do not establish that no indirect or interior-entry caller exists. The caller uses `0x25bf160` and `0x22f2f70`; this packet does not rename those helpers or re-claim the prior formatting-adapter work.

## Implementation and comparison

No Rust implementation, compiler/source build, independent source-body match or normalized comparison is supplied. The 641 bytes in the two raw intervals are disassembly evidence, not newly reconstructed or compared implementation bytes. No byte-window registration or component gate is requested.

The hosted producer rejects a truncated capture, a changed full capture and a changed selected-body hash. Those three actual input/body controls are preserved in `receipts/controls.json`. The replay also checks rejection of altered call destinations at both sites, an increment and decrement, the shift count, an incomplete native partition, a changed FDE extent and a changed body digest. These eight checks operate on in-memory copies of parsed evidence. Both validation runs reproduced the two call edges and the stride, and rejected all eight controls for the expected reasons.

## Results and limitations

The explicit direct-call denominator is two E8-target candidates: two of two pass complete GNU/LLVM instruction-boundary and byte checks. One complete caller interval was exported. Both native producers agreed on all 135,313 FDE headers. The hosted audit and artifact index are retained separately from the producer's own result. The source-level owner and the build-wide Rust frame-pointer setting remain unknown.

The lower-hex operation and scalar arm are existing work from [PR #2650](https://github.com/lalalune/hyperliquid-source/pull/2650). [PR #3646](https://github.com/lalalune/hyperliquid-source/pull/3646) retains the formatting adapter. The separate open [PR #6031](https://github.com/lalalune/hyperliquid-source/pull/6031) targets encoder `0x2eabb50` through slot `0x64e4d08`; that path is excluded. The new candidate contribution is the qualified incoming edges and their observed stride context. Current indexed caller/callsite and public PR/issue searches found no matches, with index and active-branch limits preserved in the private review record.

The validation candidate at `cac3e221a3820a2a2fc7c620d2979ca3d40c16ae` completed all 1,397 test modules across the [serial run](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/42934523733) and [continuation](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/43048885814). The serial run reached its cap after 1,234 completed modules. The continuation completed the remaining 163 using the same test runner. Together the receipts report zero failed modules and 30 skipped tests. The continuation also passed the post-test verify and catalogue checks. The replay code, original receipts and test files are identical in this validation note update.

Next question: can the caller's source/type owner be established from qualified caller/data context without assuming that a large stack buffer or a familiar encoding pattern names its owner? Keep the current direct-edge/stride claim separate from any later source attribution or behavior claim.
