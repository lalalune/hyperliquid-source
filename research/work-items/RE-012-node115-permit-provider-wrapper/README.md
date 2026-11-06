# RE-012: node115 permit-provider wrapper and conditional instrumentation

## Current repository validation

The user explicitly authorized the disclosed isolated offline evaluator tests. The original repository `make test` command exercised **583 modules**, 5409 reported unittest cases, 899 pytest passes and 9 recorded built-in skips. Script modules may not report an assertion count; no count is invented. Optional compiler/version skips are listed in `repository-tests.json`, not presented as compiler-comparison passes.

The original full command's exit code was 2: one pure-static catalogue fixture hit macOS sandbox hardlink policy. Its unmodified13-test module then passed with a stronger TMPDIR process-exec deny; network and artifact execution restrictions were not relaxed. Original failures/logs remain preserved, and all583 final module results are successful.

 The full suite actually ran on PR2829 head `196bb08453803749319890a91ee2e640cc772283`. All eight PRs have byte-identical tools/tests/src/provenance/artifacts/build-rule trees and differ only in their independent evidence packet plus generated inventory. Shared results are combined with fresh per-packet controls/native regeneration and per-head doctor/verify/catalogue-check/reproduce. This follow-up changes only this README, the test receipt and its manifest; it does not alter target evidence or testing logic.

Execution used an OS network-denying sandbox, isolated HOME/TMPDIR, no inherited auth/proxy state, explicit `HL_ALLOW_CAPTURED_INSTRUCTION_EVAL=1`, offline Cargo and disabled automatic toolchain installation. Captured native binaries, real services, signing and private runtime data were not used. Raw logs and checksums are preserved in the operator findings; this compact receipt pins their identities. The earlier static collection metadata remains historical rather than rewritten. Repository test success does not recover opaque helpers, prove target equivalence or advance any reconstruction/component gate. Hosted CI success is not claimed.

Task/component: RE-012 / node-runtime, one missing provider boundary from the retained IP-permit state packet. Target node115: 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `05bc2de303c05525b71e7e257426e741bc66a390`. No imported source implementation is used. New analysis/code is MIT; captured bytes retain upstream rights.

Before this packet, `RE-001-node115-ip-permit-state` named `0x4774c50` as an opaque provider. The newly recorded owner is a conditional-instrumentation wrapper around a different callee, `0x47849c0`, and forwards a 16-byte local result. This resolves that local ownership boundary without attributing per-IP storage or admission semantics to the wrapper.

## Scope and evidence

Complete FDE `[0x4774c50,0x4774eab)` is **603 bytes / 131 contiguous native instruction rows**. `evidence.json` contains full original bytes, section-resolved file offsets, raw FDE/CIE, direct edges, all native RIP references and six selected unique RELATIVE writers. `0x4774c50.objdump.txt` is the complete LLVM decode; GNU readelf independently confirms the same PC range in `0x4774c50.frames.txt`. An FDE is an unwind-described range, not proof of source function identity, all incoming edges or exception closure.

This is partial static research. Caller state gating is existing context and not new coverage. The underlying provider, formatting/context helpers, cleanup internals, concrete key/source types and concurrency behavior remain outside scope. No reconstruction/component gate changes.

## Conditional instrumentation

Let out be incoming RDI, object be RSI, context be RDX, flag be low8(RCX), and metadata be incoming R8, under ordinary x86-64 ABI and valid memory assumptions. The owner saves out in RBX and context in R14.

If `object[0x20] == 0`, execution skips the instrumentation prefix. Otherwise it copies metadata's two qwords and following dword, then calls `0x476a390` with a static object `0x64965f8`, a pointer to saved object, and the copied metadata. Its returned RAX is saved at RSP+0x28; the concrete guard/type contract is unknown.

A nonzero entry flag skips the additional diagnostic path. A zero flag tests a qword at **FS:-0x488**; zero also skips it. This is a raw TLS-relative offset, not a recovered TLS index, registered key or current runtime value. When both conditions admit the path, `0x476a290` prepares temporary stack storage; `0x5c842e0` receives numeric argument1; slot `0x64e0a90 -> 0x1563d10` receives that result and a metadata copy. Only returned RAX equal1 enters the formatter preparation.

That preparation binds a raw 59-byte slice at `0x7e15c1`, selected descriptor prefix at `0x432670`, callback addresses `0x4769f70`, `0x476a0f0`, `0x476a170`, and relocated slot `0x64e0a98 -> 0x1689420` before calling `0x64df4b8 -> 0x5c9b900`. The original bytes are retained; the 59-byte slice crosses adjacent-looking textual material, so it is not renamed a source error message or proof of a complete log line. Formatting effects, output sinks and errors remain opaque.

After the diagnostic attempt, a temporary qword is tested. If nonzero, its paired pointer and the product `word*0x38` (u64 machine arithmetic) are passed with RDX=0 through `0x64df4a0 -> 0x635de30`. This is a cleanup-like argument handoff; the multiplication is not asserted nonoverflowing for arbitrary raw state, and the callee is not executed or proved to free memory.

## Common provider and result forwarding

Both ordinary paths prepare the same underlying call. From incoming context C:

```text
base = qword[C+0]
word = qword[C+8]
triple_pointer = qword[C+16]
local_triple = 24 bytes read through triple_pointer
call 0x47849c0(out=RSP+0x48, base+0x70, base, word, &local_triple, 1)
```

The listed order corresponds to RDI, RSI, RDX, RCX, R8, R9. `base+0x70` is observed pointer arithmetic, not a proven map/semaphore member type. After that call, the owner loads exactly16 bytes at RSP+0x48 and stores them to the saved out address. The instrumentation-enabled route subsequently calls `0x4787f20` with the saved guard storage at RSP+0x28; the disabled route bypasses this cleanup. Both normal routes return RAX=out. Neither the underlying call's scalar return nor output tag/error meaning is invented.

These statements are conditional on the opaque calls returning normally with the expected ABI and without unclosed aliases invalidating saved storage. They establish explicit local copying and argument construction, not identical runtime outcomes across instrumentation states. The retained tail includes cleanup and `_Unwind_Resume` calls; LSDA actions, exceptional reachability and helper nonreturn contracts are not reconstructed.

## Reproduce, controls and repository validation

From repository root with installed Python3.11, LLVM objdump and GNU readelf, use a new output directory:

```sh
python3.11 -B research/work-items/RE-012-node115-permit-provider-wrapper/collect.py \
  --output work/permit-provider-fresh --objdump "$OBJDUMP" --readelf "$READELF"
```

Observed macOS arm64, Python3.11.15, Apple LLVM21.0.0 and GNU readelf2.45. Exact banners are in `validation.json`. The collector authenticates the complete target before output/native calls and gives native tools a private byte-identical snapshot. It verifies every decoded byte and continuous owner coverage. Only path labels and surplus terminal newlines are normalized; raw instructions/data are unchanged. Two final captures reproduced all four outputs byte-for-byte.

**27 real below-identity controls** ran: 17 instruction pins, three selected-data locks, one FDE-extent check and six parsed relocation-binding locks. The relocation mutations invoke the same actual parsed binding checker used on the original; these remain static binding controls, not helper-semantic proofs. The first exploratory collector used a weaker relocation inequality check; it was replaced before the two retained final collections. No arbitrary-byte completeness claim is made. Public identity rejection and independent cross-review are recorded in the operator findings.

The packet producer uses no target instruction evaluator, captured execution, native provider/allocator call or network/chain action. No independent Rust reconstruction, byte-equivalence or full-node claim is made. Next: recover `0x47849c0` and a caller's raw output consumption before assigning a provider state/result type or admission behavior.
