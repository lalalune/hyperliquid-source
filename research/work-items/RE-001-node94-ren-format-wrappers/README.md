# RE-001: two ren-linked format-wrapper argument layouts and tagged cleanup

- Component ID: foundation.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference commit: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Claim status: instruction/data/relocation observations, bounded layout inference; Rust names, types, exact formatting and reachability unresolved.
- Question: how do these two source-linked nonreturning wrappers construct different callback argument layouts, and how does their exceptional cleanup select a tagged payload path?
- Included: two actual FDE-described extents, 551 bytes, descriptors, source Location records, callback addresses, call-slot relocations, local tag/drop/unwind branch and two observed caller instructions. Excluded: wider ren family, whole-text caller census, helper implementations, exception-table semantics, runtime behavior, target execution and reconstruction.

## Reproduce

Run from repository root on Linux x86-64 with materialized authenticated pinned inputs, Python 3.12.3, GNU readelf/objdump 2.42. Git 2.43.0, git-lfs 3.4.1 and ripgrep 14.1.0 were available for repository checks. Local tool prefixes were added only to the child process PATH; no installation/global environment change. Platform: WSL2 Linux 5.15.146.1-microsoft-standard-WSL2 x86_64. Ghidra, Java, LLVM objdump and the optional Rust toolchains were unavailable; GNU static analysis was used.

```sh
python3 tools/ren_format_static.py --output work/ren-a
python3 tools/ren_format_static.py --output work/ren-b
diff -r work/ren-a work/ren-b
python3 -m unittest discover -s tests -p test_ren_format_static.py -v
make doctor
make verify test catalogue-check
make reproduce
```

The collector calls the repository artifact identity check before any analysis. It parses file-backed ELF sections and RELA entries independently, reads full `readelf -wf` output, requires each selected extent exactly once, then exports complete selected FDE records and bounded `objdump -d` output. Addresses below are original ELF VAs, not rebased analysis addresses. GNU objdump nearest-symbol annotations are retained verbatim as raw tool output; distant C++ symbol names do not identify these Rust-associated bodies. `records.json` retains exact body hex, file offsets, full body hashes, raw Location/descriptor data and relocations. `SHA256SUMS` authenticates the durable exported files. No operand masks or normalization are used. Two complete producer invocations gave byte-identical four-file exports; the earlier exploratory export was superseded after expanding evidence fields.

## Evidence

| FDE extent (end exclusive) | File offset | Bytes | Location VA; line:column | Callback address(es) |
| --- | --- | ---: | --- | --- |
| `0x13cea50..0x13ceb5b` | `0x13cda50` | 267 | `0x5666d90`; 206:21 | `0x13d94b0` |
| `0x13ceb60..0x13cec7c` | `0x13cdb60` | 284 | `0x5666da8`; 259:21 | `0x13e28a0`, `0x13e27c0` |

Both Location records have a zero pointer field in file data, length 44, and an `R_X86_64_RELATIVE` relocation to path VA `0x1f8849`, whose bytes are the embedded `base/src/ren.rs` path. This establishes diagnostic attribution for the two LEAs, not source function identity. No reference source implementation was copied or used as an authority.

The first wrapper saves RSI at stack offset 0, and places the RDI operand and callback address in the stack pair at offsets 8/16. It then points a formatting record at the saved RSI and reads another callback address through slot `0x576ea70`. The second saves RDX at offset 0, places RDI/callback at offsets 8/16 and RSI/callback at offsets 24/32, then points its final pair at saved RDX and the same slot. Thus the inline argument list has one versus two constant callback pairs plus a shared slot-backed final pair. The collector's `callback_pairs` counts only the constant pairs, not all pairs.

Descriptor bytes are `c0023a20c000` at `0x1dd419` and `c0022c20c0023a20c000` at `0x1f4d9e`. They visibly differ in embedded comma/space and colon/space bytes; their complete compact-format semantics are unresolved. Both wrappers load the descriptor into RDI, Location into RDX, and argument-list stack address into RSI before calling through `0x576e098` (relative relocation addend `0x157b810`). A `ud2` immediately follows each call (`0x13cea9d`, `0x13cebbe`). This is static evidence for nonreturning normal fallthrough, not proof that the call cannot return under every condition.

Exceptional landing pads preserve the exception pointer from RAX in R14, load the saved operand into RAX, copy EAX into ECX, mask ECX with 3 and compare to 1. The `je` enters the payload path only for low bits equal to 1; otherwise R14 is passed to `_Unwind_Resume@plt` at `0x5660110`. In the payload path, RBX becomes RAX-1, R15 is loaded from RAX-1 and R12 from RAX+7. The first qword at R12 is tested for zero, then called indirectly with R15 if nonzero. Subsequent conditional size/alignment processing and slot-based deallocation calls are retained in raw disassembly, as are secondary cleanup landings; their high-level ownership types and unwinding rules are unresolved. Only this local tag branch and dynamic-drop prefix are semantically asserted by the collector.

The raw relocation table records all seven selected slots, including `0x576e010 -> 0x54c8cb0`, `0x576ea70 -> 0x4f0d950`, `0x576ea78 -> 0x14bf1b0`, and `0x576e128 -> 0x157b63b`. These resolve selected indirections; they do not establish callee semantics or closure. The register-indirect drop target remains dynamic. Constant callbacks are addresses only: their bodies, exact ABIs and source types have not been established here.

Observed direct callers at `0x13ce25b` and `0x13ce96a` target the first and second wrapper respectively, both inside FDE `0x13cdfc0..0x13cea45`. Small raw caller excerpts are retained. These are two selected observations, not a complete inbound-xref count.

## Implementation and comparison

New Python tooling and documentation were independently authored from ELF bytes and GNU tool output. Rust implementation, Cargo.lock/compiler/linker flags, two Rust builds, target behavioral fixtures, raw/normalized reconstructed comparisons and helper/data/relocation closure are not yet implemented/measured. There is no captured-node or emulator execution. No live node, chain, signing, keys, paid datasets or external operational effects were used.

The 23 focused tests use the authentic local binary and call the semantic validator below the top-level digest gate. Controls independently corrupt the path, line, Location LEA, descriptor, each callback family, shared formatting call displacement, trap, cleanup tag mask/comparison, payload layout, unwind displacement, both caller targets, an argument-pair stack store, the shared callback-slot load and a relocation addend. Missing/duplicate/wrong FDE extents, unbacked VA and malformed RELA extent are also rejected. These are target-grounded static corruption controls, not tests of reconstructed runtime behavior. No whole-function hash is the only negative control.

## Results and limitations

`records.json` reports 2 selected windows / 2 expected FDE extents, 551 bytes; the total parsed FDE record count is metadata, not a function census or reconstruction denominator. Raw-equal reconstructed bodies, normalized-only reconstructed bodies and unmatched reconstructed bodies: not measured. No component gates or progress/catalogue records change.

See `validation.txt` and sanitized check logs for actual verification results. `initial-failures.txt` preserves the setup and first-validator errors without personal home paths. The local materialized LFS inputs initially appeared modified in worktree status; their authenticated bytes were preserved and excluded from staged changes. The reference LFS index was refreshed locally without changing its pinned commit. Passing static tooling checks establishes neither reconstructed Rust nor whole-node equivalence.

Next question: independently map the callback targets and shared formatting helper to establish compact-descriptor and argument ABI semantics before attempting a Rust implementation.

New code/docs MIT; original binary evidence and imported materials retain upstream rights.

Made via @slopdotcash

AI tool: OpenAI / sol (operator-reported menu label; exact backend not exposed), via Codex desktop.
