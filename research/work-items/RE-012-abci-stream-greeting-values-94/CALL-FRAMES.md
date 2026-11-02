# Calls, escaped pointers and excluded paths

All179 call sites in30 complete bodies are bound in scope.json and records.json.
This includes calls on excluded diagnostic, unwind and instrumentation paths;
the census is not179 independently closed callees. Every direct rel32 and RIP
disp32 is checked against raw bytes and unique file-backed ELF mapping. RELATIVE
bindings require symbol index0; imported memcpy/memmove/memcmp require their
actual dynsym names and GLOB_DAT/addend0 bindings. All80,300 captured RELAs are
checked for8-byte width classes1/6/7/8/18 and nonoverlap with admitted code/data.
Nothing here executes a dynamic loader or import implementation.

All calls to the28 core FDE entries are handled by PROOF.md/TREE-PROOF.md. The
following remaining ordinary calls have explicit external premises:

| Binding | Ordinary use and required effect |
| --- | --- |
| 576dfd8→54c06b0 | Fresh aligned leaf0x400, internal0x460 or aggregate0x1830 allocation. Preserve all previously live Reader/input/output/tree/stack memory. Return nonnull storage of the requested size. |
| 576e298→54c0780 | Fresh byte-vector allocation of the admitted positive N, with the same successful/frame conditions. |
| 576e010→54c8cb0 | Deallocate exactly the passed live owned allocation; ordinary return and preservation of all unrelated live memory. Native size/alignment arguments remain bound; no Rust allocator ABI equivalence. |
| 576dfe0→memcpy | Exact requested-byte copy between valid disjoint ranges; preserve everything else. Count0 expressly permits the bulk vector's destination sentinel1 and empty source span without dereference. Includes Reader-record stack and heap copies, even after pointers escaped. |
| 576e0e0→memmove | Exact requested-byte copy allowing overlap; preserve outside destination. Required for paired key/value/child suffix moves. |
| 576e488→memcmp | No buffer mutation; zero iff equal, otherwise sign of the first differing unsigned byte. Required for strict key order and equal-key replacement. |

Seventeen calls use loaded callee-saved RBX/R12/R15. The validator proves the
bound import/free slot load dominates each call on the complete in-FDE CFG,
that the call is entry-reachable, and that no other register/alias write lies
on a load-to-call path without reloading that same slot. Each intervening
ordinary call must preserve the SysV callee-saved register. The algorithm
does not equate an opaque memory frame with register preservation; both are
required. Calls remain CFG fallthroughs, so no guessed noreturn label hides
a bypass. Prefixed non-NOP instructions are rejected rather than silently
treated as padding or unrecognized control transfer.

The byte-function pointer466bbb0 passed by467486c is never used by4589a30's
complete body. It is retained as context only, not charged once per byte.
No normal core path calls a logger, lock, cryptographic verifier or user
callback. Allocation/deallocation implementations may have internal effects;
their successful/frame behavior is assumed, not derived from names.

The following bound targets appear only on branches excluded by the proved
validity/success premises:1345e2a allocation failure;1346068 byte-vector allocation
refusal;157a6f0/157b7f0/157a9f0 structural/status diagnostics;157b520 refund or
caller consumption underflow;157b63b cleanup/unwind failure handling. They are
not assumed noreturn. Instead valid node counts/indices, reservation invariants,
closed status partitions and successful allocation keep the original execution
off those branches. Inert diagnostic literal pointers remain recorded in the
full reference census; their displayed text is not needed for this theorem.

Nine FDEs have LSDA. The retained parser admits the exact raw FDE/CIE and bounded
LSDA byte interval, call-site ranges, action chain and personality relocation.
The next LSDA address is an extraction upper bound, not an asserted object size.
Outer4674820 protects nested call46748c3 and lands at4674b27 to free the vector.
Map496ec70/496f370 land at496f00b/496f70b and call4900220; map496f030 lands at
496f353 and calls49b5c50. Product49784e0 protects second-map call4978597 and
lands at49787d3, calling4908500 to clean its first map. Shared insertion and
the two traversals also retain diagnostic cleanup ranges. These landing-pad
facts corroborate owner separation; they do not establish a whole unwind
runtime theorem. `_Unwind_Resume`5660110 and personality behavior are excluded.

Full caller471b880 is context. Its EDX=0 branch bypasses4381410,4eeb8c0,
4edda70,4f72510,4f6fe90,4b1d6b0,4f74b70 and all TLS/instrumentation handling.
Only greeting471b967 lies on the selected ordinary branch. Full bytes and calls
remain admitted so that the selection is reviewable; no broader caller API or
instrumented-path equivalence is claimed.

Stack pushes/pops, call return-address writes, local stack probes, and explicitly
initialized locals require a valid disjoint stack with sufficient space. The
proof does not use a first-operand write scan to infer absence of implicit
effects. Temporary byte copies may include inactive union/padding bytes; only
the explicitly active value/error projection is interpreted.
