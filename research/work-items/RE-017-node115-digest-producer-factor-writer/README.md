# Node #115: selected digest-producer factor writer

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The selector in open #6048 reaches the selected producer; open #6046 explicitly leaves `0x54cf1b0` outside scope. This packet ties its selected write to the factor observed in #6747/#6748.

The `0x54cf1b0` dispatch table at `0x926b0c` has relative entry 3 targeting `0x54cf213`. On the normal successful allocation branch, the case constructs a one-element pointer array containing `owner+0x3e88`. The shared loop at `0x54cf250` stores the incoming `xmm0` binary64 bits at that pointer and incoming `xmm1` bits at pointer+8. It then frees the temporary pointer array and calls `0x54cae80` with the same owner and selector byte 3. That selector's case 3 passes `owner+0x3e50` into `0x5afa3b0`, which passes it to `0x5373e40`; the latter reads its input `+0x38`, i.e. `owner+0x3e88`, as the membership-count factor.

This is a same-call conditional write-before-read relation for selector 3, assuming successful allocation, normal return, unchanged owner identity, and no intervening hidden mutation. The next stored binary64 at `owner+0x3e90` is observed but its meaning is not established here. The inputs' origin, valid ranges, caller selection and complete runtime behavior remain open; no policy, authentication or node-completion claim follows from these stores.

Run `python3 research/work-items/RE-017-node115-digest-producer-factor-writer/verify.py` for target digest, table entry, instruction anchors, direct-call and mutation controls. Static disassembly in `windows.txt`; no target execution.
