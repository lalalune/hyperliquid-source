# Node #115: selected membership-object calls before digest refill

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows a selected caller-side loop before the four selector invocations in #6048 and relates its object to the count gate in #6747/#6748. It does not infer a protocol vote or authenticated membership.

At `0x5391eba..0x5391ec4` the selected loop retains one base pointer in `r14` and sets `r15=base+0xdb8`. In the tag-2 iterator path, `0x5391f32..0x5391f56` reads a 20-byte value and a following byte from records at stride 25; the alternate path obtains a value via `0x51e7c70`. Tag byte 2 ends the loop. For another byte with low bit 0 the code calls `0x51d8660(base+0xdb8, value)`; with low bit 1 it calls `0x51d2ae0(base+0xdb8, value)`. This packet records arguments and branch selection only, not complete insertion or removal semantics.

After iterator completion and cleanup, `0x5392006..0x5392032` calls `0x54cae80` with the same retained base and selectors 0, 1, 2, 3 in order. On selector 3 the separately documented same-owner path passes `base+0xdb8` to the producer's selected 20-byte membership-count gate. Therefore the selected calls occur before that refill on this path, assuming normal helper returns and unchanged base identity. Effects of the two helpers, mutation/aliasing, iterator validity, caller provenance and other execution paths remain open.

Static windows, direct-call checks and mutation controls are provided. Run `python3 research/work-items/RE-017-node115-digest-member-update-before-fill/verify.py` without executing the captured binary. No component gate changes.
