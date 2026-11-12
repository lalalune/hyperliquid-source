# RE-017: raw pending existing-key value provenance (#115)

## Question and scope

PR #6686 identifies a zero first-dword stop in the small-map builder, but does not establish where a pending value comes from. PR #6048 describes the separate hash-tracker twin and explicitly excludes `0x5afa3b0`; #6611 traces its upstream candidate producer and leaves its map insert opaque. This packet follows the selected existing-key replacement in that raw-tracker twin. Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`.

## Observations

`0x5afa3b0` saves its first argument as the tracker and second argument as an input object, calls `0x5373e40` and iterates its `0x68`-byte output records. For a selected record it reads the qword at record offset zero as a key, derives a pointer to the input object's `+0x60`, and calls `0x4dbe1e0` with tracker `+0x60`, that key and the derived pointer (`0x5afa3c1..0x5afa4cb`). It also conditionally updates tracker `+0x80` with the unsigned maximum of the previous value and key. #6611 covers producer-side filtering; this packet addresses the map update.

`0x4dbe1e0` saves the incoming value pointer. On a selected existing-key route, the replacement block saves the old 12-byte value to its output and copies eight bytes plus four bytes from the incoming value pointer into the located value (`0x4dbe4c6..0x4dbe4e5`). The selected tree equality branch at `0x4dbe570..0x4dbe599` also targets that replacement block. Thus, subject to correct key lookup, valid pointers and no alias interference, the first value dword on that route comes from the original input object's `+0x60`. There is no first-dword test in the shown replacement block. This supplies a provenance lead for #6686, but it does not prove the input can validly contain zero, that any zero reaches the later builder, or that a record is lost in production.

New-key insertion, full key search, input-object construction, domains and runtime behavior remain open. The selected qwords must not be assumed to be checkpoint heights solely from their offsets. No security, state-root or component-completion claim is made.

## Reproduction

Run `python3 research/work-items/RE-017-node115-raw-pending-time-replace/verify.py` to authenticate the target, check eight instruction anchors and two direct calls, and reject eight independent one-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. No captured code is executed.
