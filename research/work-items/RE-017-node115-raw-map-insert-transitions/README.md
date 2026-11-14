# RE-017: raw pending-map insertion transition thresholds (#115)

## Question and scope

PR #6685 records a `<32` post-traversal transition, while #6693 traces raw pending updates but leaves insertion representation choices open. What thresholds are tested by the insert helper? Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; ELF virtual addresses; main reference `a8616af9432b8d8517b2af677880e117b7c28ef3`. Insert FDE `[0x4dbe1e0,0x4dbe6ad)`.

## Observations

The raw tracker producer calls `0x4dbe1e0` with map `tracker+0x60` (#6693). At helper entry, `0x4dbe209..0x4dbe225` combines two tests: the first qword has the sentinel bit pattern `0x8000000000000000` and unsigned map `+0x18` is below 32. Only when both hold does the selected code clear map fields, construct an iterator descriptor and call `0x5b86860` (`0x4dbe22b..0x4dbe2b0`). This is an insertion-time transition distinct from #6685's post-traversal check; builder limits and stop conditions are in #6686.

For the selected non-sentinel path, the helper calls `0x57f95d0`. When its returned qword is nonzero **and** map `+0x18` is at least 64, it moves out the four-qword map descriptor, initializes the map fields to `(0,8,0,0)`, and calls `0x515d620` on the saved descriptor (`0x4dbe36e..0x4dbe3d1`). A zero lookup status or a count below 64 bypasses this selected call. In a selected equality comparison, `0x57f9659..0x57f9667` returns zero for equality and one for inequality; a complete proof of every search path is outside this packet.

Together these are static evidence of different `<32` and `>=64` thresholds on specific operations, suggesting representation hysteresis. The builder's full output, successful allocation, stable ordering, all lookup cases, concurrency, zero-valued records and actual runtime reachability are not established. Valid pointers and normal calls are assumptions. No checkpoint, state-root, equivalence or completion claim is made.

## Reproduction

Run `python3 research/work-items/RE-017-node115-raw-map-insert-transitions/verify.py` to authenticate the target, check six anchors and four direct calls, and reject six independent single-byte mutations. `windows.txt` uses Apple LLVM objdump 21.0.0 `-d --x86-asm-syntax=intel`; Python 3.11.15 was used. No captured code is executed.
