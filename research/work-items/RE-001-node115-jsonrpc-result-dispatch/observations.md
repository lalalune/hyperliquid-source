# Node #115 local operations and unresolved contracts

All addresses below are ELF VAs in the authenticated #115 capture. Two complete FDE ranges were statically decoded by GNU objdump 2.42 in the hosted isolated job. The exports retain 79 constructor rows and 410 caller rows, 489 total over 2,296 bytes. Linear decoding does not prove reachability of every instruction or complete exception behavior.

## Constructor range 0x1751380..0x17514d6

The entry retains the output pointer in RBX. It loads input-header words at RSI+8 and RSI+0x10, shifts the latter by six at `0x1751395` and forms an end pointer. The subsequent helper at `0x1705d50` is opaque. If its local returned tag byte equals raw `0x16`, the range copies a returned word to output+8 and writes raw `0x8000000000000001` to output+0. This is an observed tagged-store arm, not a recovered Rust error enum.

On the other arm it stages an intermediate representation at RSP and calls `0x16fdba0` at `0x175140e`, with output at RSP+0x20 and input at RSP. If the first output word differs from the sentinel, control reaches the ordinary copy. Otherwise it calls opaque helper `0x174d1d0`, then calls `0x16fdf90` at `0x1751436`, using the same intermediate storage address. Storage-address reuse does not prove that an opaque helper preserved its contents.

If the second result also equals the sentinel, another opaque helper call precedes a RIP-relative LEA at `0x175144c` to readonly VA `0x480c41`, followed by length `0x3d` and call `0x17421f0`. The exact 61 bytes are `data did not match any variant of untagged enum JsonRpcResult`. The returned word is stored at output+8 and the sentinel at output+0. This binds the diagnostic to the local alternative path; it does not establish a fully qualified type or variant field schemas.

The ordinary arm writes six 16-byte chunks to output offsets 0,16,32,48,64,80 and an eight-byte word at offset96: 104 local bytes. The sentinel arms visibly write two eight-byte words, which does not imply the entire object is 16 bytes. After local cleanup, `0x17514af` puts the retained output pointer in RAX. All callees, allocation/cleanup contracts and LSDA/exception closure remain unresolved.

## Caller range 0x1707010..0x17077b2

The entry compares state cursor+0x28 with length+0x20, reads input through pointer+0x18 and scans with mask `0x100002600` plus unsigned bound32. That local predicate admits byte values9,10,13,32. The next local comparison is with opening brace `0x7b`. State byte+0x48 guards a decrement of byte+0x49, with a zero branch afterward. The byte is depth-like by usage; this range does not establish its initial budget, and no #94 budget value is transferred.

The loop writes four vector chunks into records addressed with a shift by six, binding a local 64-byte append stride. Helper contracts, keys and full input schemas are unknown. The colon arm at `0x17072b0` compares against raw `0x3a`, stores an advanced cursor and calls opaque `0x17061f0`; no exact value decoder or field name is assigned.

The direct call at `0x17074ee` is a native instruction boundary and resolves to constructor entry `0x1751380`. The caller reads the returned first two words and compares the first with its sentinel. Its ordinary arm stages a 104-byte representation; the sentinel arm stages the corresponding tagged result for shared cleanup. A separate helper `0x1700a10`, called at `0x17073f9`, has a raw result tested later. Only when the local staged result is non-sentinel and that helper's raw result is zero does this path reach the final 104-byte output stores. A non-sentinel constructor result alone therefore does not prove complete-input acceptance.

The original job did not decode helper `0x1700a10`. The independent #115 follow-up below establishes its local closing-brace path; a whole-input trailing-data rule and error enum remain unproved. Other opaque calls, indirect slots, all callers and exception paths remain open. This is independently collected #115 local evidence, not a whole parser or code-equivalence claim.

## Completion helper range 0x1700a10..0x1700ac3

The follow-up native job independently authenticates the complete #115 capture and decodes the actual 179-byte FDE (47 rows). It renews all 410 caller rows without a difference and qualifies the direct call at `0x17073f9`; `0x17073f6` passes the caller's retained state in RDI. This adds one unique function to the original two, for 2,475 retained bytes / 536 rows. The renewed caller is not counted twice.

The helper loads length from state+0x20 and cursor from state+0x28. A cursor at or above length branches to raw stack tag3 and opaque error helper `0x16ffc80`. Otherwise RAX becomes a one-past candidate position. Input bytes are loaded from state+0x18 through `[data+rax-1]`. The unsigned bound44 plus mask `0x100002600` admits exactly9,10,13,32; the code consumes those whitespace bytes by storing the advanced cursor and loops while more input remains. The end-after-whitespace path also selects raw tag3. The verifier enumerates all256 byte values for this local mask predicate, not runtime parser cases.

A comma byte (`0x2c`) selects raw stack tag21 before the same opaque error helper. The local closing-brace comparison at `0x1700a8b` uses `0x7d`. On equality, with nonzero one-past cursor, `0x1700a96` stores that cursor, then `0x1700a9a` clears EAX and the function returns. An explicit zero-cursor branch reaches an indirect call through RIP-relative slot `0x64df520` after loading address `0x640c070`; its type/meaning is not assigned. Other non-whitespace bytes select raw tag22 and call `0x16ffc80`. Its behavior and returned error values remain opaque; raw stack tags are not a recovered source enum.

The ordinary closing-brace path contains no post-consumption load or cursor-equals-length check. It therefore establishes local delimiter consumption and a zero result, not acceptance of trailing data by the whole parser. The caller tests this raw result after its staged-value sentinel check, before the 104-byte final stores. Variant field schemas, outer callers, the error helper, indirect slot and exception behavior remain unresolved. No #94 semantics, initial depth budget or acceptance credit was transferred.
