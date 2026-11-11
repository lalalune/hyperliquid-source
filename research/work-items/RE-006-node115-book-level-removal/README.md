# Book caller: flat level selection through empty-level removal

This packet advances issue #3915 by binding a real caller (`0x58e1400`) to the previously reconstructed order-unlink routine (`0x58dfbc0`). On its selected flat-map path, the caller derives the level from the order's side and price, passes that exact level pointer to unlink, and uses unlink's extra empty-level flag to remove the same key from the same side map. Issue #3915 remains open; no component or acceptance gate changes.

## Evidence and prerequisites

The source is the pinned, original node/115 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. All addresses below are ELF virtual addresses. `records.json` contains four bounded windows (1,508 bytes / 333 instructions), enclosing FDE identities, byte hashes, 102 checked facts, and 19 semantic mutation controls. No target instructions are executed or emulated.

`RE-006-node115-book-order-unlink` already establishes the slot unlink, free-list, neighbor repair, aggregate updates, event construction, and empty-level flag. `RE-006-node115-forward1-map-readback` already establishes the earlier per-user map-removal success and slot lookup; this packet does not repeat that admission claim. `RE-006-node115-sorted-set-read-side` supplies earlier map-removal context. The added evidence is the caller-level connection, including the flat representation's pointer arithmetic, the auxiliary-map result's immediate consumers, and the conditional same-key cleanup.

## Selected caller path

1. At `0x58e1544..0x58e1569`, the slot index is bounded by `book+0x90`, slots start at `book+0x88`, each slot occupies `0x110` bytes, and tag 2 is excluded. The selected slot's price is at `+0xb0`; a negative value branches out of the selected path. Its side byte is at `+0xd2`.
2. At `0x58e1583..0x58e15b9`, side 0 selects `-price` and side 1 selects `price`. The signed key is saved at `rsp+0x70`; the map owner `book+0xa8+32*side` is saved at `rsp+8`. This report assumes valid side tags 0/1 and does not assign price units.
3. The map's first word equal to signed MIN selects the tree representation. The selected non-MIN path at `0x58e19d3` calls `0x57f3ce0` with the saved key. A missing result (`AL & 1`) or returned index outside `map+0x18` leaves the level pointer null and still proceeds to unlink. This packet binds the call and branch; it does not newly prove the search helper.
4. On a flat hit, the physical index is `head+logical_index`, minus capacity once when that sum reaches capacity. Under the valid ring invariant, the level address is `buffer + 136*physical_index + 8`. The extra eight bytes skip the row's key. At `0x58e1a27..0x58e1a59`, helper `0x518e690` receives that level, a 12-byte context, a scalar context, and `book+0x80`. Its effects remain opaque.
5. At `0x58e1a63..0x58e1a8c`, the same level pointer becomes the seventh, stack-passed argument to `0x58dfbc0`. The other arguments include the output buffer, `book+0x80` slab, exact slot index, a context word, event vector, and `book+0x118` aggregate pointer. Six saved registers plus `0x418` local bytes and the return address explain the callee's `rsp+0x450` seventh-argument loads.

## Unlink return and auxiliary removal

The prior unlink copies the slot's 264-byte payload from `slot+8` to `rsp+0x48`. Therefore its saved `rsp+0x118`, `+0x11c`, `+0x120`, and `+0x130` correspond to slot `+0xd8`, `+0xdc`, `+0xe0`, and `+0xf0`.

For a non-null level, a nonzero byte at slot `+0xd8` triggers `0x4de02d0(level+0x50, key)`. The key contains the qword from slot `+0xf0` and dword from `+0xdc`. On normal return, neither helper return register controls the following quantity/count updates: `RAX` is overwritten by a load from `level+0x70`, and `RDX` is cleared. The same updates occur when the auxiliary call is skipped. Quantity is saturated at zero after subtraction of the removed slot's `+0xe0`; count at `level+0x78` is saturated at zero after decrement. This does **not** prove the helper always succeeds, rollback behavior, or arbitrary invalid-map safety.

After neighbor repair, the extra byte at output `+0x110` is false for a missing level or a nonzero head tag. With valid Option tags 0/1 and a zero head tag, it is `tail_tag XOR 1`. Thus the caller's tested bit is true precisely when both level ends are absent. The caller first rejects unlink result tag 2, copies the 272-byte removed slot, and then tests this extra byte at `0x58e1aba`.

When the bit is set, `0x58e1acc..0x58e1ad6` passes the **same saved key and map owner** to `0x4dded40`. The selected flat branch of that helper calls the same `0x57f3ce0` search, uses the same 136-byte row layout, invokes `0x5811830` for the ring move, and decrements the map's live count on a valid hit. A returned tag 2 skips cleanup; another tag is handed to `0x5946f70`. This report binds that cleanup call without claiming a newly reconstructed destructor contract.

## Reproduction and limits

Run from the repository root with the project's audited offline Python environment:

```sh
python research/work-items/RE-006-node115-book-level-removal/verify.py
make doctor verify catalogue-check reproduce
```

`verification.json` records the verifier result. Mutation controls alter the slot and side-map strides, side field/key selection, missing-result bit, ring head, level offset, seventh argument, returned-empty bit, saved cleanup key, auxiliary presence/map, aggregate destinations, tail tag, and returned flag offset. They are rejected with the whole-target digest guard deliberately bypassed for each synthetic mutation; the original artifact remains unchanged.

Assumptions are valid native structures and enum tags, nonnegative price, ordinary successful allocation/copy behavior, and normal returns from opaque helpers. Tree selection, the preparation helper's contract, full auxiliary-map removal, complete events, subsequent caller effects, wire admission/authentication, cancellation/replace semantics, append composition, unwind rollback, and end-to-end matching equivalence remain unproved. The full `make test` target is excluded because its discovery includes captured-instruction emulation; this contribution runs static verification and offline repository checks only.

Overlap was checked against current main evidence, current open PR titles/bodies, and targeted all-state historical PR searches for the caller and helper addresses/semantics. Existing lower-level packets are credited above; historical title/body search does not guarantee that every historical patch was manually inspected.
