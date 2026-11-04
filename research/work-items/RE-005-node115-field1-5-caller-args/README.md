# RE-005 node115 field1-5 varint reader caller arguments

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/field1_5_caller_args_static.py`;
retained exports sit beside this file and are hash-bound by
`MANIFEST.sha256`.

## Question

The field1-5 varint reader packet (#2422) closed with an open
question: which mode and limit values do the reader's six direct
call sites pass, and does any caller pair this reader with another
scalar-reader family on the same buffer, which would make the
error-field difference observable as two different error results
for one input? This packet traces the six sites.

## Result

The six sites live in four caller functions — two twin pairs —
and at **every site the reader-state argument is the caller
function's own entry state argument**, forwarded unchanged (the
entry register `rsi` on the first call of a pair, its callee-saved
copy in `r14` afterwards). **No traced function writes the mode
field (`state +0x0`) or the limit field (`state +0x8`)** — the
complete state-field access inventory is in `records.json` — so
the mode and limit each read is charged against are established
upstream of these functions and only read here.

- **The twins** `0x26e5710..0x26e58d8` and `0x5aaa460..0x5aaa628`
  (456 bytes each) are byte-identical except the four disp32
  fields of their two calls and two string references. Each first
  calls the **u32 reader** (#2412) with the shared result buffer
  `rsp+0x18`; only when that value is zero does it continue:
  an inline four-byte read from the cursor, an inline mode-1
  charge of **1**, one flag byte (must be `<= 1`), and finally the
  **field1-5 reader** call — all on the *same* state pointer and
  the same result buffer. One input stream through one state can
  therefore yield a field1 **2** error from the first read and a
  field1 **5** error from the second.
- **The bulk pair** `0x2cd9710..0x2cd9844` (308 bytes) and
  `0x5968840..0x5968980` (320 bytes) share one output contract:
  two field1-5 reads (values land at output `+0x808`/`+0x810`),
  then one fixed **0x800-byte record** read; wrapper tag 0 on
  success, 1 on failure. `bulk_a` performs the record read
  **inline** (header fields copied from the cursor, the remaining
  `0x7e9` bytes through `memcpy`); `bulk_b` delegates it to the
  shared charge helper `0x58214b0..0x582153d` and stages the
  helper's 0x800-byte payload through four `memcpy` copies.
- **Charges.** Three more charge sites, all with the readers'
  store-before-compare discipline and the same success bound
  (new charged count `<=` limit): the twin inline charge of **1**
  (overflow iff charged `== u64::MAX`; refusal iff the *old*
  charged count `>=` limit) and the 0x800 charges of `bulk_a`
  inline and of the helper (overflow iff charged
  `> u64::MAX - 0x800`; refusal iff the *new* count `>` limit).
  One asymmetry: the twin's four-byte read is **committed** to
  the state (cursor `+4`, remaining `-4` stored) *before* its
  charge is evaluated, so a charge refusal still leaves the
  state advanced by four bytes; the flag byte after it is
  charge-gated. The bulk record reads charge before consuming.
- **Upstream.** `bulk_a` is called from exactly one function
  (`0x2ce1dc0..0x2ce2a32`, 3 sites), which first reads a u32
  discriminant on the same state at `0x2ce1e0c` and passes its
  own entry state on. `bulk_b` is called from exactly one
  function (`0x4e05c10..0x4e05dd8`, 3 sites), which repeats the
  call on its own entry state until a result with first dword 1
  arrives. The twins have **zero** direct call sites and zero
  `.rela.dyn` addend references; each is referenced by exactly
  one rip-relative `lea` (`0x2dd298e` / `0x4de621e`), where a
  function passes the twin's address in `rdx`, with a stack
  result buffer in `rdi`, to a helper call (`0x232cd90` /
  `0x58251a0`) — an indirect registration whose forwarding is a
  boundary of this packet. The state therefore arrives from an
  untraced upstream at every level visible here; who first
  writes a mode or a limit value is *not* established.

## Trace

1. Authenticated the pinned distribution by size and SHA-256 and
   re-derived all four owner extents (and the helper's) from
   `.eh_frame` FDE records (CIE `0xca6ed8`); body hashes are in
   `records.json`, native readelf lines in `frames.txt`.
2. At each of the six field1-5 call sites, pinned the argument
   setup bytes: result buffer identity (`rsp+0x18` / `rsp+0x8` /
   `rsp`) and state argument provenance (entry `rsi`, then `r14`).
   The first call of each pair runs before the entry `rsi` is
   reloaded, so no other state can reach it.
3. Pinned the twin inline block end to end: remaining/cursor
   loads, the four-byte read and its state stores *before* the
   mode test, the mode `== 1` compare at `state +0x0`, charged
   load at `+0x20`, the `u64::MAX` overflow compare, limit load
   at `+0x8`, the `+1` increment, its store, and the
   old-count compare with its refusal branch; then the flag
   byte's `<= 1` test and the field1-5 call. The nonzero-u32
   arm's named result (tag 5, a length-6 string slice `NodeIp`
   at `0x5f430e` / `0x93a9f1`, a second pointer `0x4553c0`
   shared by both twins) is pinned as bytes.
4. Pinned the `bulk_a` inline charge (0x800) and record consume
   (cursor advance 0x800, `memcpy` of `0x7e9` bytes through GOT
   slot `0x64df508` after a 0x17-byte field-by-field header
   copy), and the `bulk_b` delegation: two calls, the helper
   call, the result-byte-1 branch, and the four staged 0x800
   `memcpy` copies through the pointer loaded from the same
   slot. Slot `0x64df508` resolves through `.rela.dyn`
   (R_X86_64_GLOB_DAT) to the dynamic symbol `memcpy`.
5. Traced the helper `0x58214b0` as a called boundary: mode
   test, 0x800 charge with the new-count rule, width test,
   shortfall form (tag 0 at `+0x8`, additional at `+0x10`),
   refusal form (tag 2 at `+0x8`), success payload at result
   `+0x1`, failure wrapper byte 1 / success byte 0 at `+0x0`.
6. Extracted the complete state-field access inventory of all
   five functions from the retained exports (every `[r14]` /
   `[rsi]` memory operand, classified read vs store) and
   censused the full `.text`: exactly 3 + 3 field1-5 sites (the
   six above), 0 slow-reader sites, exactly the two u32 sites
   inside the twins, **no** u64-family site inside any owner,
   3 + 3 direct callers for the bulk pair, exactly one helper
   caller, exactly one `lea` reference per twin. A whole-binary
   scan finds no 8-byte literal of any owner or helper address,
   so no absolute pointer table holds them either.

## Boundaries

- The field1-5 readers (`0x2cd7bb0`/`0x5821340`, slow
  `0x5822710`), the u32 readers (`0x2cd79c0`/`0x5821150`) and
  the u64 readers (`0x2cd7ac0`/`0x5821250`) are the owners of
  open packets #2422, #2412 and #2300 respectively; they are
  recorded here only as call targets. #2412 and #2422 each
  record these caller functions only as bare call-site census
  entries; no packet records the argument values, the inline
  charges, or the shared-state pairing traced here. #2300's own
  next question (identify an actual service caller) stays open:
  no u64 call occurs in these functions.
- The bulk helper `0x58214b0` is recorded as a called boundary
  of `bulk_b` with its charge and result contract pinned; its
  other callers, if any beyond the one direct site censused
  here (there are none in `.text`), and its own registration
  are not traced.
- The two helpers that receive the twin addresses (`0x232cd90`,
  `0x58251a0`) and the functions containing the `lea` references
  (`0x2dd2980..0x2dd2bd7`, `0x4de6210..0x4de6467`) are
  boundaries: whether the state they eventually pass is the one
  they received is not traced, and no mode/limit origin is
  claimed.
- `bulk_a`'s and `bulk_b`'s single calling functions are
  recorded as census entries with their state provenance; their
  own callers are not traced.
- No Rust reconstruction is included or claimed. Result and
  rawtag values are raw bytes; which Rust enum variants they
  name is not established from these bytes.

## Files

- `records.json` — authenticated owners and frame records,
  per-site argument facts, inline charge rules, the state-field
  access inventory, the cross-family finding, the direct-caller
  census, boundaries, relocations and limits.
- `twin_a.objdump.txt`, `twin_b.objdump.txt`,
  `bulk_a.objdump.txt`, `bulk_b.objdump.txt`,
  `bulk_helper.objdump.txt` — retained disassembly of the four
  owners and the boundary helper.
- `frames.txt` — native readelf FDE lines for the owners and
  the helper.
- `../../tools/field1_5_caller_args_static.py` — regenerator
  and verifier; `../../tests/test_field1_5_caller_args_static.py`
  — regeneration, census and counterfactual tests.

## Next question

Who constructs the reader state these decoders forward — the
first writer of a mode and limit value — and through which
registration the twin decoders are actually invoked: the helper
calls at `0x232cd90` / `0x58251a0` are the next hop.
