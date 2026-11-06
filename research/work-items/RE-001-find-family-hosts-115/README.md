# RE-001: pin node #115's four remaining sibling Find-family hosts

Task ID: RE-001. Artifact: node #115 (`artifacts/node/115/hl-node`),
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How do the four remaining sibling Find-family hosts drive the
already-pinned Find pipeline (find_e70 0x6099e70, no_equals
0x609ba30, kind_dispatch 0x609b700, name_lookup 0x60ba0b0,
element_scan 0x6096f40, matcher 0x60bb9a0, status_builder
0x61cf670), and what does each report when the name cannot be
resolved?

## The four hosts

- `find_plain_table` 0x6080b10 (700 B): the PlainTableOptions
  host. The delegate is loaded from the holder; a null delegate
  reports Status code 1 "Mismatched table option: " + name
  (with a factory name the defaults are built directly instead).
  Otherwise "PlainTableOptions" is built and the delegate's
  slot 0x38 resolves the options struct. The factory name
  "plain_table_factory" (19 chars) takes the create path (the
  resolved struct, or the 0x28-byte defaults: byte +0x04 = 0xa,
  dword +0x0e = 0x103fe8); any other name takes no_equals when
  resolved, else the code-1 error. On a successful find_e70 the
  created object is installed into the holder's shared_ptr
  (control counts 0x100000001, vtable 0x64c8748) and the old
  control is released; on a failed find_e70 the created
  object's vtable slot 0x08 is called instead.
- `find_block_table` 0x60818f0 (1048 B): the BlockTableOptions
  host, the same skeleton with the name "BlockTableOptions",
  the factory name "block_based_table_factory" (25 chars) and
  the 0x260-byte creator. A null resolved struct builds the
  0xf8-byte defaults (29 zeroed qwords, then the pinned field
  values, including the 16-byte template {0x2000, 0x2} from
  0x4506c0 at +0xe8); the defaults' owned sub-objects are
  released after the creator (all zero in the defaults path).
- `find_by_element_scan` 0x6098ad0 (1331 B): the element-scan
  host. element_scan runs over the table's vector; a null
  result is Status code 1 "Cannot find option: " + name.
  Otherwise the 0x50-byte value is copied (its +0x48 control
  use-count bumped) and the copy's name is replaced with ";"
  (the resolver sentinel); an exact match or kind 0x13 takes
  the matcher 0x60bb9a0, kinds 0x15/0x16 take the delegate
  slot-0x10 virtual (dereferenced once when the found node's
  +0xb1 byte has any of bits 0x8/0x4/0x2 set; a null object is
  the code-1 error), any other kind is the code-1 error.
- `resolve_all_elements` 0x609bcb0 (2770 B): the registry
  walker. A local empty name set is built (one bucket, count
  1, load 1.0) and the registry map is walked: per element
  the node's slot 0x68 fills the search key, name_lookup
  runs, and on a hit kind_dispatch runs with the element's
  value string as arg7. Code 1 advances; code 3 accumulates
  the code-3 status and inserts the element's key into the
  local set (a 0x30 node, hash at +0x28); any other code
  erases the element (the erase counter incremented) and,
  when non-zero, accumulates the code status. When the list
  is exhausted and erasures happened, the outer loop repeats;
  the sweep phase erases every collected name from the
  registry map. The final Status follows the value's +0x00
  word bytes and the accumulated families.

## Helpers pinned by this item

`cstr_ctor` 0x607d9f0 (a second instantiation of the same
template as 0x60b7d80), `plain_creator` 0x6193b40 /
`plain_ctor` 0x6193a00 (vtable 0x64d6628, the 17-char name
"PlainTableOptions", the record append), `block_creator`
0x60dbd80 / `block_ctor` 0x60db710 (a documented boundary:
sub-constructors, mutex init, record append with global
0x6507540, vtables, "map::at"), `options_list_destroy`
0x607e020 (recursive, reverse-chain free order),
`map_find_name` 0x609a1b0 / `map_erase_next` 0x609a2f0 /
`map_insert` 0x609bad0 (the local name set's insert),
`cstr_dup` 0x61cf610, `counted_release` 0x5d350c0 (1273 call
sites + 25 jumps), `options_record_append` 0x6099ce0,
`clear_string` 0x60b79b0. The entry, find_e70, no_equals,
resolve_no_equals, kind_dispatch, element_scan, name_lookup,
hash_name_find, move_assign, ends_with, str_compare,
fallback_delegate, delegate_impl, zero_stub, find_norm,
parser, map_clear, status_builder, shared_release, matcher,
resolver, value_copy, value_dtor and cstr_ctor 0x60b7d80
are re-shipped byte-identical from #3485 / #3488.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-find-family-hosts-115/verify.py

It checks the binary digest against
`provenance/artifacts.json`, the MANIFEST coverage, the
byte-for-byte regeneration of every excerpt, the raw bytes
of every excerpt line against the binary (plus three seeded
random gate spots, `random.seed(20261106)`), the FDE
presence, the relocation row, the literal read-back
(including the 16-byte template at 0x4506c0), the census
reproduction (3761 rows) and per-target counts, the model
constants and the GOT re-derivation, and the model tests
(50 tests in `tests/test_find_family_hosts_115.py`).

The model is `tools/find_family_hosts_115.py`, self-contained
(it imports nothing from the open #3485 / #3488 PRs).

## How the evidence was produced

    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin

per window (see `export_excerpts.py`, which regenerates every
excerpt in `excerpts/`). The census (`census.py`) is one
objdump pass over the whole binary counting direct calls,
jumps and lea references to the packet's routines with the
enclosing FDE per site; it writes `callers.tsv` (3761 rows).
`frames.txt` is the `readelf --debug-dump=frames-interp`
listing filtered to the packet's FDE ranges. The mnemonics
in the excerpts (endbr64 included) are genuine instructions
present in the target binary, not placeholders.

## Open unknowns

- On the null-delegate path with a factory name the binary
  builds the defaults directly (slot 0x38 is never called);
  the model takes that deterministic defaults path.
- The walker's arg2 first two bytes select the final Status;
  their source meaning is not pinned -- the model reads them
  from the value's +0x00 word.
- The block constructor's sub-calls and field layout are a
  boundary; only its contract and pinned references are
  modelled.
- The created objects' vtable slot 0x08 semantics: the
  binary calls it on the created object only when find_e70
  fails; the model calls the injected slot_0x08 on that
  path (likely the deleting destructor, since the object is
  otherwise leaked there).
- The plain host's reach is lea-only (address taken at
  0x609052f in FDE 0x6089b50..0x6091e5c, no direct call);
  the block host has one direct call (0x6081d38), the
  element-scan host one (0x609907a), the walker one
  (0x609ca6d).
- The global default name at 0x6508980: its runtime contents
  are set by static init and were not located (carried from
  #3440); the model takes "default" as the documented
  assumption (a "default" literal sits at 0x44371c).
- The delegate vtable base is not pinned; the model holds
  the delegate's slots as callables supplied by the harness.
- The serializer 0x60ba600 per-kind rules (25 jump-table
  cases) are a boundary; the default model reports every
  kind as serialized.
- Which construction paths install a non-null +0x28
  delegate is not pinned.
- The walker's local-set insert passes a fifth argument
  (r8d = 1) to map_insert 0x609bad0 at its only call site;
  its meaning is not pinned and the model ignores it.
