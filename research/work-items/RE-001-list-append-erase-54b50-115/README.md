# RE-001: map node #115 list append 0x5d54b50 and erase 0x5d54ba0

Task: RE-001. Bounded question: what do the routines at 0x5d54b50 and
0x5d54ba0 do to their holder's list at +0x1260/+0x1270, and which code
calls them?

Target: node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound via `provenance/artifacts.json`), upstream main `8fd8db68`
at the time of this work.

## Answer in one paragraph

The two routines are the append and erase halves of one list behavior.
Append reads an 8-byte value from the holder's value source (the
sub-object at holder +0x68, field +0xd8), allocates a 0x18-byte node
holding that value at +0x10, hooks the node immediately before the
holder's list sentinel at +0x1260, increments the size at +0x1270,
and returns the new node (the sentinel's prev slot after the hook).
Erase takes the address of a handle slot: a null slot is a no-op, and
otherwise it unhooks the node the slot's cell points to, frees the
node with the sized delete passing (node, 0x18), zeroes the slot, and
frees the 8-byte cell. The append caller at 0x5d6b634 demonstrates
the full handle lifecycle — fresh cell, node stored into it, previous
cell freed, cell stored into the slot — so the pair is pinned end to
end, not as two lone windows.

## Layouts

Holder list (offsets from the holder pointer):

| Field | Offset |
| ----- | ------ |
| sentinel next | +0x1260 |
| sentinel prev | +0x1268 |
| list size | +0x1270 |
| value-source sub-object | +0x68 (value field at +0xd8 of that object) |

List node (0x18 bytes):

| Field | Offset |
| ----- | ------ |
| next | +0x00 |
| prev | +0x08 |
| value | +0x10 |

Handle cell: one 8-byte heap cell whose sole field holds the node
pointer. A handle slot holds null or a cell pointer.

## Append 0x5d54b50 (75 bytes)

1. Load the value: sub-object = [holder + 0x68], value =
   [sub-object + 0xd8].
2. Allocate a 0x18-byte node with operator new.
3. Store the value at node + 0x10.
4. Hook the node immediately before the sentinel at holder + 0x1260
   (PLT stub `_List_node_base::_M_hook`, called with the node and
   the sentinel address).
5. Increment [holder + 0x1270] by 1.
6. Return [holder + 0x1268] — the sentinel's prev slot, which after
   the hook holds the new node.

## Erase 0x5d54ba0 (97 bytes)

1. Load the cell pointer from the slot: cell = [rsi].
2. If the cell pointer is null, return at once: size unchanged,
   nothing freed.
3. Otherwise load the node: node = [cell].
4. Decrement [holder + 0x1270] by 1.
5. Unhook the node (PLT stub `_List_node_base::_M_unhook`), then free
   it with the sized delete passing (node, 0x18).
6. Store 0 into the slot, then free the cell with the sized delete
   passing (cell, 8).
7. Return with no value.

## Consumers

Census method: executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by `census.py` and re-run inside
`verify.py`. Neither routine is reached by data: 0 stored qwords and
0 RELATIVE relocations for either address.

Append: exactly 6 direct calls, 0 tail jumps — 0x5d6b634 (caller
0x5d6b530..0x5d6b7d4), 0x5d77b21 (0x5d77770..0x5d7833f), 0x5defe9d
(0x5defe00..0x5df03d6), 0x5df2dcd (0x5df2380..0x5df3659), 0x5df65d3
(0x5df6530..0x5df6d1d), 0x5e66974 (0x5e666a0..0x5e68ceb).

Erase: exactly 8 direct calls, 0 tail jumps — 0x5d77c26
(0x5d77770..0x5d7833f), 0x5d82c1a, 0x5d82d0f and 0x5d83648 (all in
0x5d82240..0x5d83d9a), 0x5defefb (0x5defe00..0x5df03d6), 0x5df324a
(0x5df2380..0x5df3659), 0x5df6636 (0x5df6530..0x5df6d1d), 0x5e67ae4
(0x5e666a0..0x5e68ceb).

Five caller functions call both routines; caller bodies beyond the
call sites are not pinned.

## Evidence packet

- `main.txt`, `erase.txt`: whole-function disassembly excerpts,
  verbatim as objdump emitted them. The objdump header is normalized
  to the bare binary name only; every instruction line is byte-for-byte
  the binary's bytes (checked by `verify.py` against the raw file).
  The leading `endbr64` in each routine is a genuine instruction
  present in the target binary, not a placeholder.
- `frames.txt`: the FDE lines for both routines and all distinct
  caller functions.
- `callers.tsv`, `erase_callers.tsv`: the confirmed call sites.
- `relocations.txt`: empty — no RELATIVE relocation references
  either routine.
- `records.json`: semantic records only (no per-instruction detail).
- `export_excerpts.py`: regenerates the excerpts and frames from
  the binary. `census.py`: reproduces the censuses.
- `verify.py`: re-checks the digest, the manifest, excerpt
  regeneration, excerpt bytes against the raw binary, the FDE ranges,
  both censuses with exact site lists, the empty relocation record,
  the semantic-only records, and model spot checks.

Regeneration commands:

```
objdump -d --start-address=0x5d54b50 --stop-address=0x5d54b9b work/hl-node-115.bin
objdump -d --start-address=0x5d54ba0 --stop-address=0x5d54c01 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin
```

## Observations and unknowns

- The hook-before-sentinel reading is cross-checked, not assumed
  from the stub name: after the hook the sentinel's prev slot holds
  the new node, and the 0x5d6b634 caller stores exactly that return
  value into its handle cell, which erase later unhooks.
- Erase's null check is on the cell pointer, not the node. A
  non-null cell is assumed to hold a live node of the holder's list;
  the routine checks neither membership nor liveness.
- Not pinned: the type/identity of the value at
  [[holder + 0x68] + 0xd8] (only its load chain), what callers do
  with the list beyond these routines, and the bodies of the
  `_M_hook` / `_M_unhook` PLT stubs beyond their observed effects.
