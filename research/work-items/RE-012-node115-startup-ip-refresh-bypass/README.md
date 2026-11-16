# Selected catch-up construction bypasses computed-IP refresh

Partial RE-012 startup evidence for Linux x86-64 node #115, size 105896032,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

On the selected successful construction path in `0x2af45f0`, the byte that
becomes the refresh object's +0x260 is initialized to 1. The retained copy
chain transports that byte into the catch-up task and ultimately into
`0x2af7150`, whose equality branch skips the computed-IP comparison/replacement
block. This establishes a concrete startup limitation: reaching this refresh
function does not by itself establish publication of a fresh address map.

The claim is about the selected construction and preserved byte, not every
startup mode, every invocation, or an immutable configuration for all time.
It also does not infer a listener-owner identity from matching field offsets.

## Existing contracts and the additional evidence

#6060/#6064/#6065 and `RE-009-abci-freeze-snapshot` already cover portions of
catch-up task construction, initial engine state and output. They do not bind
the +0x260 refresh condition to the initialized byte followed here. #7045
(`RE-005-node115-computed-ip-refresh`) establishes what `0x2af7150` does when
+0x260 is not 1: construct a candidate view, compare under a read lock, and
replace under a separate write lock. That packet deliberately does not assert
that every startup reaches that branch or that its destination equals the
listener's allocation.

#5407 (`RE-005-node115-peer-address-admission`) establishes the listener's
lookup source, but excludes construction of its future/owner. This packet
records why the selected catch-up constructor cannot be used as an assumed
producer-to-listener allocation bridge. No previous component result is
reclassified or marked complete.

## Exact byte through construction and polling

The following offsets are local to the named frame/object. Copies are ordinary
normal-return copies of the retained byte ranges; all hexadecimal arithmetic
below concerns placement, not matching layout alone.

| Stage | Placement of the selected byte | Native evidence |
|---|---|---|
| `0x2af45f0` local refresh aggregate | stack+0x590 = aggregate at stack+0x330, plus 0x260 | `0x2af578f` stores 1 |
| Same function's output N | N+0x260 | stack+0x330 → stack+0xa60, length 0x2e0 at `0x2af5b4c..61`; stack+0xa60 → N, length 0x308 at `0x2af5c06..16` |
| `0x2b41b70` startup frame | object+0x320 | output at stack+0x70 → stack+0x430, length 0x3b8; first 0x2e0 bytes → stack+0x7f0 → object+0xc0 (`0x2b42442..54`, `0x2b42499..ae`, `0x2b4257d..91`) |
| Catch-up input I, starting at object+0x80 | I+0x2a0 | 0xc0 + 0x260 - 0x80 = 0x2a0; 0x350-byte copy to stack+0x70 passed to `0x2b3aba0` at `0x2b4261c` |
| Allocated task Q | Q+0x2e0 | constructor input → stack+0x4f4, then 0x354 bytes from stack+0x4f0 → stack+0xbc; final 0x400-byte copy from stack+0x80 → Q. Input I begins at Q+0x40 |
| Task poll's local input | stack+0x910 | poll extracts Q+0x40 into stack+0x1188 and copies 0x350 bytes to stack+0x670 (`0x2b1e104..133`, `0x2b1e171..186`) |
| Refresh argument O | O+0x260 | call `0x2b1e5f1` passes O=stack+0x6b0; 0x670 + 0x2a0 - 0x6b0 = 0x260 |

The constructor puts vtable `0x6449fb0` at task Q+0x10; its relocated first
entry is `0x2b1df60`, the poll function whose extraction is shown above. This
binds the payload copy to its actual poll entry, rather than pairing two
similarly shaped task objects. The constructor's four-byte prefix explains
why its first local copy starts at +0x4f4 while its next starts at +0x4f0.
Ignoring that prefix changes the resulting field offset.

This is a selected normal-construction/copy contract. Calls to scheduler,
allocation, copy and intervening helpers must return normally; valid ownership
and no intervening writes to this tag through aliases are premises. The
packet does not turn a retained initialization into a universal temporal
invariant. In particular, a separately constructed object or later explicit
tag change requires its own provenance analysis.

## Observable branch boundary

`0x2af7150` preserves O in RBX and reads O+0x260 at `0x2af717a`. If it equals
1, `0x2af7188` initializes the local optional result byte to zero and
`0x2af718d` jumps directly to `0x2af7400`. The alternative starts at
`0x2af7192` and includes:

- candidate construction/filtering;
- the O+0x290 destination-pointer load at `0x2af7292`;
- comparison and selected replacement already established by #7045;
- candidate cleanup ending at `0x2af73f6`.

The equality branch therefore does not load O+0x290 or execute that block.
At `0x2af7400`, later processing resumes with other captured fields and the
local optional result; the function itself has not returned. This finding
must not be described as skipping all publication, all catch-up processing,
or the whole function.

The inactive destination field is not evidence of a live allocation shared
with a listener. This packet neither interprets its unused bytes nor claims
that no other startup path initializes them. A future producer/listener join
must identify a path with a non-1 tag and trace the actual allocation/captures
on that path.

## Reproduction and scope

`records.json` retains ten windows, 315 instructions, 64 selected witnesses and
the task-poll relocation. `verify.py` validates the whole artifact digest/size,
enclosing FDEs, exact window hashes, instruction bytes/boundaries, witnesses
and relocation. Eight controls reject a wrong artifact, active-refresh tag,
truncated aggregate copy, shifted job origin, omitted constructor prefix,
wrong refresh member, inverted condition or redirected skip jump. These are
static witness controls, not captured-code execution or behavioral emulation.

```
python3 research/work-items/RE-012-node115-startup-ip-refresh-bypass/verify.py --target artifacts/node/115/hl-node
```

Use Capstone 5.0.7 and pyelftools 0.32. No captured executable is run or
emulated. No fabricated live fixture, source-owned node, full initialization
model, scheduler proof or full-scope component gate is introduced. The useful
output is the actual initialized-byte-to-branch relation and the precise
additional prerequisite for a future live-map publication integration.
