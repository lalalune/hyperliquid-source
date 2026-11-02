# RE-001: node #94 counters-to-uptime report 0x5159180

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x5159180 do end to end — which counters does it render,
through which name map, and which uptime entry does it append from
the clock?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## What the window does

The window (0x5159180..0x515994f, FDE 0x00634bf8) renders nine
counters of an outer object into a keyed report map, then appends
one uptime entry from the clock. It returns void; the map is the
result.

- Counters, i = 0..8: the name comes from `global_names.at(i)`,
  an ordered int-to-string map whose header sits at 0x578bee0+0x08
  (root at [0x578bee0+0x10]); a missing key throws
  std::out_of_range with the literal "map::at" (0x1efeee), so all
  nine keys must be present. The value is the unsigned decimal of
  outer + i*8 (outer+0x00..outer+0x40), produced by an inlined
  itoa: a digit-count ladder (<= 9 / 99 / 999 / 9999, then
  divide-by-10000 steps adding 4 digits with 999999 / 9999999 /
  99999999 remainder arms adding 5 / 6 / 7), a "00".."99"
  digit-pair table copied onto the stack from the same 13
  .rodata vectors as the standalone itoa, pairs written from the
  end per divide-by-100 step, and a one- or two-digit tail arm.
  The entry is written by find-or-insert 0x5153a70 (which returns
  the node's +0x40 value-string address) plus an inlined
  move-assign with heap-steal and SSO-copy arms.
- Uptime: the clock comes from a 3-node +0x98 dispatch chain
  rooted at [outer+0x780] (sentinel cell 0x5777bc8, links +0x20;
  the first two slots are called when they differ from the
  sentinel, the third unconditionally). The entry value is
  "%f" % ((clock - [outer+0x790]) mod 2**64 / 1,000,000.0), where
  the negative-difference arm performs the unsigned conversion
  ((x >> 1) | (x & 1), then double and add to itself). The key is
  the literal "db.uptime" (0x1eb2b6). An inline lower_bound walk
  over the target nodes (saturating string comparison: memcmp
  over the common prefix, then the length difference clamped to
  int32) either finds the node and move-assigns the %f string
  into its +0x40 value string, or inserts a fresh 0x60-byte node
  via 0x5153650 and then assigns it.
- Canary check, then return. The exception cleanup at
  0x515914e..0x5159180 (no FDE of its own) has a full entry
  (dispose the uptime-key string, then the %f string) and a
  %f-only entry, ending with _Unwind_Resume. The two thunks at
  0x5159130 and 0x5159140 belong to the 0x5158ef0 accessor and
  are not part of this item.

Callees cited only, not re-claimed: the find-or-insert 0x5153a70,
the insert 0x5153650, the double formatter 0x514c050 (format
"%f"), the string constructor 0x514b6d0, the string compare
0x514b340 and the move-assign 0x514b4f0. The sole direct caller
is the thin wrapper 0x5159950..0x5159967, which forwards
(outer, target) unchanged and returns 1.

## Notes on the evidence

Instruction-level detail lives only in the raw disassembly
excerpt text files, kept verbatim and whole-function. The JSON
record holds semantic records only. Mnemonics such as `endbr64`
are genuine instructions present in the target binary, not
placeholders; the checker re-verifies three sampled instructions
byte-for-byte against a fresh objdump run.

The nine names in the global map are runtime-populated storage
(0x578bee0 is zero in the file), so they are model parameters,
not file contents. The same holds for the clock chain's sentinel
value: the cell at 0x5777bc8 is compared by value, and the model
takes that value as a parameter.
