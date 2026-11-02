# Private RE-008 mode1 group intake — before new Rust

Published #1509 remains unchanged at3514ba93af48fc0cfd819f9706144c6b4b2e44bb.
This ignored intake closes a different state domain of the same contiguous
four-call helper: full u64(D+0)==1, initial32-byte reservation denial, and
admitted0..FA/FB/FC/FD composition. No source extension/build/public change
has occurred. This is not a standalone static-only PR proposal.

Target node94 SHA256:
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Coordinates are linked ELF VAs; ends exclusive. Group FDE0xef1f28 covers
0x466bf60..0x466c13f (479bytes, SHAaa484554c9abb65bea26e5450e6cda287fc037cc7c53a47ed5e04e2069ab44a0).
Scalar229B/Reader316B/row717B full bodies/FDEs and GNU/LLVM partitions were
reauthenticated with the published static verifier. `native-auth/` retains
complete exports/report. Its mode0 vector check is credited context, not a
new mode1 oracle; new mode1 expectations are the separate frozen TSVs.

## New gap

#1509's mode1 API deliberately leaves non-FD and nonadmitted inputs outside
its native claim. In particular its atomic OutsideDomain cannot stand for
native over-limit behavior: node stores C+32 before rejecting a limit. The
new normal path also shows four immediate bytes consume4 but charge32; charge
is logical scalar width, not encoded byte consumption.

- 0x466bf74 checks DWORDmode1. Domain fullword1 satisfies it and all three
  later QWORD-nonzero refund tests; no other modeword result is assigned.
- 0x466bf7d/81: unsigned C>MAX-32 returns before loading L or changing C.
- Otherwise0x466bf8f stores C+32 BEFORE0x466bf93/96 checks inclusive C+32<=L.
  Limit denial retains that increment. Both denials precede every scalar and
  input pointer/length/marker read. EOF or FE/FF cannot preempt this error.
- 0x466bf98/9c initializes only G tag qword1 and G+8 BYTE2. With a supplied
  valid prefilled40B G, the other31bytes are unchanged. Their error-payload
  meaning and any need value are unqualified. The raw40B relation is a
  prefilled-memory observation, not recovered error ABI or enum layout.
- On admission0x466bfae/b2 uses originalRAX C+24 (an8-byte state reduction
  from the earlier reservation). Each credited scalar adds8 before input;
  the first three successful returns refund8. Thus every scalar return has
  originalC+32 and before each next scalar state is originalC+24. The initial
  admission guarantees scalar charging cannot overflow/exceedL on this domain.
- Accepted scalar widths/LE values and first-short cursor/need come from
  #1365 and #1509 mode0 proof. The new claim is their mode1 group composition.
  Four calls/stop edges are the existing authenticated CFG, not new credit.
- Second row call0x4c7e422 passes G=rowRSP+0x28. Row loads/copies the complete
  result and takes its shared error route before0x4c7e4f3. Only active tag1/
  kind2 is assigned on initial denial; row need is deliberately `-` even
  though the machine loads/copies an uninitialized-or-prior G+0x10 qword.

## Frozen boundary corpus

PRE-MODE1-RUST-FREEZE.json pins128rows before source:
96admitted mixed-width/fast-Reader/short observations (18 explicitly credited
FD-only domains,78 formerly excluded mode1 marker cases),24 pre-marker denials,
and8 exact-admission edges. The denial pairs vary EOF vsFE/FF input and an
asymmetric40B prefill. C=MAX-32 vsMAX-31, C+32=L vsL+1, C0/L0, maximum charge,
EOF-before-marker and prefix-short cases are included. Successes specify the
whole40B group view. Shorts specify active fields only; their full memory
image remains `-`. Denials specify exact prefilled memory stores, with no
semantic need/payload claim. Row forwarding is a separate conditional native
observation, never a claimed complete decoder or constructor reachability.

Ten static native-site controls freeze exact original bytes and named-witness
predictions: overflow/limit equalities, reserve-store omission, reserve32→31,
initial24→23, each refund omission, kind and tag. They are analytical
counterfactual distinctions, never executed patched code. If Rust follows,
full-corpus source-countermodel counts must remain distinct from these
qualified native-site witness predictions; checker failure/API-only refusal
cannot count as a semantic witness.

## Premises, ownership and next step

Input immutable; decoder and declared G mutable; valid nonwrapping ranges;
input/state/result disjoint from one another and callee's own live control/
preservation frame. Declared ancestor-frame outputs are permitted. Ordinary
returns/preserved registers and no external mutation. Fullword1 is a supplied
byte-level premise, not a recovered constructor/enum. AdmittedFE/FF, other
modewords, inactive short-error bytes, allocator/panic ownership, original ABI/
lifetimes, fullQC-call reachability and crypto remain outside claim.

Fresh271openPRs/three pages: only#1509 owns466bf60/4c7e422. #1365 unchanged
4d33431d owns the scalar wrapper/Reader (six selected FDEs, not this group);
#1366 unchanged198ff2d0 owns outer4752890 construction; #1526 distinct response
helper remains credited. #1515 is same-crate preimage work, a module-list
integration overlap without this parser claim.

Await independent pre-Rust evidence/vector review. A later existing-component
extension must preserve old bool/outcome APIs, select a documented safe API
without inventing native error bytes, compile independently against these
frozen128rows atopt0/3 and compare operative group charge/denial controls.
No new tools, large worktree, Rust source, target execution/emulation, public
mutation or gate advancement is authorized by this intake alone.
