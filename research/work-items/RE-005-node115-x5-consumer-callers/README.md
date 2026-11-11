# RE-005 node 115: who calls the X5 slot consumers

## Question

The caller-slot packet (`RE-005-node115-x5-caller-slot-consumers`,
PR #3235) pinned the 63 FDE bodies that load GOT slot `0x64e7718`
-- the only static holder of the X5 schedule-caller body
`0x5cf5100` -- and recorded, for each consumer, only the count of
its direct rel32 callers. It left one question open: who calls the
consumers, from which bodies and call sites, under what call-site
conditions -- and is there any indirect path to a consumer at all?

## Method

Static analysis only, against the authenticated node 115 binary
(SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`). The consumer set is
re-derived from the binary -- verified rip-relative references to
the slot, grouped by FDE body -- and checked against the start,
end, and body hash of every consumer pinned by PR #3235. A
candidate scan over every executable section
(.fini, .init, .plt, .text) enumerated every `e8`/`e9`
byte position whose rel32 lands on a consumer start; each candidate
was verified by decoding the instruction at the site, and the
verified set was cross-checked against a linear disassembly sweep
of every containing FDE body: the two sets are identical.
Independent passes excluded the indirect forms: relocation addends
across all 60723 `.rela.dyn` and
278 `.rela.plt` entries, stored 8-byte copies
outside the relocation sections' own serialised entries,
immediate materialisations, rip-relative references resolving to a
consumer start, and `.dynsym` values.

## Answer

Every consumer is called directly, and only directly:
**67 verified `call rel32` sites**
in **65 caller bodies**, no direct jumps, no
site outside an FDE body, and no indirect path -- the indirect
census above is zero in every form. The caller bodies form
17 address clusters:

- 1 body, 0x159d600..0x159eab7, body sizes 5303
- 1 body, 0x17457f0..0x17480df, body sizes 10479
- 14 bodies, 0x24519c0..0x24535be, body sizes 510
- 1 body, 0x2a0acc0..0x2a0b327, body sizes 1639
- 1 body, 0x2a191e0..0x2a195a7, body sizes 967
- 1 body, 0x2a225c0..0x2a2334f, body sizes 3471
- 1 body, 0x2a2a0e0..0x2a2b882, body sizes 6050
- 1 body, 0x2a64e20..0x2a66324, body sizes 5380
- 1 body, 0x2a91280..0x2a915c0, body sizes 832
- 1 body, 0x2ae27c0..0x2ae3cbf, body sizes 5375
- 1 body, 0x2b41b70..0x2b43283, body sizes 5907
- 1 body, 0x2c7fa40..0x2c7fd80, body sizes 832
- 1 body, 0x452aab0..0x452aeb9, body sizes 1033
- 5 bodies, 0x4e35990..0x4e3666e, body sizes 629/639/686
- 31 bodies, 0x4e44fd0..0x4e4a95a, body sizes 534/538/556/740/748/802/888/897/898/927/1232/1364/1368/1447
- 2 bodies, 0x5a93b50..0x5a945ff, body sizes 1343/1387
- 1 body, 0x5ceb530..0x5ceb6c3, body sizes 403

64 of the 65 caller bodies call exactly one consumer. The single
exception, body `0x2b41b70`, calls three (`0x2b3aba0`,
`0x2b3b3e0`, `0x2b3d250`). Three consumers have more than one
caller: `0x2e8e7b0` has three call sites, and `0x2b3c9d0` and
`0x5a79730` have two each.

The call sites separate into three families by the instruction
pattern around them, pinned per site in `records.json`:

- **Flag-pair family (36
  sites)** -- exactly the callers of the 36 uniform 1169-byte
  consumers. Within eight instructions before the call, at least
  two `mov byte ptr [rsp + k], 0` stores zero a pair of stack flag
  bytes; within six, a `lea rdx, [rip + disp]` loads the same
  static (0x649db00) as the third argument at every site; the
  instruction before the
  call points `rsi` at the second flag byte in
  36 of the 36 sites, and the
  instruction after the call is `test rax, rax` at all 36.
- **Static-second-argument family
  (28
  sites)** -- a `lea rsi, [rip + disp]` within six instructions
  loads a static as the second argument
  (6 distinct statics).
- **Residual (3
  sites)** -- the two callers of the large consumer `0x5a79730`
  and the caller of `0x5cf4540`; each is pinned with its own
  preceding and following instruction.

One level up is recorded as counts only (`direct_callers` and
`relocation_addends` per caller body). Seven caller bodies have
no direct rel32 callers at all; each of them has exactly one
`.rela.dyn` entry whose addend is its start, so their addresses
are held as stored pointers. Those pointers are counted here,
not followed.

## Boundaries

RE-005-node115-x5-caller-slot-consumers (#3235) pins the 63 consumer bodies and records only the count of each consumer's direct rel32 callers; this packet enumerates them. Individual sites appear incidentally in earlier work: RE-017 packets record 11 of the sites as transfer/call rows (0x2b4261c, 0x4e359fc, 0x4e35c7c, 0x4e36191, 0x4e3642f, 0x4e45a61, 0x4e460c1, 0x4e46e71, 0x4e47938, 0x4e47cdf, 0x4e4a771), RE-011-evm-fee-history-115 records one call row (site 0x2a0afd5 into 0x2b3daa0), and RE-012-node115-startup-end-height's instruction window over caller body 0x2b41b70 includes its three sites (0x2b420da, 0x2b4261c, 0x2b428ab). No earlier packet enumerates the call sites of the consumer set, groups them by caller body, pins their call-site conditions, or excludes the indirect reference forms for the consumers.

For each caller body this packet records only two counts: raw direct rel32 call/jump byte occurrences in .text whose target is the body start, and .rela.dyn entries whose addend is the body start. Who reads the seven stored pointers, and the callers' callers in general, are outside this packet's question.

Which runtime path reaches a given call site, what the per-site statics name, and the concrete Rust types of the caller bodies are not established by static evidence.
