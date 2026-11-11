# RE-002 · Node #115 RocksDB TracerHelper::ParseTraceHeader

Component: storage / tracing. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115's `rocksdb::TracerHelper::ParseTraceHeader` work:
how does it split the header trace payload and parse the two version
ints? One function, `0x61b4840..0x61b530d` (2765 bytes), body hash
matching the vendor census exactly, source hash reproduced by zeroing
its 36 relocation fields (see `functions.tsv`).

## Answer (pinned)

**Signature.** `Status ParseTraceHeader(const Trace& trace, int*
trace_version, int* rocksdb_version)` — the Status is returned by
value (hidden sret `Status*` in `rdi`; `rsi` = trace, `rdx` =
trace-version out-param, `rcx` = RocksDB-version out-param), per the
census symbol
`_ZN7rocksdb12TracerHelper16ParseTraceHeaderERKNS_5TraceEPiS4_`. The
binary reads only the payload `std::string` at `Trace+0x18`
(timestamp and type are not read here).

**Split.** The payload is split on TAB (single byte `0x09`,
`.rodata 0x43fc29`, `find` with `n=1`) into exactly three fields. The
loop runs three times; each field is `payload[pos : pos+len]` where
`len` is the distance to the next TAB, or the remainder when no TAB
follows. Field 0 is never read — in live headers it holds the 16-byte
magic, but nothing in this function checks it.

**The wrap quirk.** The position is 32-bit: when `find` returns
`npos`, the next position becomes `(npos + 1) & 0xFFFFFFFF == 0`, so
the next iteration searches from the payload start again. A one-TAB
payload's third field is the payload's own first field; a no-TAB
payload repeats itself three times. The split loop's own
`out_of_range` check (`pos > size`) is present in the binary but
unreachable — `pos` is always a found TAB index + 1, or 0 after the
wrap.

**Version parsing.** `field[1].substr(15)` then `field[2].substr(17)`
— the skips are offsets only, the label bytes are never compared.
The producer (`Tracer::WriteHeader`, `0x61b3860`) writes exactly the
labels `"Trace Version: "` (15 bytes, `.rodata 0x4478de`) and
`"RocksDB Version: "` (17 bytes, `.rodata 0x442aec`), which is why
the offsets are 15 and 17. A field shorter than its skip throws
`std::out_of_range` (`"basic_string::substr"`, `.rodata 0x43e542`;
format `"%s: __pos (which is %zu) > this->size() (which is %zu)"`,
`.rodata 0x958cf8`). Each remainder is parsed by `ParseVersionStr`
(`0x61b10f0`, modeled from open PR #5863): at least two `'.'`,
then the decimal concatenation of every digit (32-bit wrap); on
failure the version out-parameter is left untouched.

**Error precedence.** A first-version failure returns at once — the
second parse never runs, both versions stay untouched, and the
returned Status is the first error. A second-version failure keeps
the parsed trace version, leaves the RocksDB version untouched, and
returns the second error. On success both versions are written and
the returned Status is OK. The returned Status is always the second
call's status: it is moved over the first one in the out Status (the
first one is OK whenever the second call runs, so nothing is freed
in practice).

**Caller.** Exactly one direct caller, validated by the whole-`.text`
Capstone census (`census.py`): `rocksdb::ReplayerImpl::Prepare`
(`0x61fe431`, in FDE `0x61fe370..0x61fe51c`), which passes a member
`int*` for the trace version (`this+0x58`) and a stack-local `int*`
for the RocksDB version, and moves the returned Status into its own
Status slot. No tail jumps or LEA references exist.

## Cases

2,400 deterministic cases (`cases.tsv`, seeded generator in
`tools/tracer_helper_parse_header115.py`): 600 `split_payload` (the
three-field TAB split, empty fields, extra TABs ignored, the
npos-wrap quirk), 600 `parse_version_str` (digit concatenation,
both error messages, 32-bit wrap, bad-byte rejection), 1200
`parse_trace_header` (live header payloads, field 0 ignored,
prefix-agnostic skips, error precedence, `substr` throws, extra
TABs). 20 tests pass
(`tests/test_tracer_helper_parse_header115.py`).

## Caller census

Whole-`.text` scan for E8 calls, E9 tail jumps and RIP-relative LEA
references landing on the target, validated by decoding forward from
the enclosing FDE start with Capstone (`census.py`). 1 validated
site: the `Prepare` call at `0x61fe431`.

## Unknowns (kept separate from observations)

- The upstream `TraceType` enumerator names are not needed here —
  this function never reads the type byte. They remain open from the
  codec packet.
- Whether the upstream source spells the split as an explicit loop or
  a helper is not pinned from the binary; the observable split
  semantics (three fields, TAB delimiter, npos wrap) are. An
  upstream-source read was requested; if it has not landed, this
  stays open.
- The `Tracer` methods that produce the header payload (`WriteHeader`
  at `0x61b3860`, `WriteTrace`) and the replayer method that consumes
  the parsed versions (`Prepare` at `0x61fe370`) are separate FDEs
  and are NOT reconstructed in this packet.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool is a behavioural Python model of the one function
only. `make verify` / `make test` / `make catalogue-check` in a tooled
environment is still owed upstream. Object dump format: GNU objdump
2.42, Intel syntax. Upstream base: RocksDB v8.1.1
(librocksdb-sys 0.11.0+8.1.1 per the vendor census).
