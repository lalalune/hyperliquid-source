# RE-002: reconstruct node #115 `rocksdb::LineFileReader::ReadLine`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `LineFileReader::ReadLine(std::string* out,
Env::IOPriority rate_limiter_priority)` -- the OPTIONS-file line
reader `RocksDBOptionsParser::Parse` loops on to read the OPTIONS
file one `\n`-terminated line at a time: scan the 8 KiB buffer for a
newline, refill it from the embedded `SequentialFileReader` when the
buffer is exhausted, and report EOF vs I/O error through `GetStatus()`.
2,400 byte-checked cases; 29 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). One FDE, pinned by recomputation, with
NO vendor census record (body hash only, per the #5992 no-census
convention):

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::LineFileReader::ReadLine` | `0x60d4cf0..0x60d4f62` | 626 B | `4894ad484826ac17944c8af7f6c897240815886e42b70fd44ae700cffa3418b2` | none (no record) |

The identity is pinned three other ways, not by the census: (1) the
class is named by the census-bound destructor
`_ZN7rocksdb14LineFileReaderD1Ev` at 0x60cbea0 (member
`d7ece8bd5f9dc186-options_parser.o`, body hash
`4dfc45e60530e411...`), whose body destroys exactly this layout; (2)
its only caller in the whole `.text` is the census-bound
`rocksdb::RocksDBOptionsParser::Parse` 0x60cfb60 (call site
0x60d0343), which loops `while (ReadLine(&line, IO_TOTAL))`; (3)
upstream v8.1.1, read live this cycle, matches the binary step for
step (see Upstream cross-check). This closes the open unknown the
#5992 packet left ("the unidentified FDE 0x60d4cf0
(`SequentialFileReader::Read` caller, n 0x2000, priority forwarded)")
and the follow-up the #6222 packet noted.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `bool LineFileReader::ReadLine(std::string* out,
Env::IOPriority rate_limiter_priority)`; `this` in `rdi`, `out` in
`rsi`, the priority in `edx` (forwarded to
`SequentialFileReader::Read` as `r9d`).

**1. Entry gate (0x60d4d16..0x60d4d1d).** If `io_status_.code`
(`this+0x20a8`, byte 0) != 0, return `false` at once -- `out` is NOT
cleared and NOT touched (the sticky-error gate; upstream
`line_file_reader.cc:33-37` does the same check, then
`io_status_.MustCheck(); return false;` -- `MustCheck()` is an empty
inline in this build and has no binary call).

**2. `out->clear()` (0x60d4d23..0x60d4d45).** `out->size() = 0` and
`out->data()[0] = 0`. The reader state is loaded: `r12 = buf_begin_`
(`this+0x20b8`), `r15 = buf_end_` (`this+0x20c0`).

**3. Loop head (0x60d4ebc..0x60d4ed2).** `remaining = buf_end_ -
buf_begin_`; `p = memchr(buf_begin_, '\n', remaining)` (PLT memchr
0x63f1790). If `p` is null, go to the refill path (step 5).

**4. Newline found (0x60d4ed8..0x60d4f17).** `len = p - buf_begin_`;
the length check (0x60d4ede..0x60d4eef) throws
`__throw_length_error("basic_string::append")` (PLT 0x63f0de0, string
at 0x4474d2) if `len > MAX - out->size()` with `MAX =
0x3fffffffffffffff`; else `out->append(buf_begin_, len)`
(`std::string::_M_append`, PLT 0x63f0f40) -- the returned line
EXCLUDES the newline; `buf_begin_ += len + 1` (the newline is
skipped); `line_number_` (`this+0x20c8`) += 1; return `true`.

**5. Refill path, no newline in the buffer
(0x60d4d70..0x60d4d96).** If `at_eof_` (`this+0x20d0`) is set, return
`false` -- `out` keeps whatever earlier refills of THIS call already
appended, and the caller discards it. Else the same length check, then
`out->append(buf_begin_, remaining)` -- the leftover partial line is
appended BEFORE the refill, so a line spanning several 8 KiB chunks is
built up across refills.

**6. Refill read (0x60d4d9b..0x60d4dc7).** `io_status_ =
sfr_.Read(buf_.size(), &result, buf_.data(), rate_limiter_priority)`
-- the call at 0x6048e00 with the hidden 16-byte sret in `rdi` (the
stack slot at `rsp+0x30`), `sfr_` (the embedded
`SequentialFileReader` at `this+0x2000`) in `rsi`, `n = 0x2000` in
`rdx`, the result `Slice` (stack, `rsp+0x20`, initialised to `{"", 0}`
-- the empty-string literal at 0x4376fd, exactly `Slice::clear()`) in
`rcx`, the scratch `buf_.data()` (= `this+0x0`, the first 8192 bytes
of the object) in `r8`, and the priority in `r9d`.
`SequentialFileReader::Read` itself is the #5992 subject (not
census-bound; identified by the call-site signature match and the
`IO_TOTAL` bypass branch in the ReadMore packet); this model scripts
it as an oracle.

**7. Status move (0x60d4dcc..0x60d4e2b).** The sret `IOStatus` is moved
into `io_status_` (`this+0x20a8`): bytes 0-1, 3-4, 5 and 8-15 are
copied (byte 2 and bytes 6-7 are NOT copied -- the move leaves them at
their previous values); the old `state_` pointer is freed with
`operator delete[]` (PLT 0x63f0dc0) and the sret slot is zeroed. The
second `delete[]` at 0x60d4e2b is dead (its argument was just zeroed).

**8. IOSTATS (0x60d4e30..0x60d4e79).** Two calls to the TLS-marker
helper 0x606d9f0 (the same helper the `WritableFileWriter` family
calls at its sync-point sites; it sets a TLS once-flag at `fs-0x400`
and clears the guard byte at `fs-0x3f8+0x98`) bracketing the guarded
counter add: if the guard byte is clear, the TLS bytes-read counter at
`fs-0x3f8+0x10 += result.size()`. This is the expansion of upstream
`IOSTATS_ADD(bytes_read, result.size())`
(`line_file_reader.cc:59`); it runs BEFORE the status check, so a
failed Read still adds its (partial) result size. No sync-point string
is passed at either helper call site, so no upstream sync-point name is
pinned for these calls.

**9. Status check (0x60d4e7d..0x60d4e84).** If `io_status_.code != 0`,
return `false` -- `out` keeps the partial line appended in step 5,
`buf_begin_`/`buf_end_` are NOT updated (the buffered bytes stay where
they were), and the next `ReadLine` call will fail at once at the entry
gate (the error is sticky). Upstream: `MustCheck()`; return `false`
(`line_file_reader.cc:60-63`).

**10. Short-read EOF (0x60d4e8a..0x60d4e98).** If `result.size() !=
0x2000`, `at_eof_ = true` -- upstream calls this "The obscure way of
indicating EOF" (`line_file_reader.cc:64-67`). A full 8192-byte read
does NOT set `at_eof_`, even if it was the last chunk: the next call
refills, reads 0 bytes (OK), and only then learns EOF. Then
`buf_begin_ = result.data()` and `buf_end_ = result.data() +
result.size()` (0x60d4e9f..0x60d4eb5, via `movups`), and the loop
repeats at step 3.

**11. Epilogue (0x60d4f22..0x60d4f40).** Stack-canary check, restore
the six callee-saved registers, return the bool in `eax`. The
length-error path (0x60d4f41..0x60d4f58) checks the canary first, then
throws. There is NO `.cold` landing pad: the FDE has no LSDA, and the
function never throws except through `__throw_length_error` (which
propagates to the caller).

Layout (pinned by the disassembly AND upstream
`file/line_file_reader.h:16-24`, declaration order):

| offset | member | notes |
|---|---|---|
| `+0x0000` | `buf_` (`std::array<char, 8192>`) | the scratch; `sfr_.Read` writes into it (`this+0x0`) and `buf_begin_`/`buf_end_` point into it |
| `+0x2000` | `sfr_` (`SequentialFileReader`, 0xa8 B) | the embedded file reader; its `+0x88..+0x98` holds a `vector<shared_ptr>` (destroyed by the implicit destructor at 0x60cbea0) |
| `+0x20a8` | `io_status_` (`IOStatus`, 16 B) | code at byte 0 (the entry-gate test), subcode at byte 1, `state_` pointer at `+0x8` (freed with `operator delete[]` on the status move) |
| `+0x20b8` | `buf_begin_` (`const char*`) | the next unconsumed byte of `buf_` |
| `+0x20c0` | `buf_end_` (`const char*`) | one past the last valid byte of `buf_` |
| `+0x20c8` | `line_number_` (`size_t`) | lines returned so far; `Parse` reads it per line via `GetLineNumber()` |
| `+0x20d0` | `at_eof_` (`bool`) | set by a short Read (`result.size() != 8192`); `Parse` distinguishes EOF from an error via `GetStatus()` |

The constructor is a forwarding template
(`file/line_file_reader.h:28-30`): it forwards all arguments to the
`SequentialFileReader` ctor and has an empty body; `buf_begin_` and
`buf_end_` start at `buf_.data()` by their default member initialisers,
`line_number_` at 0, `at_eof_` at `false`. There is NO explicit
destructor in the upstream source (implicit default); the census-bound
`_ZN7rocksdb14LineFileReaderD1Ev` at 0x60cbea0 is that implicit
destructor, and its body destroys exactly this layout (it frees
`io_status_.state_` at `+0x20b0` first, then destroys the
`vector<shared_ptr>` at `sfr_+0x88..+0x98`).

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **1 direct call** to ReadLine, 0 tail jumps, 0 LEA refs. The
caller:

| site | caller FDE | caller |
|---|---|---|
| 0x60d0343 | 0x60cfb60..0x60d1354 | `rocksdb::RocksDBOptionsParser::Parse` |

`Parse` constructs the reader on its stack as `LineFileReader
lf_reader(std::move(seq_file), file_name,
config_options.file_readahead_size)` (`options_parser.cc:264-265`) and
loops `while (lf_reader.ReadLine(&line, Env::IO_TOTAL))`
(`options_parser.cc:273`); after the loop it reads the status back with
`lf_reader.GetStatus()` (`options_parser.cc:310`). No other caller
exists in the whole `.text`; the routine is private to the OPTIONS-file
parse loop.

## Evidence

- `tools/line_file_reader_readline115.py` -- the ReadLine model.
- `tests/test_line_file_reader_readline115.py` -- 29 tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600 lines +
  600 chunking + 600 bindings), 0 mismatches on replay
  (`python3 tools/line_file_reader_readline115.py --verify`).
- Live engine check (`--live`): all 9 legs pass -- a plain OPTIONS
  file (5 lines, `line_number_` 5, `iostats_bytes_read` == file size),
  an empty file (first call `false`, status OK, `at_eof_` set), no
  trailing newline (the last partial line is NOT returned, `out` stays
  empty), an unterminated tail spanning two chunks (the call returns
  `false` with the first chunk's 8192 bytes in `out`), a 20000-byte
  line spanning three refills (returned whole), a line of exactly 8192
  bytes + `\n` (found only after its refill), a file ending exactly on
  an 8192-byte boundary (`at_eof_` stays clear on the full read and is
  learned only from the zero-byte refill), a scripted read failure
  (code 5, the partial line kept in `out`, the error sticky, the next
  call leaving `out` untouched), and empty lines + CRLF (empty lines
  return `b""`, `\r` stays in the line); the model output equalled the
  real file bytes split on `\n` after every ReadLine.
- `records.json` -- semantic records only (never a per-instruction
  mnemonic list); `functions.tsv`, `callers.tsv`, `census.json` -- the
  census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags
  only the pre-existing mismatch in unrelated packet
  RE-001-adjacent-last-115 (present on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt`), with
  the repo-relative binary path `work/hl-node-115.bin` (no absolute
  home paths).

## Upstream cross-check

`meta/rocksdb` v8.1.1, read live this cycle
(`file/line_file_reader.h`, `file/line_file_reader.cc`,
`options/options_parser.cc` -- the repo has since moved from
`facebook/rocksdb` to `meta/rocksdb`), confirms the packet step for
step: the class declaration (`buf_` `std::array<char, 8192>`, `sfr_`
`SequentialFileReader`, `io_status_` `IOStatus`, `buf_begin_ =
buf_.data()`, `buf_end_ = buf_.data()`, `line_number_ = 0`, `at_eof_ =
false`, in that order, lines 16-24), the forwarding-template
constructor with an empty body (lines 28-30), `ReadLine` declared at
line 45 with the comment that the line is stored without its delimiter
and `GetStatus()` distinguishes EOF from an I/O error, and the
definition at `line_file_reader.cc:30-71` (the `io_status_` gate, `out
->clear()`, the `for(;;)` loop, `memchr` for `'\n'`, the found arm with
`buf_begin_ += len + 1` and `++line_number_`, the `at_eof_` arm, the
refill with `sfr_.Read(buf_.size(), &result, buf_.data(),
rate_limiter_priority)`, `IOSTATS_ADD(bytes_read, result.size())`, the
failure arm, the short-read `at_eof_` arm, and the `buf_begin_` /
`buf_end_` reset). `Parse` (`options_parser.cc:252-321`) builds the
reader on its stack, loops `while (lf_reader.ReadLine(&line,
Env::IO_TOTAL))` (line 273), uses `GetLineNumber()` per line (line
274), and reads the status back with `lf_reader.GetStatus()` after the
loop (line 310).

Binary-vs-source observations, recorded not hidden:

- `MustCheck()` has no binary call: it is an empty inline in this
  build, compiled out on all three false-return paths (entry gate,
  `at_eof_`, read error).
- The binary's entry gate tests only the code byte at `this+0x20a8`
  (upstream tests `!io_status_.ok()`).
- The binary's `IOSTATS_ADD` expands to two TLS-helper calls
  (0x606d9f0) around a guarded counter add, with no sync-point string
  passed at either site.
- The binary's `IOStatus` move copies bytes 0-1, 3-4, 5 and 8-15 and
  leaves byte 2 and bytes 6-7 untouched; the second `operator delete[]`
  at 0x60d4e2b is dead (its argument was just zeroed).
- There is no explicit destructor in the upstream source (implicit
  default) -- the census-bound 0x60cbea0 is that implicit destructor,
  emitted as a symbol.
- `LineFileReader` is NOT defined in `options_parser.cc` (which only
  includes `file/line_file_reader.h`); the definition is
  `file/line_file_reader.h` and the implementation is
  `file/line_file_reader.cc`.

## Open unknowns (not claimed)

- `SequentialFileReader::Read` (0x6048e00) is scripted as an oracle:
  its record bytes, rate-limiter internals and buffered-path
  `scratch[0]` bump are the #5992 subject, not reimplemented here.
- The TLS IOSTATS counter is modelled as a plain integer: the guard
  byte at `fs-0x3f8+0x98` is cleared by the helper on first use, so the
  add is unconditional in practice; the exact TLS layout (which
  `IOStatsContext` fields the `+0x10` counter and `+0x98` guard byte
  are) is not pinned from this FDE.
- The two TLS-helper calls (0x606d9f0) carry no sync-point string, so
  no upstream sync-point name is pinned for them; they are the
  `IOSTATS_ADD` expansion, not `TEST_SYNC_POINT` calls.
- The `vector<shared_ptr>` at `sfr_+0x88..+0x98` (destroyed by the
  implicit destructor) is not named: its element type is not pinned
  from this FDE.
- The implicit destructor (0x60cbea0) is not modelled: it runs only
  when the reader is destroyed (after `Parse` returns), and no explicit
  destructor exists upstream.
- The next natural follow-ups: `DBImpl::Open` 0x5e62c50..0x5e65462 /
  `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518, the two callers of
  `CreateWAL` found by the #6222 census (both census-bound, 10258 B
  and 7304 B -- large); or the `LineFileReader::Create` factory
  (`file/line_file_reader.cc:14`), which `Parse` does not use.

## Environment limits (stated honestly)

No cargo/rustc/git-lfs/Ghidra on this VM. The binary is read statically
(`work/hl-node-115.bin`); nothing is executed. `SequentialFileReader::
Read` is scripted as an oracle, the TLS IOSTATS counter is a plain
integer, and the implicit destructor is not modelled. `make verify` /
`test` / `catalogue-check` in a tooled environment is still owed
upstream.
