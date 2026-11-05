# RE-012: node115 startup line-count command and result boundary

Component **node-runtime**; static research, no gate change. Target is Linux
x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes. Source/reference base is
`05bc2de303c05525b71e7e257426e741bc66a390`. Coordinates below are ELF virtual
addresses before load bias.

The [startup selector packet](../RE-001-node115-startup-file-height-composition/README.md)
left `0x1500e50` as an opaque supplied count. This packet resolves its command
construction and the status, UTF-8, whitespace-token and unsigned-decimal result
boundary. It also follows the previously opaque argument transform rather than
treating the joined path as an unquoted shell argument. The actual process,
allocator and error-object implementations remain explicit boundaries.

## Evidence and bounds

`spec.json` fixes the selected extents, native-byte obligations, data and RELA
bindings. `native/*.gnu.txt` retains complete GNU exports of those extents.
`fdes.readelf.txt` retains independently obtained GNU FDE headers. `records.json`
rederives byte hashes, instruction denominators, Python FDE/CIE records, raw
unwind records, LSDA call-site tables, selected direct/slot edges and the contract
bindings from the authenticated ELF. `native-provenance.json` preserves native
options and original/retained export hashes. Only the machine-local filename in
each file-format header is replaced; **no instruction operand or byte is masked**.
The independent GNU headers are checked for FDE offset/length, CIE pointer and
range, rather than accepting an equal PC range alone. Separator, process literals,
UTF-8 table and the caller's `.lz4` load are also derived from actual RIP displacements.

| Extent, end exclusive | Role in this question | Bytes |
| --- | --- | ---: |
| `0x1500e50..0x150128b` | supplied-view to count/error | 1083 |
| `0x15b0450..0x15b0625` | collect transformed arguments and join | 469 |
| `0x1541040..0x154130a` | view iteration, empty filtering and transform dispatch | 714 |
| `0x150d100..0x150d32b` | one-byte separator join | 555 |
| `0x5c67050..0x5c67554` | argument quoting/NUL rejection | 1284 |
| `0x1536720..0x1536a01` | command/result wrapper | 737 |
| `0x16815e0..0x16817d7` | UTF-8 validation | 503 |
| `0x150caf0..0x150cd87` | two-sided Unicode whitespace trim | 663 |
| `0x14cca10..0x14cca2f` | argument-failure carrier boundary | 31 |
| `0x14ccb10..0x14ccb39` | numeric-failure carrier boundary | 41 |
| `0x150d950..0x150d98a` | no-token formatting/error boundary | 58 |
| `0x1536a10..0x1536a83` | command-error boundary | 115 |
| `0x635de30..0x635ded5` | observed release dispatch, not allocator closure | 165 |
| `0x5c87d50..0x5c87f6c` | conditional suffix/state detour, not callback closure | 540 |

These **14 selected FDE extents / 6,958 bytes** are a static evidence denominator,
not reconstructed source coverage. The existing selector extent
`0x595b520..0x595bc3a` (1,818 bytes) is separately marked **reused context**. Its
export is independently checked against this target; it earns no new caller or
implementation credit. There are zero compiled-source comparisons, no Rust
implementation in this packet, and no change to any of the 92 acceptance gates.

## Observed command path

The normal-memory analysis assumes readable, valid UTF-8 input string views and
ordinary successful allocation. No original Rust type or stable `Result` ABI is
assigned to the observed registers/sentinel words.

1. `0x1500e89..0x1500edb` constructs three 16-byte pointer/length views:
   `"wc"` at `0x4659f2`, `"-l"` at `0x4659f4`, and the **original supplied view**.
   The collector receives the array begin/end, with a reference to a false flag.
   RCX is the array end, not an extra path-context argument.
2. `0x1541040` calls `0x150caf0` to test each view's trimmed length. It skips
   whitespace-only views, but transforms the **untrimmed original view** at
   `0x15410dd` through slot `0x64e0a60`, RELA type8/addend `0x5c67050`.
3. The transform rejects NUL for this false-flag caller. Its empty-view result
   is the borrowed literal `''` at `0x94725e`; that case is filtered earlier on
   this caller path. It may return a borrowed or owned view. First-word
   `0x8000000000000001` sets the collector's failure byte. The provider cleans
   intermediates and returns sentinel `0x8000000000000000` on failure.
4. `0x150d100`, reached by the provider, joins retained transformed views with
   the actual single byte **space**, `0x20` at `0x468cca`. An empty/whitespace-only
   third view therefore leaves `wc -l`. There is no inserted `--` argument.
5. The helper calls slot `0x64e0960` -> `0x1536720`. That wrapper supplies fixed
   `/bin/sh` (`0x466adc`, 7 bytes), `-c` (`0x466ada`, 2 bytes), and the joined
   command through slots `0x64e0ee0/ee8/ef0`, whose RELA targets are respectively
   `0x5c94cb0`, `0x5c94bb0`, `0x5c98260`. Those process-adapter bodies are **not
   recovered here**. Static construction does not prove a particular filesystem,
   environment, stdin, shell implementation or `wc` version/result.

The quoting transform scans byte segments with flags 1=unquoted, 2=single-quoted,
4=double-quoted, in that priority. The two unquoted ASCII membership masks at
`0x5c67122/12f` are `0x07fffffea7ffffff` (bytes64..127) and
`0x07ffe80000000000` (bytes0..63). Non-ASCII clears the unquoted flag. `!`, `$`,
and backtick clear double-quoted mode; apostrophe and backslash clear
single-quoted mode; caret clears both quoted modes. A leading caret instead
initializes flags2 and starts classification at byte1, retaining that caret.
If the next byte would clear every mode, the segment ends **before** it. Segments
are concatenated without spaces. Double-quoted segments prefix backslash before
double quote, dollar, backslash and backtick (`0x4400000000000005` mask at
`0x5c67339`). This describes observed byte construction, not a shell-safety proof.

Manual examples under these premises: `a b` -> `wc -l 'a b'`; ` file ` retains
both spaces inside quotes; `a'b` uses double quotes; `a^b` becomes `a'^b'`.
The static projection in `relations.py` runs no command. Its tests are explanatory
witnesses, **not differential observations of the captured target**.

## Observed result and decimal path

The command wrapper propagates its sentinel failure through `0x1536a10`.
Otherwise it first checks DWORD `[rsp+0x50]` at `0x1536823`: a nonzero status
word takes the formatted error path. The exact OS status encoding remains at
the process-adapter boundary. With zero status it validates the stdout view
through slot `0x64dfca8` -> `0x16815e0`. Invalid UTF-8 takes an error-carrier
route before token parsing, including when invalid bytes follow an otherwise
valid first numeric token. The observed zero-status route does not separately
reject nonempty stderr; it releases those buffers. It trims valid stdout via
`0x150caf0`, then copies that trimmed view into the returned owned buffer.

The UTF-8 checker has no calls. Its lead-byte table at `0x46ebe7` assigns width1
to bytes00..7f, 0 to80..c1, 2 toc2..df, 3 toe0..ef, 4 tof0..f4 and 0 tof5..ff.
The complete export contains continuation, short-input, E0/ED/F0/F4 and scalar
range checks. Its error record contains a valid-prefix length and an optional
error length; this packet does not assign an original source struct layout or
claim allocator/error-conversion closure from that record.

The main helper's inlined scan selects the first nonempty whitespace-delimited
span. Its exact 25-codepoint whitespace set, also used by the trim helper, is:
U+0009..000D, 0020, 0085, 00A0, 1680, 2000..200A, 2028, 2029, 202F, 205F, 3000.
This is derived from the ASCII mask at `0x1500f46`, page dispatch, and the
256-byte table at `0x479266` via slot `0x64dfc30`. Python `str.isspace()/split()`
also treat U+001C..001F as whitespace and would silently change this contract.
No span takes the error route at `0x1501175`; the retained format prefix at
`0x442df6` contains `file_n_lines empty wc output `, with the original view
supplied to its formatter. Exact allocated error objects remain opaque.

The selected span accepts one leading `+`, leading zeros and ASCII decimal
digits. Sign-only input and negatives take numeric code1. A post-plus length
below17 uses the short unchecked loop (at most16 decimal digits); longer spans
use unsigned multiply-by10 and add with overflow checks. No saturation occurs
inside this helper. Numeric error codes are passed to `0x14ccb10` and must not
be confused with the final pointer/carrier returned by that wrapper.

| Manual byte witness | Observed-branch relation |
| --- | --- |
| `+00042` | success42 |
| `18446744073709551615` | success, u64 maximum |
| `18446744073709551616` | addition overflow, numeric code2 |
| `1844674407370955162x` | multiplication overflows but current `x` classifies as nondigit: code1 |
| `18446744073709551620` | same overflowing multiplication with a digit: code2 |
| `18446744073709551616x` | addition overflow occurs before reaching `x`: code2 |
| stdout `7 9999999999999999999999999` | only first token parsed: success7 |

The multiply-overflow edge `0x15011bd` reaches `0x1501212`, classifies the
current byte and selects code1/2. Addition carry after an accepted digit at
`0x15011cc` immediately selects2. Simplifying this to unconditional
overflow-before-digit validation would lose the first distinction.

Normal returns set full EAX=0 and RDX=count. The observed failure paths set full
EAX=1 and RDX=an **opaque error carrier**, including command and argument errors.
Owned output is released through slot `0x64df4a0` -> `0x635de30` when its capacity
word is nonzero. That release dispatcher has a TLS fast path and a tail fallback;
it does not establish the complete allocator's identity or behavior.

## Caller, suffix detour and unwind limits

The credited selector skips exact `.lz4` suffixes before selecting a view.
Its actual count call at `0x595bb9c` is `ff15b64db800`, reaching slot
**`0x64e0958`**, whose RELA addend is `0x1500e50`. It tests returned AL bit0;
the normal path adds the count to the prior parsed filename number with unsigned
saturation at `0x595bba9..0x595bbbb`. That saturation belongs to the caller,
not to decimal conversion. The selector's broader filesystem/tree/path-component
contracts remain at the earlier packet's declared boundaries.

For other callers, a view of length>=4 ending in exact `.lz4` and nonzero DWORD
at `0x64f01d8` detours through slot `0x64df9f0` -> `0x5c87d50`, then rejoins
command construction. Initial file data at that word is3. The state object,
metadata and their selected RELA bindings are retained, but callback effects,
concurrency and runtime mutations of this global are **unresolved**. The selected
startup caller excludes this branch; no generic all-caller helper closure is
claimed. Data/source-location candidates are observations, not proof of source
ownership or original names.

Raw CIE/FDE and LSDA header/call-site bytes are retained for every selected
extent that has them. For the primary body the no-token formatter and numeric
error-wrapper protected ranges land at `0x150126d`, conditionally release the
owned output and call `0x63f0a50`. Its actual FF25 PLT/GOT writer resolves to
dynamic symbol `_Unwind_Resume`. LSDA action/type chains, cleanup implementations,
OOM/diagnostic termination and arbitrary callee unwinding are not interpreted.
Edges in `records.json` cover E8/E9 and RIP-relative FF15/FF25 only; arbitrary
register/vtable targets, runtime reachability and whole-program xrefs are not
claimed. Complete FDE exports do not imply semantic recovery of every callee.

## Reproduction and validation

From the repository root, with authenticated artifact inputs materialized:

```sh
python3 research/work-items/RE-012-node115-startup-line-count/verify.py
python3 -m unittest discover -s tests -p test_node115_startup_line_count.py -v
make doctor
make verify test catalogue-check index reproduce
```

`verify.py` uses only Python's standard library and existing repository MIT
parsers (`elf_index`, `fde_extents`, `foundation_millis.decode_export`,
`node115_cli_command_factory.lsda_table`). It authenticates the target before
creating output. `--write-records` deliberately regenerates the deterministic
static snapshot; ordinary invocation compares it. Native tools need not be
installed merely to check the retained exports. To obtain fresh exports use
GNU objdump with `-d -w -M intel --insn-width=16 --start-address=<start>
--stop-address=<end> artifacts/node/115/hl-node`, and GNU readelf
`-wf` on the same artifact. The original collection used
GNU binutils2.47, Python3.10.11 and independent Capstone5.0.7. Selected GNU
headers were taken from the candidate's authenticated full-stream cache rather
than repeatedly scanning the same full native frame dump.

The focused tests include complete snapshot checks and controls for wrong target
before output, instruction/branch/immediate mutations, literal/table mutations,
RELA targets, FDE range/duplicate changes, and gapped/duplicated/truncated/changed
native exports. Inner semantic/data/RELA/FDE controls deliberately call the
individual guard without the outer target/body hash shortcut. Manual relations
cover signs, leading zeros, exact overflow precedence, all25 whitespace points,
the four Python counterexamples, UTF-8/status precedence, quoting and original
path preservation. These do not constitute target execution or Rust equivalence.

Local command outcomes and platform limitations are recorded in `validation.json`.
The bounded local `make test` attempt reached file33/584 before owner cancellation
after unchanged Windows failures:17 CRLF golden-output failures in
`test_abci_state_export115.py` and4 symlink privilege errors (WinError1314) in
`test_accept4_source115.py`. `full-test.log` retains the output with only local
path prefixes sanitized; the original raw log hash is recorded. The full suite
is **failed and incomplete**, not passed. The three opt-in captured-instruction
evaluation classes were not enabled. Hosted Linux CI/container results are not
claimed. Final submitted-head outcomes are reported in the PR/handoff; the
earlier phase records remain historical results, not a final-head substitute.
No captured process, shell command, network node, live dataset, instruction
evaluator or emulator was executed. A future process comparison would require
separate authorization and a declared isolated harness. The next engineering
question is the three process-adapter bodies and their output/status ownership
contract; independent Rust reconstruction should preserve the established
argument/result/error ordering while keeping those unresolved dependencies visible.

New code and prose use MIT. This work credits the existing selector packet for
caller discovery and the repository's licensed static parsers; it does not copy
unlicensed inferred source or infer #115 behavior from an older node release.
Historical PR#468 supplied a node94 discovery lead, not a #115 behavior oracle.
