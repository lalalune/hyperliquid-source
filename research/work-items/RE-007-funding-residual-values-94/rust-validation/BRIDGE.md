# Input-only source qualification bridge

`input_client.rs` receives only stdin and has no filesystem/fixture or expected
output access. It maps the immutable PROTOCOL.md fixed-width raw inputs to the
actual public component types. Expected outputs remain in the parent Python
process. The client receives opaque Cdddddd IDs and preserves input order; no
case name, expected value/hash/status or corpus count is passed to it.

All frames are parsed before any result is printed. Version/kind/selection,
fixed-width spans, unique state map/set keys, canonical IDs/hex, trailing bytes,
extra argv and malformed later lines are rejected. Summary duplicates deliberately
reach the actual safe API. State maps are serialized canonically by key. The
complete result includes every represented user field, every position, ARU,
auxiliary and users-with-positions collection; successful output also includes
all72 bytes of every retained record, ordered total and complete winner.

`qualification.py` independently parses full output-frame shape and canonical
state ordering. It checks row count, ID/order and every byte against the pre-code
expected stream. This parser has no implementation of residual arithmetic or
winner/flatten semantics. It refuses short, malformed and partial mutant streams;
only a successful executable producing different complete valid frames counts
as a detected semantic mutation. Frozen case metadata labels each output
as native-conditional or safe-policy;19 mutations must change a native-domain
frame, while3 policy-only mutations must preserve all853 native-domain frames.
Both difference counts are retained for every profile. The unmodified stream is a positive comparator
control, with11 corruptions including a well-formed changed total and full-frame
truncation.26 malformed input transports plus extra argv must exit2 with empty
stdout; empty stdin must succeed with empty stdout. No driver fallback fabricates
an output after panic or malformed input.

The full 912-case corpus includes huge mathematical count-helper frames without
allocating huge vectors. Real application frames are finite and their encoded
u32 counts fit this transport. Qualification transport additionally requires every complete output count to fit
u32 and ordinary available memory for parsing, state and buffered output. Several
individually u32 input record counts can mathematically aggregate aboveu32: such
an otherwise syntactically valid input can fail the client's checked output-count
encoding and exit2 with no output. We do not claim every unbounded syntactically
valid input emits a result frame. The frozen finite corpus has representable
complete output counts; successful host qualification will establish its actual
memory feasibility for that run. This is a client transport envelope, not a new
production/native span policy. Production Vec/usize capacity, native allocator
or arbitrary huge output encodability is not inferred from that finite client.
The operation itself invokes the same checked-count helper after actual checked
length accumulation. Handwritten tests are own-source checks, separate from the
pre-source frozen full-state corpus.

The harness copies the exact real five-file package into fresh build roots; it
does not invent a Cargo workspace or add dependencies. It copies only the frozen
input client, calls the package's public APIs and links its produced rlib. Cargo
metadata must expose exactly one local dependency-free package with lib/test
targets. No captured binary is an executable, library or link input. The separate
static replay reads the pinned capture as bytes using the unchanged verifier.

The new harness adapts MIT orchestration mechanics from our Keccak qualification
harness, explicitly credited in build.py. No pending production source dependency
is introduced. Full approved97-file Rust bin/lib payload identities and symlinks
are checked before and after. Lexical /tmp and canonical /private/tmp ancestors
are both audited; only the known /tmp alias is allowed. Actual Cargo configuration,
ancestor workspace, source symlinks, hooks and complete copied graphs are denied
unless explicitly admitted. HOME is left unchanged; a fresh task Cargo home is
used and inherited compiler/config environment overrides are not forwarded.

Every command is recorded before launch and completed stdout/stderr is retained
raw, compressed deterministically. Timeout and launch failures stop qualification
and keep available partial streams/diagnostics; they cannot create a passing
receipt. First rlib bytes are archived before linking and all first rlib/client
bytes are retained before same-path target deletion. Actual compiled bytes stay
in the private output root, because remapping does not guarantee removal of
private paths. Public metadata gives their exact identities and availability
limit, with no binary masking. Public stdout/stderr are not rewritten; an observed
personal HOME prefix stops the run pending review. Logical command/path mapping
is metadata only and is retained separately in a private map.

Two profiles, a clean same-path repeat and a separate-directory build must match
all frozen values. Same-path artifact byte equality is required and originals
are preserved on failure. Cross-directory raw artifact comparisons are measured
without normalization; inequality is reported without guessing its cause. OS,
dyld, full SDK and target compiler equivalence remain outside the toolchain audit.
