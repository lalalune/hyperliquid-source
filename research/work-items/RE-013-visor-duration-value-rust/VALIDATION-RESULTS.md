# Actual author qualification

The amended author run completed 165 commands: 151 returned zero and 14 input
rejection controls returned the expected exit code 2. Both profiles passed eight
integration tests. All four clean-directory streams matched the independently
frozen 59,159-case expectations exactly. Twenty mutants compiled and emitted
complete value streams in both profiles, and every mutant differed from the
expected values. The run therefore retained 44 full value streams, including the
four clean streams and 40 mutant streams.

Ten comparator controls rejected deliberately wrong streams. Thirteen malformed
input streams and an extra argument were rejected without partial value output;
an empty valid stream emitted no bytes. The post-source static replay passed
67 controls and regenerated 88 outputs. Exact results are retained in
[author/results.json](rust-validation/author/results.json),
[author/commands.json](rust-validation/author/commands.json) and
[author/static-replay.json](rust-validation/author/static-replay.json).

All 330 stdout/stderr references were rehashed against their unmodified raw
bytes; 90 content-addressed command gzip files store those streams. Outer launch
output is retained separately. All six pre-source preparation commands and their
12 raw stream references are retained in
[source-preparation](rust-validation/source-preparation/SCOPE.json).

Across the two clean author directories, both-profile rlibs and the release
client are byte-identical. Debug clients differ. No byte masks or normalization
were applied, and the cause of that difference is not established. The host
build is not a claim of captured-target binary equivalence or complete OS/SDK
hermeticity.

All 88 actual compiled rlib/client entries were rehashed and retained exactly in
private scratch plus a private content-addressed archive. Forty-four contain a
private HOME-path marker. No compiled payload is included in the public packet;
[COMPILED-IDENTITIES.json](rust-validation/author/COMPILED-IDENTITIES.json)
provides hashes and sizes with this explicit availability limit. Public raw
command streams are complete and unredacted. No compiled bytes were stripped,
masked or rebuilt to obtain cosmetic equality.

The initial authorized run failed at command 58 while compiling the third
mutant, because deleting the implicit leading-bit expression left unnecessary
parentheses. Its 116 raw command references, eight completed value streams,
outer output and static replay remain separately frozen. Its 16 compiled
artifact entries are retained privately with public identities. That failure is
neither hidden nor counted as a semantic kill; the subsequent amended run is a
new qualification under a distinct freeze.

The command runner retains streams after `subprocess.run` returns. A timeout or
launch exception before that return would lack its inner command receipt; this
known limitation was not exercised by either actual run. The outer launch
receipts remain separate. Finite host tests and independent mathematical checks
support the source bridge; the all-bit native relation still rests on the
explicit proof and ISA/frame premises. All target evidence comes from one
project/capture lineage.
