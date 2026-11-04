# Minimal unblocker for validating this reconstruction on current main

Main05bc2de3 expanded the registry to7,886 windows. This hash contribution
adds no registered byte window, but its required catalogue checks recompare
that registry. The unchanged checker read and hashed each complete source file
again for every referring window:6unique source files total5,314,742bytes,
but their window references imply39,471,531,822bytes per pass, excluding the
initial pinned-file pass. The5,207,243byte vendor blob alone is referenced7,574
times. All pinned evidence totals18,084,630bytes.

The current-main refresh hit its600-second limit after native checks and
catalogue generation, before the full validation sequence completed. A later
uncached check was explicitly interrupted at its own process handle after the
source-reference problem was identified. Neither run is reported as a pass.
With two original registry windows, the new regression reproduces3 source
reads where one authenticated snapshot is required. That test fails on the
unmodified checker and passes with the minimal change in tools/byte_progress.py.

The change retains one immutable, SHA-256-validated evidence blob per path
within one load_coverage call, as the checker already does for target images.
Every path remains root-bounded, every whole-file digest is checked before
use, and every window's source extent/body digest, target digest, relocation
qualification and overlap check still runs. A later invocation starts with
an empty snapshot map. The second regression changes a copied source after
one invocation and proves the next rejects its changed digest. Captures are
linked read-only by the fixture and are never its mutation target.

The entire coverage JSON, including7,884 aligned windows and2 unequal-extent
candidates, is byte-identical to the actual uncached output captured before
this change: SHA256787aa8a3160a5069fd7fadce769153882a9d10ed802cf092ead32336682d14f3.
No matching result, denominator, normalization rule or attribution changes.
The snapshot map is local to the invocation; it is not a persistent cache.
This is an active RE validation blocker fix bundled with the hash contribution,
not a separate tooling outcome or additional PR count.

An initial attempted update to the old keepalive packet's supporting-tool
manifest was incorrect: its entry resolves to its retained local checker
snapshot, not the current root helper. The manifest and archived checker were
restored unchanged. The packet-integrity test caught this; its original failure
log is preserved. Only this new packet binds the updated live helper.
