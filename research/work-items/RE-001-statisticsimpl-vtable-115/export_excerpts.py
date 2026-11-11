"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-statisticsimpl-vtable-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.

Re-shipped excerpts are regenerated here from the binary, so the
bytes are identical to the excerpts the source packets shipped;
verify.py regenerates every excerpt fresh and requires
byte-equality, which subsumes the re-ship check. Sources:
- RE-001-systemclock-wrapper-vtable-115 (#3902): the 11 shared
  Configurable/Customizable base slots.
- RE-001-stats-write-side-115 (#3396): the write side, the dtors,
  the name/delegate/hist-id stubs, the ctor and the helpers.
- RE-001-locked-ticker-read-115 (#3392): the three locked reads,
  their cleanups, the ticker getter, the histogram builder and
  the mutex wrappers.
- RE-001-stats-produce-115 (#3362): ToString 0x6070810 (its
  main.txt, renamed here to tostring.txt).
- RE-001-stats-ticker-map-115 (#3378): the slot-0xf0 fill.
New in this packet: the deleting dtor 0x6071040, the slot-0xc8
forwarder 0x5d48960, the base PrepareOptions 0x6095e70 and
SerializeOptions 0x609de80, IsInstanceOf 0x5d2e770 and the
empty-string slot 0x5d2ca10.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    # The 32 vtable slots, in slot order.
    ("stats_dtor.txt", "0x6070ea0", "0x607103c"),  # slot 0x00 D1
    ("deleting-dtor-6071040.objdump.txt", "0x6071040", "0x607105b"),  # slot 0x08 D0
    ("getoption-609d760.objdump.txt", "0x609d760", "0x609d954"),  # slot 0x10
    ("areequivalent-609dc40.objdump.txt", "0x609dc40", "0x609de39"),  # slot 0x18
    ("slot04-emptystring-5d32560.objdump.txt", "0x5d32560", "0x5d3257b"),  # slot 0x20
    ("prepareoptions-base-6095e70.objdump.txt", "0x6095e70", "0x609661c"),  # slot 0x28
    ("validateoptions-6096790.objdump.txt", "0x6096790", "0x6096f0c"),  # slot 0x30
    ("getoptionsptr-5d2e090.objdump.txt", "0x5d2e090", "0x5d2e0de"),  # slot 0x38
    ("slot08-emptystatus-60956f0.objdump.txt", "0x60956f0", "0x609570c"),  # slot 0x40
    ("configureoptions-609d0e0.objdump.txt", "0x609d0e0", "0x609d75e"),  # slot 0x48
    ("parseoption-60986b0.objdump.txt", "0x60986b0", "0x6098a9c"),  # slot 0x50
    ("optionsareequal-6095710.objdump.txt", "0x6095710", "0x609579a"),  # slot 0x58
    ("serializeoptions-base-609de80.objdump.txt", "0x609de80", "0x609e29e"),  # slot 0x60
    ("getoptionname-609d980.objdump.txt", "0x609d980", "0x609dc18"),  # slot 0x68
    ("stats_name.txt", "0x606fa20", "0x606fa2c"),  # slot 0x70 Name
    ("getid-5d32a30.objdump.txt", "0x5d32a30", "0x5d32a51"),  # slot 0x78 GetId
    ("isinstanceof-5d2e770.objdump.txt", "0x5d2e770", "0x5d2e832"),  # slot 0x80
    ("delegate_getter.txt", "0x606fa30", "0x606fa39"),  # slot 0x88 delegate
    ("slot18-emptystring-5d2ca10.objdump.txt", "0x5d2ca10", "0x5d2ca1c"),  # slot 0x90
    ("locked_ticker.txt", "0x6070490", "0x60704d2"),  # slot 0x98
    ("locked_percentiles.txt", "0x6070610", "0x60706c9"),  # slot 0xa0
    ("locked_histogram_text.txt", "0x6070700", "0x60707c1"),  # slot 0xa8
    ("record_tick.txt", "0x606fba0", "0x606fc59"),  # slot 0xb0
    ("set_ticker.txt", "0x6070dc0", "0x6070e9a"),  # slot 0xb8
    ("get_reset_ticker.txt", "0x6070c50", "0x6070d92"),  # slot 0xc0
    ("slot-c8-forwarder-5d48960.objdump.txt", "0x5d48960", "0x5d48979"),  # slot 0xc8
    ("record_hist_devirt.txt", "0x606ffd0", "0x60700c4"),  # slot 0xd0
    ("record_hist.txt", "0x606fef0", "0x606ffce"),  # slot 0xd8
    ("reset_stats.txt", "0x6070b30", "0x6070c2a"),  # slot 0xe0
    ("tostring.txt", "0x6070810", "0x6070ab5"),  # slot 0xe8
    ("slotf0.txt", "0x6076030", "0x6076615"),  # slot 0xf0
    ("hist_id_check.txt", "0x606fa40", "0x606fa4b"),  # slot 0xf8
    # Helpers and the installer.
    ("stats_ctor.txt", "0x6071a00", "0x6071b60"),  # ctor, installs the vtable
    ("set_core.txt", "0x6070ac0", "0x6070b1b"),  # unlocked set core
    ("cpu_shard_pick.txt", "0x60d5cd0", "0x60d5cf0"),  # CPUID picker
    ("lcg_seed.txt", "0x61c4080", "0x61c4117"),  # thread-local LCG seed
    ("mutex_lock.txt", "0x60d5230", "0x60d52c5"),  # mutex lock
    ("mutex_unlock.txt", "0x60d52f0", "0x60d5385"),  # mutex unlock
    ("ticker_getter.txt", "0x6070430", "0x607047d"),  # ticker shard-sum getter
    ("histogram_builder.txt", "0x6070500", "0x60705d8"),  # histogram builder
    ("hist_record.txt", "0x606b130", "0x606b1b3"),  # HistogramImpl record
    ("hist_record_thunk.txt", "0x606b1c0", "0x606b1cd"),  # outer record entry
    ("hist_locked_init.txt", "0x606b0c0", "0x606b10a"),  # HistogramImpl locked init
    ("hist_bucket_index.txt", "0x606afa0", "0x606b013"),  # bucket lower_bound
    ("hist_shared_init.txt", "0x606b020", "0x606b07c"),  # shared record init
    ("boundary_gen.txt", "0x606bf10", "0x606c134"),  # boundary generator
    ("landing_pad.txt", "0x607047e", "0x607048e"),  # locked-read cleanup
    ("cleanup_a0.txt", "0x60705d8", "0x607060c"),  # percentiles cleanup
    ("cleanup_a8.txt", "0x60706ca", "0x60706fe"),  # histogram-text cleanup
    ("set_cleanup.txt", "0x6070d92", "0x6070db2"),  # set-ticker cleanup
    ("reset_cleanup.txt", "0x6070b1c", "0x6070b2e"),  # reset cleanup
    ("reset_cleanup2.txt", "0x6070c2a", "0x6070c4a"),  # reset cleanup 2
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0075bb90 ", "00369974 ", "0036b19c ", "0075dd6c ", "00346504 ",
    "0075d434 ", "0075d4ac ", "00345764 ", "0036ae98 ", "0075dc7c ",
    "0075d728 ", "0036aeac ", "0075ddf8 ", "0075dcf4 ", "0036962c ",
    "003465c4 ", "003458ac ", "00369640 ", "00344b98 ", "0075b824 ",
    "0075b8e8 ", "0075b948 ", "00369758 ", "0075bb1c ", "0075bab4 ",
    "003485c0 ", "003698b8 ", "00369870 ", "0075ba40 ", "0075b9a8 ",
    "0075be80 ", "00369654 ", "0075bce8 ", "00369960 ", "0036ca90 ",
    "0076c098 ", "007607a4 ", "007607f0 ", "0036994c ", "0075b874 ",
    "00368f08 ", "00368f34 ", "0075b284 ", "00368ea4 ", "00368eb8 ",
    "0075b3bc ", "0075b854 ", "0075b928 ", "0075b988 ", "0075bb70 ",
    "0075ba90 ", "0075baf8 ",
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + start, "--stop-address=" + stop,
             "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name, len(out.splitlines()), "lines")
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = []
    for prefix in FRAME_PREFIXES:
        block = []
        in_block = False
        for line in frames.splitlines():
            if line.startswith(prefix):
                in_block = True
            elif in_block and line == "":
                break
            if in_block:
                block.append(line)
        blocks.extend(block)
        blocks.append("")
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n".join(blocks))
    print("wrote frames.txt", len(blocks), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
