"""Export the verbatim objdump excerpts for the
RE-001-basic-stats-factory-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-basic-stats-factory-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Core behaviour: create a Statistics object by name.
    ("host.txt", 0x6077820, 0x60780A0),               # create-by-name entry
    ("register.txt", 0x6075BC0, 0x6075FF5),           # RegisterBuiltinStatistics lambda (once-init)
    ("stats_ctor.txt", 0x6071A00, 0x6071B60),         # StatisticsImpl ctor
    ("creator.txt", 0x6071BA0, 0x6071CCB),            # factory create callback (invoker)
    ("manager.txt", 0x606FA50, 0x606FA7D),            # std::function manager for the lambda
    ("registry_default.txt", 0x61F8B60, 0x61F8D12),   # ObjectLibrary singleton accessor
    ("map_op.txt", 0x5FD1DA0, 0x5FD1FFA),             # unordered_map operator[] ("Statistics")
    ("vector_grow.txt", 0x5FD17C0, 0x5FD1962),        # vector _M_realloc_insert (FactoryEntry*)
    # Ctor callees.
    ("mutex_init.txt", 0x60D50C0, 0x60D5157),         # pthread_mutex_init wrapper
    ("shard_store.txt", 0x60716D0, 0x6071952),        # ticker shard-store construction
    ("options_record.txt", 0x6099CE0, 0x6099E34),     # "StatisticsOptions" record append
    # Destructor reached by the counted-ptr _M_dispose paths.
    ("stats_dtor.txt", 0x6070EA0, 0x607103C),         # StatisticsImpl destructor
    ("stats_dtor_delete.txt", 0x6071040, 0x607105B),  # StatisticsImpl deleting destructor
    # FactoryEntry<Statistics> vtable slots (header 0x64d2e88).
    ("factory_dtor.txt", 0x606FAD0, 0x606FB12),
    ("factory_dtor_delete.txt", 0x606FDA0, 0x606FDEA),
    ("factory_matches.txt", 0x606FB40, 0x606FB4E),
    ("factory_name.txt", 0x606FB50, 0x606FB5E),
    # PatternEntry vtable slots (header 0x64d8ec0) + matcher helper.
    ("pattern_dtor.txt", 0x5FF2030, 0x5FF2145),
    ("pattern_dtor_delete.txt", 0x5FF2150, 0x5FF225F),
    ("pattern_matches.txt", 0x61F8670, 0x61F86F2),
    ("pattern_name.txt", 0x61F8120, 0x61F8129),
    ("match_helper.txt", 0x61F8430, 0x61F8670),
    ("submatch.txt", 0x61F8280, 0x61F842B),
    # _Sp_counted_ptr<StatisticsImpl> vtable slots (header 0x64d2eb8).
    ("counted_impl_dtor.txt", 0x606FAC0, 0x606FAC5),
    ("counted_impl_dtor_delete.txt", 0x606FB80, 0x606FB8E),
    ("counted_impl_dispose.txt", 0x60710B0, 0x60710FB),
    ("counted_impl_destroy.txt", 0x606FB90, 0x606FB9E),
    ("counted_impl_get_deleter.txt", 0x606FB30, 0x606FB37),
    # _Sp_counted_ptr<Statistics> vtable slots (header 0x64d2ef0).
    ("counted_stats_dtor.txt", 0x606FAB0, 0x606FAB5),
    ("counted_stats_dtor_delete.txt", 0x606FB60, 0x606FB6E),
    ("counted_stats_dispose.txt", 0x6071060, 0x60710AB),
    ("counted_stats_destroy.txt", 0x606FB70, 0x606FB7E),
    ("counted_stats_get_deleter.txt", 0x606FB20, 0x606FB27),
    # _Sp_counted_ptr_inplace<ObjectRegistry> vtable slots (header 0x64d8ef0).
    ("inplace_registry_dtor.txt", 0x61F8130, 0x61F8135),
    ("inplace_registry_dtor_delete.txt", 0x61F8140, 0x61F814E),
    ("inplace_registry_dispose.txt", 0x61F8760, 0x61F89DB),
    ("inplace_registry_destroy.txt", 0x61F8170, 0x61F817E),
    ("inplace_registry_get_deleter.txt", 0x61F8180, 0x61F81C7),
    # _Sp_counted_ptr_inplace<ObjectLibrary> vtable slots (header 0x64d00e0).
    ("inplace_library_dtor.txt", 0x5FEFC70, 0x5FEFC75),
    ("inplace_library_dtor_delete.txt", 0x5FEFD00, 0x5FEFD0E),
    ("inplace_library_dispose.txt", 0x5FF7900, 0x5FF7952),
    ("inplace_library_destroy.txt", 0x5FEFD50, 0x5FEFD5E),
    ("inplace_library_get_deleter.txt", 0x5FEFF70, 0x5FEFFB7),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / "excerpts" / name).write_text(text)
        print("wrote excerpts/%s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
