"""Tests for tools/dboptions_log_readahead_size_115.py.

Grounds: DBOptions default ctor 0x60b2db0, the copy ctors and operator=,
ImmutableDBOptions ctor 0x60a3b60, BuildDBOptions 0x60c2e20, the static
initializer 0x60aa2b0, the Configurable ctor 0x60a47f0, the ConfigOptions
ctor 0x60bb890, outer/inner PersistRocksDBOptions 0x60d4a00/0x60d2820,
VerifyRocksDBOptionsFromFile 0x60d13a0 and Parse 0x60cfb60, in
research/work-items/RE-001-dboptions-log-readahead-size-115/.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import dboptions_log_readahead_size_115 as m

N = 0


def check(cond, what):
    global N
    N += 1
    if not cond:
        raise AssertionError(what)


# --- DBOptions defaults (default ctor 0x60b2db0) -------------------------
db = m.DBOptions()
check(db.log_readahead_size == 0, "log_readahead_size default 0")
check(db.log_readahead_size == m.LOG_READAHEAD_SIZE_DEFAULT,
      "default constant 0")
check(m.LOG_READAHEAD_SIZE_OFFSET == 0x220, "DBOptions offset +0x220")
check(db.wal_compression == 0, "wal_compression default 0")
check(db.atomic_flush is False, "atomic_flush default false")
check(db.avoid_unnecessary_blocking_io is False, "avoid default false")
check(db.file_checksum_gen_factory is None, "checksum factory null")
check(db.best_efforts_recovery is False, "best_efforts default false")
check(db.max_bgerror_resume_count == 0x7FFFFFFF, "max_bgerror INT_MAX")
check(db.bgerror_resume_retry_interval == 1000000, "retry interval 1e6")
check(db.allow_data_in_errors is False, "allow_data_in_errors false")
check(db.db_host_id == "__hostname__", "db_host_id __hostname__")
check(db.checksum_handoff_file_types == frozenset(), "checksum handoff empty")
check(db.compaction_service is None, "compaction_service null")
check(db.lowest_used_cache_tier == 1, "lowest tier 1")
check(db.enforce_single_del_contracts is True, "single-del true")
check(db.persist_stats_to_disk is False, "persist_stats_to_disk false")
check(db.enable_thread_tracking is False, "enable_thread_tracking false")
check(db.enable_pipelined_write is False, "enable_pipelined_write false")
check(db.unordered_write is False, "unordered_write false")
check(db.allow_concurrent_memtable_write is False,
      "allow_concurrent_memtable_write false")
check(db.enable_write_thread_adaptive_yield is False,
      "enable_write_thread_adaptive_yield false")

# --- the +0x21b open unknown ---------------------------------------------
check(db.write_dbid_to_manifest is None,
      "+0x21b is never stored by the default ctor")
check(m.NO_READ_SITES_21B is True, "no code reads DBOptions+0x21b")
check(len(m.OPEN_UNKNOWNS) == 4, "four open unknowns recorded")

# --- verbatim copies ------------------------------------------------------
src = m.DBOptions()
src.log_readahead_size = 0x12345678
cpy = src.copy()
check(cpy.log_readahead_size == 0x12345678, "copy ctor carries +0x220")
check(cpy is not src, "copy is a distinct object")
cpy.log_readahead_size = 0
check(src.log_readahead_size == 0x12345678, "copy is independent")
check(cpy.max_bgerror_resume_count == 0x7FFFFFFF, "copy carries tail")
check(cpy.db_host_id == "__hostname__", "copy carries db_host_id")

opts = m.Options(src)
from_opts = m.DBOptions.from_options(opts)
check(from_opts.log_readahead_size == 0x12345678,
      "Options ctor carries +0x220")
check(from_opts is not src, "Options ctor makes a distinct DBOptions")

dst = m.DBOptions()
dst.assign(src)
check(dst.log_readahead_size == 0x12345678, "operator= carries +0x220")
dst.log_readahead_size = 0
check(src.log_readahead_size == 0x12345678, "operator= copy is independent")

# A default (zero) field copies as zero, not as a stale value.
check(m.DBOptions().copy().log_readahead_size == 0, "zero copies as zero")

# --- ImmutableDBOptions compaction ----------------------------------------
imm = m.ImmutableDBOptions(src)
check(imm.log_readahead_size == 0x12345678, "immutable +0x1a0 from +0x220")
check(m.LOG_READAHEAD_SIZE_IMMUTABLE_OFFSET == 0x1A0,
      "ImmutableDBOptions offset +0x1a0")
check(imm.best_efforts_recovery is False, "immutable best_efforts false")
check(imm.max_bgerror_resume_count == 0x7FFFFFFF, "immutable max_bgerror")
check(imm.bgerror_resume_retry_interval == 1000000, "immutable interval")
check(imm.allow_data_in_errors is False, "immutable allow_data false")
check(imm.db_host_id == "__hostname__", "immutable db_host_id")
check(imm.checksum_handoff_file_types == frozenset(), "immutable handoff")
check(imm.compaction_service is None, "immutable compaction_service null")
check(imm.lowest_used_cache_tier == 1, "immutable lowest tier")
check(imm.enforce_single_del_contracts is True, "immutable single-del")
check(imm.pack_197 == (0, False, False, False), "pack +0x197 defaults")
check(imm.pack_158 == (False, False, False, False), "pack +0x158 defaults")
check(imm.pack_15c is False, "pack +0x15c default")

# The pack groups follow their source fields.
src2 = m.DBOptions()
src2.atomic_flush = True
src2.persist_stats_to_disk = True
src2.enable_pipelined_write = True
src2.enable_write_thread_adaptive_yield = True
imm2 = m.ImmutableDBOptions(src2)
check(imm2.pack_197 == (0, True, True, False), "pack +0x197 follows source")
check(imm2.pack_158 == (False, True, False, False),
      "pack +0x158 follows source")
check(imm2.pack_15c is True, "pack +0x15c follows source")

# ImmutableDBOptions copy ctor: +0x1a0 -> +0x1a0 verbatim.
imm3 = imm.copy()
check(imm3.log_readahead_size == 0x12345678, "immutable copy carries +0x1a0")
check(imm3 is not imm, "immutable copy is distinct")
imm3.log_readahead_size = 0
check(imm.log_readahead_size == 0x12345678, "immutable copy independent")

# Default DBOptions compacts to a default ImmutableDBOptions.
check(m.ImmutableDBOptions().log_readahead_size == 0,
      "default compacts to 0")

# --- BuildDBOptions (reverse direction) -----------------------------------
built = m.build_db_options(imm, m.MutableDBOptions(max_open_files=1000))
check(built.log_readahead_size == 0x12345678,
      "BuildDBOptions +0x1a0 -> +0x220")
check(built.max_open_files == 1000,
      "BuildDBOptions max_open_files comes from MutableDBOptions")
built2 = m.build_db_options(m.ImmutableDBOptions(), m.MutableDBOptions())
check(built2.log_readahead_size == 0, "BuildDBOptions default 0")
check(built2.max_open_files == -1, "MutableDBOptions max_open_files -1")

# --- ConfigOptions defaults ----------------------------------------------
cfg = m.ConfigOptions()
check(cfg.sanity_level == 0xFF, "sanity_level 0xff")
check(cfg.file_readahead_size == 0x80000, "file_readahead_size 0x80000")
check(cfg.file_readahead_size == 524288, "file_readahead_size decimal")
check(cfg.delimiter == ";", "delimiter default ';'")
check(cfg.invoke_prepare_options is True, "invoke_prepare_options default 1")
check(m.CONFIGOPTIONS_SIZE_BYTES == 0x50, "ConfigOptions size 0x50")
check(m.PERSIST_DELIMITER == "\n  ", "persist delimiter newline+2 spaces")

# --- Persist bridge --------------------------------------------------------
cfg0 = m.persist_outer(m.DBOptions())
check(cfg0.file_readahead_size == 0x80000,
      "Persist keeps the 0x80000 default when log_readahead_size is 0")
check(cfg0.delimiter == "\n  ", "Persist sets delimiter")
check(cfg0.invoke_prepare_options is False, "Persist clears +0x03")

for value in (1, 0x80000, 0x100000, 2 ** 40, 2 ** 64 - 1):
    d = m.DBOptions()
    d.log_readahead_size = value
    c = m.persist_outer(d)
    check(c.file_readahead_size == value,
          "Persist overwrites +0x30 with %r" % value)

# The bridge fires on any nonzero value, even one equal to the default.
d = m.DBOptions()
d.log_readahead_size = 0x80000
check(m.persist_outer(d).file_readahead_size == 0x80000,
      "bridge overwrites even when equal to the default")

# --- Parse / Verify round trip --------------------------------------------
for value in (0, 1, 0x80000, 0x12345678, 2 ** 40):
    d = m.DBOptions()
    d.log_readahead_size = value
    back = m.persist_round_trip(d)
    check(back.log_readahead_size == value, "round trip %r" % value)

# The 4-arg Parse overload stores its file_readahead_size argument into
# ConfigOptions+0x30 without changing what is parsed.
cfg2 = m.ConfigOptions()
lines, _c = m.persist_inner(cfg2, m.DBOptions())
parsed = m.parse_options_file(cfg2, lines, file_readahead_size=0x4000)
check(cfg2.file_readahead_size == 0x4000, "Parse overload sets +0x30")
check(parsed.log_readahead_size == 0, "Parse reads the persisted value")

# A readahead size of 0 in the overload leaves +0x30 untouched.
cfg3 = m.ConfigOptions()
m.parse_options_file(cfg3, lines, file_readahead_size=0)
check(cfg3.file_readahead_size == 0x80000, "Parse overload keeps +0x30 on 0")

# --- corruption controls ----------------------------------------------------
bad_lines = ["[DBOptions]", "  log_readahead_size=7", "not a statement"]
try:
    m.parse_options_file(m.ConfigOptions(), bad_lines)
    raise AssertionError("non-statement line accepted")
except ValueError:
    pass

tampered = ["[DBOptions]", "  log_readahead_size=9"]
d = m.DBOptions()
d.log_readahead_size = 8
try:
    m.verify_from_file(m.persist_outer(d), d, tampered)
    raise AssertionError("tampered value verified")
except ValueError:
    pass

# A truncated file (no log_readahead_size line) parses to the default 0,
# which fails verification against a nonzero DBOptions.
try:
    m.verify_from_file(m.persist_outer(d), d, ["[DBOptions]"])
    raise AssertionError("truncated file verified")
except ValueError:
    pass

# --- OptionTypeInfo map ------------------------------------------------------
check(m.option_type_info_offset("log_readahead_size") == 0x1A0,
      "map: log_readahead_size -> 0x1a0")
check(m.option_type_info_offset("best_efforts_recovery") == 0x1B8,
      "map: best_efforts_recovery -> 0x1b8")
check(m.option_type_info_offset("max_bgerror_resume_count") == 0x1BC,
      "map: max_bgerror_resume_count -> 0x1bc")
check(m.option_type_info_offset("avoid_unnecessary_blocking_io") == 0x198,
      "map: avoid -> 0x198 (observed; see open unknowns)")
check(m.option_type_info_offset("write_dbid_to_manifest") == 0x19A,
      "map: write_dbid -> 0x19a (observed; see open unknowns)")
check(m.option_type_info_offset("max_open_files") == 0x40,
      "map: max_open_files -> 0x40 (observed; see open unknowns)")
check(len(m.OPTION_TYPE_INFO) == 6, "six map entries pinned")
try:
    m.option_type_info_offset("file_readahead_size")
    raise AssertionError("ConfigOptions field has a map entry")
except KeyError:
    pass
try:
    m.option_type_info_offset("no_such_field")
    raise AssertionError("unknown name accepted")
except KeyError:
    pass

# --- Configurable embeds -----------------------------------------------------
conf = m.DBOptionsConfigurable(src)
check(conf.db_options.log_readahead_size == 0x12345678,
      "Configurable embeds a DBOptions copy (+0x2d8)")
check(conf.db_options is not src, "Configurable copy is distinct")
check(conf.immutable.log_readahead_size == 0x12345678,
      "Configurable embeds an ImmutableDBOptions (+0x98)")
check(m.CONFIGURABLE_DBOFFSET == 0x2D8, "Configurable DBOptions +0x2d8")
check(m.CONFIGURABLE_IMMUTABLE_OFFSET == 0x98, "Configurable Immutable +0x98")
conf.db_options.log_readahead_size = 0
check(src.log_readahead_size == 0x12345678,
      "Configurable embed is independent of the input")

print("%d tests passed" % N)
