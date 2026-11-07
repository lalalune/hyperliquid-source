"""Python model of node #115 DBOptions+0x220 = log_readahead_size.

Pinned by research/work-items/RE-001-dboptions-log-readahead-size-115/:
  - DBOptions::DBOptions() 0x60b2db0..0x60b3154 (default ctor)
  - DBOptions::DBOptions(const DBOptions&) 0x5d38750..0x5d38da5
  - DBOptions::DBOptions(const Options&) 0x60b3280..0x60b3b87
  - DBOptions::operator= 0x60c3480..0x60c3af4
  - ImmutableDBOptions::ImmutableDBOptions(const DBOptions&) 0x60a3b60..0x60a4363
  - ImmutableDBOptions copy ctor 0x5da6bc0..0x5da7600
  - BuildDBOptions 0x60c2e20..0x60c3477
  - __static_initialization_and_destruction_0v 0x60aa2b0..0x60b1d78
    (the DBOptions OptionTypeInfo name -> offset map)
  - DBOptionsConfigurable ctor 0x60a47f0..0x60a636b
  - ConfigOptions::ConfigOptions() 0x60bb890..0x60bb932
  - PersistRocksDBOptions (outer) 0x60d4a00..0x60d4b7e
  - PersistRocksDBOptions (inner) 0x60d2820..0x60d49d3
  - RocksDBOptionsParser::VerifyRocksDBOptionsFromFile 0x60d13a0..0x60d24ea
  - RocksDBOptionsParser::Parse 0x60cfb60..0x60d1354

The field: DBOptions+0x220, size_t, default 0, is
rocksdb::DBOptions::log_readahead_size (v8.1.1 include/rocksdb/options.h
L2389-2399): "The number of bytes to prefetch when reading the log...
If 0, then the prefetching is disabled."

Layout pinned for the DBOptions tail (+0x210..+0x290), defaults from the
default ctor, names from the v8.1.1 header in declaration order:
  +0x218  wal_compression (1 byte, 0 = kNoCompression)
  +0x219  atomic_flush (bool, false)
  +0x21a  avoid_unnecessary_blocking_io (bool, false)
  +0x21b  write_dbid_to_manifest (bool, false per header) -- OPEN UNKNOWN:
          the default ctor never stores it and no code in the binary reads
          DBOptions+0x21b, so it is modelled as unwritten/unread.
  +0x220  log_readahead_size (size_t, 0)
  +0x228  file_checksum_gen_factory (shared_ptr, null)
  +0x238  best_efforts_recovery (bool, false)
  +0x23c  max_bgerror_resume_count (int, INT_MAX)
  +0x240  bgerror_resume_retry_interval (u64, 1000000)
  +0x248  allow_data_in_errors (bool, false)
  +0x250  db_host_id (std::string, "__hostname__")
  +0x270  checksum_handoff_file_types (FileTypeSet, empty)
  +0x278  compaction_service (shared_ptr, null)
  +0x288  lowest_used_cache_tier (u8, 1 = kNonVolatileBlockTier)
  +0x289  enforce_single_del_contracts (bool, true)

ImmutableDBOptions compacts the tail (the ctor copies DBOptions+0x220 to
ImmutableDBOptions+0x1a0):
  +0x1a0  log_readahead_size (from DBOptions+0x220)
  +0x1b8  best_efforts_recovery (from DBOptions+0x238)
  +0x1bc  max_bgerror_resume_count (from DBOptions+0x23c)
  +0x1c0  bgerror_resume_retry_interval (from DBOptions+0x240)
  +0x1c8  allow_data_in_errors (from DBOptions+0x248)
  +0x1d0  db_host_id (from DBOptions+0x250)
  +0x1f0  checksum_handoff_file_types (from DBOptions+0x270)
  +0x1f8  lowest_used_cache_tier (from DBOptions+0x288 byte)
  +0x228  compaction_service (from DBOptions+0x278)
  +0x238  enforce_single_del_contracts (from DBOptions+0x289 byte)
  +0x197  packed bools: wal_compression, atomic_flush,
          persist_stats_to_disk (DBOptions+0x138), avoid_unnecessary_blocking_io
  +0x158  packed bools: enable_thread_tracking (DBOptions+0x1c0),
          enable_pipelined_write (+0x1d0), unordered_write (+0x1d1),
          allow_concurrent_memtable_write (+0x1d2)
  +0x15c  enable_write_thread_adaptive_yield (DBOptions+0x1d3)

The model keeps observations, inferred names and unknowns separate: the
+0x21b slot and the three OptionTypeInfo offsets that do not match the
ImmutableDBOptions layout are recorded under OPEN_UNKNOWNS, not as facts.
"""

LOG_READAHEAD_SIZE_OFFSET = 0x220
LOG_READAHEAD_SIZE_IMMUTABLE_OFFSET = 0x1A0
LOG_READAHEAD_SIZE_DEFAULT = 0

INT_MAX = 0x7FFFFFFF
BGERROR_RESUME_RETRY_INTERVAL_DEFAULT = 1000000
DB_HOST_ID_DEFAULT = "__hostname__"
LOWEST_USED_CACHE_TIER_DEFAULT = 1  # CacheTier::kNonVolatileBlockTier
ENFORCE_SINGLE_DEL_CONTRACTS_DEFAULT = True

# ConfigOptions (0x60bb890 ctor; names resolved by this work item, #4108
# left +0x2c/+0x30 open): +0x2c sanity_level (u8, 0xff =
# kSanityLevelExactMatch), +0x30 file_readahead_size (size_t, 0x80000).
CONFIGOPTIONS_SANITY_LEVEL_DEFAULT = 0xFF
CONFIGOPTIONS_FILE_READAHEAD_SIZE_DEFAULT = 0x80000
CONFIGOPTIONS_SIZE_BYTES = 0x50
PERSIST_DELIMITER = "\n  "

# OptionTypeInfo name -> offset entries from the static initializer
# (__static_initialization_and_destruction_0v 0x60aa2b0). The three tail
# immutable entries match the ImmutableDBOptions ctor exactly; the other
# three are recorded as observed (see OPEN_UNKNOWNS).
OPTION_TYPE_INFO = {
    "log_readahead_size": 0x1A0,
    "best_efforts_recovery": 0x1B8,
    "max_bgerror_resume_count": 0x1BC,
    "avoid_unnecessary_blocking_io": 0x198,
    "write_dbid_to_manifest": 0x19A,
    "max_open_files": 0x40,
}

# DBOptionsConfigurable embeds a DBOptions at +0x2d8 and an
# ImmutableDBOptions at +0x98 (ctor 0x60a47f0: lea 0x2d8(%rbx) for the
# copy ctor call, lea 0x98(%rbx) for the ImmutableDBOptions ctor call).
CONFIGURABLE_DBOFFSET = 0x2D8
CONFIGURABLE_IMMUTABLE_OFFSET = 0x98

# The DBOptions+0x21b slot: declared write_dbid_to_manifest in the v8.1.1
# header, but the default ctor never stores it and the only 0x21b(%reg)
# hit binary-wide is a negative stack slot (-0x21b(%rbp)). No function
# reads DBOptions+0x21b.
NO_READ_SITES_21B = True

OPEN_UNKNOWNS = [
    "DBOptions+0x21b (write_dbid_to_manifest per the v8.1.1 header): never "
    "stored by the default ctor, never read by any code in the binary.",
    "OptionTypeInfo offset for avoid_unnecessary_blocking_io is 0x198, but "
    "the ImmutableDBOptions ctor packs avoid at +0x19a (with "
    "persist_stats_to_disk at +0x199 and atomic_flush at +0x198).",
    "OptionTypeInfo offset for write_dbid_to_manifest is 0x19a, but the "
    "ImmutableDBOptions ctor never reads DBOptions+0x21b and BuildDBOptions "
    "does not copy the field at all.",
    "OptionTypeInfo offset for max_open_files is 0x40, but max_open_files "
    "is mutable: BuildDBOptions takes it from MutableDBOptions, and the "
    "ImmutableDBOptions ctor stores info_log_level at +0x40 instead.",
]


class DBOptions:
    """A rocksdb::DBOptions, modelled over the pinned tail region.

    Only the tail (+0x218..+0x290) is modelled in full; the rest of the
    struct is represented by the fields the behaviour touches.
    """

    def __init__(self):
        # Default ctor 0x60b2db0: mov %si,0x218(%rbx) (wal_compression,
        # atomic_flush both 0); movb $0,0x21a(%rbx) (avoid); movq $0,
        # 0x220(%rbx) (log_readahead_size); movups xmm0,0x228(%rbx)
        # (file_checksum_gen_factory null); movb $0,0x238(%rbx)
        # (best_efforts_recovery); movl $0x7fffffff,0x23c(%rbx);
        # movq $0xf4240,0x240(%rbx); movb $0,0x248(%rbx);
        # db_host_id string from the GOT slot 0x64fee88 -> "__hostname__";
        # mov %ax,0x101... (lowest_used_cache_tier=1,
        # enforce_single_del_contracts=true at +0x288/+0x289).
        # +0x21b is never stored.
        self.wal_compression = 0
        self.atomic_flush = False
        self.avoid_unnecessary_blocking_io = False
        self.write_dbid_to_manifest = None  # unwritten by the ctor
        self.log_readahead_size = LOG_READAHEAD_SIZE_DEFAULT
        self.file_checksum_gen_factory = None
        self.best_efforts_recovery = False
        self.max_bgerror_resume_count = INT_MAX
        self.bgerror_resume_retry_interval = BGERROR_RESUME_RETRY_INTERVAL_DEFAULT
        self.allow_data_in_errors = False
        self.db_host_id = DB_HOST_ID_DEFAULT
        self.checksum_handoff_file_types = frozenset()
        self.compaction_service = None
        self.lowest_used_cache_tier = LOWEST_USED_CACHE_TIER_DEFAULT
        self.enforce_single_del_contracts = ENFORCE_SINGLE_DEL_CONTRACTS_DEFAULT
        # Fields the ImmutableDBOptions pack reads (defaults per header).
        self.persist_stats_to_disk = False  # DBOptions+0x138
        self.enable_thread_tracking = False  # DBOptions+0x1c0
        self.enable_pipelined_write = False  # DBOptions+0x1d0
        self.unordered_write = False  # DBOptions+0x1d1
        self.allow_concurrent_memtable_write = False  # DBOptions+0x1d2
        self.enable_write_thread_adaptive_yield = False  # DBOptions+0x1d3

    def copy(self):
        """DBOptions copy ctor 0x5d38750: mov 0x220(%rbp),%rax then
        mov %rax,0x220(%rbx) -- the field is copied verbatim."""
        other = DBOptions.__new__(DBOptions)
        other.__dict__.update(self.__dict__)
        return other

    @classmethod
    def from_options(cls, options):
        """DBOptions(const Options&) 0x60b3280: same verbatim +0x220 copy."""
        return options.db_options.copy()

    def assign(self, other):
        """DBOptions::operator= 0x60c3480: copies +0x220 verbatim."""
        self.__dict__.update(other.__dict__)
        return self


class Options:
    """A rocksdb::Options (DBOptions + ColumnFamilyOptions)."""

    def __init__(self, db_options=None):
        self.db_options = db_options if db_options is not None else DBOptions()


class ImmutableDBOptions:
    """A rocksdb::ImmutableDBOptions, modelled over the compacted tail.

    The ctor 0x60a3b60 compacts the DBOptions tail into the packed layout;
    the copy ctor 0x5da6bc0 copies +0x1a0 to +0x1a0 verbatim.
    """

    def __init__(self, db_options=None):
        if db_options is None:
            db_options = DBOptions()
        # mov 0x220(%rbp),%rax; mov %rax,0x1a0(%rbx)
        self.log_readahead_size = db_options.log_readahead_size
        self.best_efforts_recovery = db_options.best_efforts_recovery
        self.max_bgerror_resume_count = db_options.max_bgerror_resume_count
        self.bgerror_resume_retry_interval = db_options.bgerror_resume_retry_interval
        self.allow_data_in_errors = db_options.allow_data_in_errors
        self.db_host_id = db_options.db_host_id
        self.checksum_handoff_file_types = db_options.checksum_handoff_file_types
        self.compaction_service = db_options.compaction_service
        self.lowest_used_cache_tier = db_options.lowest_used_cache_tier
        self.enforce_single_del_contracts = db_options.enforce_single_del_contracts
        # Packed bool groups, in destination order (LE byte order):
        # +0x197 = wal_compression, atomic_flush, persist_stats_to_disk,
        #   avoid_unnecessary_blocking_io
        self.pack_197 = (db_options.wal_compression,
                         db_options.atomic_flush,
                         db_options.persist_stats_to_disk,
                         db_options.avoid_unnecessary_blocking_io)
        # +0x158 = enable_thread_tracking, enable_pipelined_write,
        #   unordered_write, allow_concurrent_memtable_write; +0x15c =
        #   enable_write_thread_adaptive_yield
        self.pack_158 = (db_options.enable_thread_tracking,
                         db_options.enable_pipelined_write,
                         db_options.unordered_write,
                         db_options.allow_concurrent_memtable_write)
        self.pack_15c = db_options.enable_write_thread_adaptive_yield

    def copy(self):
        """ImmutableDBOptions copy ctor 0x5da6bc0: +0x1a0 -> +0x1a0."""
        other = ImmutableDBOptions.__new__(ImmutableDBOptions)
        other.__dict__.update(self.__dict__)
        return other


class MutableDBOptions:
    """The mutable subset (only max_open_files is modelled: it is the
    field BuildDBOptions takes from here, not from ImmutableDBOptions)."""

    def __init__(self, max_open_files=-1):
        self.max_open_files = max_open_files


def build_db_options(immutable, mutable):
    """rocksdb::BuildDBOptions 0x60c2e20 (options_helper.cc L319):
    options.log_readahead_size = immutable_db_options.log_readahead_size;
    options.max_open_files = mutable_db_options.max_open_files."""
    out = DBOptions()
    out.log_readahead_size = immutable.log_readahead_size
    out.max_open_files = mutable.max_open_files
    return out


class ConfigOptions:
    """A rocksdb::ConfigOptions (0x60bb890 ctor), with the +0x2c/+0x30
    names resolved by this work item (see #4108 for the rest)."""

    def __init__(self):
        self.flag0, self.flag1, self.flag2, self.flag3 = 0, 1, 1, 1
        self.invoke_prepare_options = True  # +0x03, default 1
        self.delimiter = ";"  # +0x08
        self.depth = 0  # +0x28
        self.sanity_level = CONFIGOPTIONS_SANITY_LEVEL_DEFAULT  # +0x2c
        self.file_readahead_size = CONFIGOPTIONS_FILE_READAHEAD_SIZE_DEFAULT  # +0x30
        self.env = "Env::Default()"
        self.registry = "ObjectRegistry::NewInstance()"


class DBOptionsConfigurable:
    """The Configurable view (ctor 0x60a47f0): embeds a DBOptions at
    +0x2d8 (copy-constructed from the input) and an ImmutableDBOptions at
    +0x98 (constructed from the same input)."""

    def __init__(self, db_options):
        self.db_options = db_options.copy()  # +0x2d8, copy ctor 0x5d38750
        self.immutable = ImmutableDBOptions(db_options)  # +0x98


def option_type_info_offset(name):
    """The static initializer's OptionTypeInfo offset for a DBOptions
    field name (ImmutableDBOptions-relative for the immutable fields)."""
    if name not in OPTION_TYPE_INFO:
        raise KeyError("no OptionTypeInfo entry for " + name)
    return OPTION_TYPE_INFO[name]


def persist_outer(db_options):
    """PersistRocksDBOptions (outer) 0x60d4a00, options_parser.cc L67-97:
    ConfigOptions defaults, delimiter "\\n  ", invoke_prepare_options 0,
    and -- only when db_opt.log_readahead_size > 0 --
    config_options.file_readahead_size = db_opt.log_readahead_size."""
    cfg = ConfigOptions()
    cfg.delimiter = PERSIST_DELIMITER
    cfg.invoke_prepare_options = False
    if db_options.log_readahead_size > 0:
        cfg.file_readahead_size = db_options.log_readahead_size
    return cfg


def persist_inner(cfg, db_options, cf_names=("default",)):
    """PersistRocksDBOptions (inner) 0x60d2820, options_parser.cc L100-270:
    writes the OPTIONS file, then verifies it by re-reading with the
    ConfigOptions file_readahead_size (VerifyRocksDBOptionsFromFile
    0x60d13a0 -> Parse 0x60cfb60 -> LineFileReader with
    config_options.file_readahead_size). Returns (file_lines, cfg) so the
    caller can run the verify step."""
    lines = ["# This is a RocksDB option file.",
             "[Version]",
             "  rocksdb_version=8.1.1",
             "  options_file_version=1.0",
             "",
             "[DBOptions]",
             "  log_readahead_size=%d" % db_options.log_readahead_size]
    for name in cf_names:
        lines += ["", '[CFOptions "%s"]' % name]
    return lines, cfg


def verify_from_file(cfg, db_options, lines):
    """RocksDBOptionsParser::VerifyRocksDBOptionsFromFile 0x60d13a0: forwards
    ConfigOptions+0x30 into Parse 0x60cfb60 (mov 0x30(%rbx),%rax at
    0x60d144d), which builds the LineFileReader with that readahead size
    (options_parser.cc L502-504) and parses the file back. Returns the
    DBOptions the file parses to; raises ValueError on a corrupt file."""
    parsed = parse_options_file(cfg, lines)
    if parsed.log_readahead_size != db_options.log_readahead_size:
        raise ValueError("persisted log_readahead_size %r != %r"
                         % (parsed.log_readahead_size,
                            db_options.log_readahead_size))
    return parsed


def parse_options_file(cfg, lines, file_readahead_size=None):
    """RocksDBOptionsParser::Parse 0x60cfb60 (and the 4-arg overload that
    stores its file_readahead_size argument into ConfigOptions+0x30,
    mov %rdx,0x30(%rbx) at 0x60d0a0f). The readahead size only sizes the
    LineFileReader; it does not change what is parsed."""
    if file_readahead_size is not None:
        if file_readahead_size > 0:
            cfg.file_readahead_size = file_readahead_size
    out = DBOptions()
    section = None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].split()[0]
            continue
        if "=" not in line:
            raise ValueError("not a statement: %r" % raw)
        name, value = (part.strip() for part in line.split("=", 1))
        if section == "DBOptions" and name == "log_readahead_size":
            out.log_readahead_size = int(value)
    return out


def persist_round_trip(db_options):
    """End to end: outer Persist -> inner Persist (write) -> Verify
    (re-read with the bridged readahead size). Returns the re-parsed
    DBOptions."""
    cfg = persist_outer(db_options)
    lines, cfg = persist_inner(cfg, db_options)
    return verify_from_file(cfg, db_options, lines)
