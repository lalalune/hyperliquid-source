"""Node #115 StatisticsImpl construction — literal model.

Covers the ctor 0x6071a00, its cold cleanup partition 0x6071952, the
shard-store builder 0x60716d0, the HistogramImpl record-init trio
0x606b020/0x606b080/0x606b0c0 (re-shipped from open PR #3371), the
aligned allocator 0x60d5d50, the free wrapper 0x60d5db0, the
shard-store destroyer 0x606fd30, the no-op record dtor 0x5d89570 and
the mutex wrappers 0x60d50c0/0x60d5170.

Every constant below is read off the verbatim excerpts in
research/work-items/RE-001-statistics-impl-ctor-115/. Names in
quotes are inferences; the typeinfo strings are verbatim from the
binary: the record class is rocksdb::HistogramImpl
("N7rocksdb13HistogramImplE") and the outer class is
rocksdb::StatisticsImpl ("N7rocksdb14StatisticsImplE").

Shard-store layout (builder 0x60716d0):
- out+0x00 = records base (alloc+0x40), out+0x08 = bucket exponent.
- bucket count = 1 << exponent; exponent is 3 when ncpu <= 8, else
  the smallest e >= 4 with (1 << e) >= ncpu.
- allocation size = count * 0xce40 + 0x40, via posix_memalign(64);
  count > 0x9ee009ee009e throws bad_array_new_length.
- each shard is 0xce40 bytes: a 0x598-byte zeroed header, then 53
  records of 0x3c8 bytes (shard+0x598 .. shard+0xce00), then a
  0x40-byte untouched tail (shard+0xce00 .. shard+0xce40).
- the bucket count is stored at alloc+0x38 (read back by the
  destroyer as *(base-8)).

Per-record init (builder, for each of the 53 records per shard):
- *(rec) = 0x64d2b80 (HistogramImpl vtable); call 0x606b080(rec+8),
  which writes rec+0x398 then tail-jumps to shared init
  0x606b020(rec+8); zero rec+0x3c0 and rec+0x3a0..0x3b0; call
  0x606b0c0(rec), which locks the mutex at rec+0x3a0, calls shared
  init again, and unlocks. Shared init runs twice per record.

The builder's old-store release is DEAD CODE: the entry zeroes
*out (0x60716e2) before the release test at 0x60717fa reads *out,
so the test always sees 0. The destroyer 0x606fd30 is only live
from the ctor cleanup partition (0x60719b9); the builder's unwind
call at 0x6071904 is dead for the same reason.
"""

MASK64 = (1 << 64) - 1

SHARD_STRIDE = 0xCE40
RECORD_STRIDE = 0x3C8
RECORDS_PER_SHARD = 53
SHARD_HEADER = 0x598
SHARD_TAIL = 0x40
BUCKET_STRIDE = 0x28
BUCKET_ARRAY_BASE = 0x30
BUCKET_COUNT_FIELD = 0x398
RECORD_MUTEX = 0x3A0
OVERFLOW_GUARD = 0x9EE009EE009E

HISTOGRAM_VTABLE = 0x64D2B80
STATISTICS_VTABLE = 0x64D2D88
BASE_VTABLE = 0x64D3430
NOOP_DTOR = 0x5D89570
CTOR_RECORD_NAME = "StatisticsOptions"


def bucket_exponent(ncpu):
    """Exponent e: 3 when ncpu <= 8, else smallest e >= 4 with (1<<e) >= ncpu."""
    if ncpu <= 8:
        return 3
    e = 4
    while (1 << e) < ncpu:
        e += 1
    return e


def bucket_count(ncpu):
    """Shard count: 1 << bucket_exponent(ncpu)."""
    return 1 << bucket_exponent(ncpu)


def alloc_size(count):
    """Allocation size: count * 0xce40 + 0x40."""
    return count * SHARD_STRIDE + 0x40


def alloc_size_overflows(count):
    """True when the builder throws bad_array_new_length."""
    return count > OVERFLOW_GUARD


def shard_record_addresses(records_base, count):
    """Record addresses in build order: shard by shard, low to high."""
    out = []
    for shard in range(count):
        base = records_base + shard * SHARD_STRIDE
        for i in range(RECORDS_PER_SHARD):
            out.append(base + SHARD_HEADER + i * RECORD_STRIDE)
    return out


def destroy_order(records_base, count):
    """Record addresses in destroyer order: shards last to first,
    records within a shard from shard+0xca38 down to shard+0x598."""
    out = []
    for shard in reversed(range(count)):
        base = records_base + shard * SHARD_STRIDE
        for i in range(RECORDS_PER_SHARD):
            out.append(base + 0xCA38 - i * RECORD_STRIDE)
    return out


def builder_release_reachable():
    """False: the entry zeroes *out before the release test reads it."""
    return False


def shared_init_writes(min_ptr, bucket_count_value):
    """(offset relative to rec, value) writes of shared init 0x606b020.

    min_ptr is the runtime global *(0x6505d38); bucket_count_value is
    the runtime rec+0x398 value written by 0x606b080. The bucket loop
    zeroes the first qword of each bucket at rec+0x30 + i*0x28.
    """
    writes = [
        (0x08, min_ptr),
        (0x10, 0),
        (0x18, 0),
        (0x20, 0),
        (0x28, 0),
    ]
    for i in range(bucket_count_value):
        writes.append((BUCKET_ARRAY_BASE + i * BUCKET_STRIDE, 0))
    return writes


def bucket_array_end(bucket_count_value):
    """End offset of the bucket array (must stay <= the mutex at +0x3a0)."""
    return BUCKET_ARRAY_BASE + bucket_count_value * BUCKET_STRIDE


def bucket_array_fits(bucket_count_value):
    return bucket_array_end(bucket_count_value) <= RECORD_MUTEX


def bucket_count_value(global_begin, global_end):
    """0x606b080: (end - begin) >> 3 for the runtime globals."""
    return (global_end - global_begin) >> 3


def ctor_fields(moved_clock, moved_stats):
    """(offset, value) writes of the ctor 0x6071a00, in order."""
    return [
        (0x00, STATISTICS_VTABLE),
        (0x20, 3),  # level byte (single byte write)
        (0x08, 0),
        (0x10, 0),
        (0x18, 0),
        (0x30, 0),
        (0x28, moved_clock),
        (0x30, moved_stats),
    ]


def ctor_record_name():
    """The 17-byte name the ctor appends via options_record_append."""
    return CTOR_RECORD_NAME


def mutex_ok(return_code):
    """pthread init/destroy wrappers accept 0, 16 and 110, else abort."""
    return return_code in (0, 16, 110)


def allocator_return(posix_error, out_ptr):
    """0x60d5d50: the aligned pointer on success, else NULL."""
    return out_ptr if posix_error == 0 else None


def destroyer_skips(slot0):
    """0x606fd30 skips the call when slot 0 is the no-op dtor."""
    return slot0 == NOOP_DTOR
