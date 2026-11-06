"""Python model of node #115's cached ZSTD compress context
(rocksdb::StreamingCompress::Create).

RE-001 work item; see research/work-items/RE-001-zstd-compress-cache-115/
for the evidence packet. The model reproduces the binary behaviour
exactly as the excerpts show it; nothing here is an implementation
claim about the upstream reconstruction.

Layout
------
Holder (0x70 bytes, built by the factory 0x61c1c10, catalogue
rocksdb::StreamingCompress::Create):
  +0x00: table pointer 0x64d7408 + 0x10
  +0x08: kind byte 7
  +0x10..+0x40: the 0x30-byte CompressionOptions template, copied verbatim
  +0x40: arg3 (2 in the one caller), +0x48: arg4 (0x7ff5 / 0x7ff9)
  +0x50: fresh CCtx (0x6218920), +0x58: 0, +0x60..+0x70: 0

CCtx (0x1480 bytes, 0x6218920, zstd ZSTD_createCCtx by shape):
  calloc(1, 0x1480); +0x08 = CPUID leaf-7 BMI1+BMI2 flag; the reset
  0x62188a0 runs on the fresh context; +0x10..+0xe8 zeroed;
  +0x30 = 1, +0x3c = 3.
Params live at CCtx+0x10 and are written by the apply worker
0x6211a10 through the setter 0x6212010 (zstd ZSTD_CCtx_setParameter
by shape). The factory sets exactly one parameter: 201 -> 1, which
the apply arm stores as (value != 0) at params+0x24.

Reset (0x62188a0): frees the +0xe48 workspace pointer through the
custom free at +0x370 (opaque +0x378), or plain free when that is
null; frees the +0xe68 CDict via ZSTD_freeCDict (0x62187a0,
catalogue 242/251); zeroes +0xe48..+0xe90.

Refresh caller (0x5f041d0, catalogue
rocksdb::log::Writer::AddCompressionTypeRecord): emits the 4-byte
kind record (type 9) via 0x5f03b80, then builds the template and
calls the factory, installing the holder at owner+0x48 and a fresh
array at owner+0x50.
"""

# ---------------------------------------------------------------------------
# Constants pinned by the excerpts.
# ---------------------------------------------------------------------------

CCTX_SIZE = 0x1480
HOLDER_SIZE = 0x70
KIND_ZSTD = 7
FACTORY_TABLE = 0x64D7408 + 0x10
GLOBAL_TEMPLATE_QWORD = 0x7FFFFFFFFFF2  # *(0x459aa0); int32s (-14, INT_MAX)
TEMPLATE_QWORDS = (GLOBAL_TEMPLATE_QWORD, 0, 0x100000000, 0, 0, 1)
RECORD_TYPE_COMPRESSION = 9

ERR_PARAM_OUT_OF_BOUND = -40
ERR_RANGE_CHECK = -42
ERR_PARAM_UNSUPPORTED = -60


def cpu_feature_flag(max_leaf, leaf7_ebx):
    """+0x08: 0 when max leaf <= 6; else 1 iff leaf-7 EBX has both
    bits 3 and 8 set (BMI1 + BMI2), else 0. Same probe as the DCtx
    create in open PR #3635 (+0x75e4 there)."""
    if max_leaf <= 6:
        return 0
    return 1 if (leaf7_ebx & 0x108) == 0x108 else 0


def create_cctx(max_leaf, leaf7_ebx):
    """0x6218920: calloc(1, 0x1480) plus the pinned field init.

    Returns the field map (offset -> value) of the fresh context;
    every other byte is zero: calloc zeroes the whole object and the
    rep stos zeroes +0x10..+0xe8 on top. The reset runs on the fresh
    context first (its pointers are all null, so it frees nothing).
    """
    fields = {
        0x08: cpu_feature_flag(max_leaf, leaf7_ebx),
        0x30: 1,
        0x3C: 3,
    }
    return {"size": CCTX_SIZE, "fields": fields}


# ---------------------------------------------------------------------------
# CDict free (0x62187a0) and the CCtx reset (0x62188a0).
# ---------------------------------------------------------------------------

class CDict:
    """A CDict object as the reset sees it: +0x20 backing allocation,
    +0x28 end marker, +0x17a0 custom-free fn, +0x17a8 opaque."""

    def __init__(self, backing=None, end=None, custom_free=None, opaque=None):
        self.backing = backing
        self.end = end
        self.custom_free = custom_free
        self.opaque = opaque
        self.freed = False
        self.zeroed = False


def free_cdict(cdict):
    """0x62187a0 (catalogue ZSTD_freeCDict): null returns 0 at once.
    Otherwise zeroes +0x20..+0x60 and +0x60, releases the backing
    allocation and the CDict itself through the +0x17a0 custom free
    (opaque +0x17a8) when set, else plain free, and returns 0. The
    branch structure (which of the two allocations is freed) depends
    on whether the +0x20 pointer lies inside the CDict object itself
    (bounds +0x00..+0x28); see records.json."""
    if cdict is None:
        return 0
    cdict.zeroed = True
    cdict.freed = True
    return 0


def _default_free(ptr):
    """Plain free(): the model has no allocator, so freeing a pointer
    is a no-op here; callers pass their own recorder when they want
    to observe it."""
    return None


def reset_cctx(ctx, free=_default_free):
    """0x62188a0: release the CCtx workspace.

    `ctx` maps field offsets to values: +0x370 custom-free fn (or
    None), +0x378 opaque, +0xe48 workspace pointer, +0xe68 CDict.
    Frees the workspace pointer (custom free when set, else plain
    free), frees the CDict, then zeroes +0xe48..+0xe90. Returns the
    list of freed pointers, in the binary's order."""
    freed = []
    workspace = ctx.get(0xE48)
    if workspace is not None:
        custom_free = ctx.get(0x370)
        if custom_free is not None:
            custom_free(ctx.get(0x378), workspace)
        else:
            free(workspace)
        freed.append(workspace)
    cdict = ctx.get(0xE68)
    if cdict is not None:
        free_cdict(cdict)
        freed.append(cdict)
    for off in range(0xE48, 0xE90, 8):
        ctx[off] = 0
    return freed


# ---------------------------------------------------------------------------
# Parameter bounds (0x62117e0) and the range check (0x62119e0).
# ---------------------------------------------------------------------------

# param -> (lo, hi); None means the bounds lookup errors (-40).
BOUNDS = {
    10: (0, 1),
    100: (-131072, 22),
    101: (10, 31),
    102: (6, 30),
    103: (6, 30),
    104: (1, 30),
    105: (3, 7),
    106: (0, 131072),
    107: (1, 9),
    130: (1340, 131072),
    160: (0, 2),
    161: (6, 30),
    162: (4, 4096),
    163: (1, 8),
    164: (0, 25),
    200: (0, 1),
    201: (0, 1),
    202: (0, 1),
    400: (0, 0),
    401: (0, 0),
    402: (0, 0),
    500: (0, 1),
    1000: (0, 1),
    1001: (0, 3),
    1002: (0, 2),
    1004: (0, 0x7FFFFFFF),
    1005: (0, 1),
    1006: (0, 1),
    1007: (0, 1),
    1008: (0, 1),
    1009: (0, 1),
    1010: (0, 1),
    1011: (0, 2),
    1012: (0, 1),
    1013: (0x400, 0x20000),
    1014: (0, 1),
    1015: (0, 2),
    1016: (0x400, 0x20000),
}


def bounds_for(param):
    """0x62117e0: (status, lo, hi). status 0 with the packed bounds,
    or -40 when the parameter has no bounds row."""
    row = BOUNDS.get(param)
    if row is None:
        return ERR_PARAM_OUT_OF_BOUND, 0, 0
    return 0, row[0], row[1]


def range_ok(param, value):
    """0x62119e0: 1 iff the bounds lookup succeeds and
    lo <= value <= hi (signed)."""
    status, lo, hi = bounds_for(param)
    if status != 0:
        return 0
    return 1 if lo <= value <= hi else 0


# ---------------------------------------------------------------------------
# The parameter apply worker (0x6211a10).
# ---------------------------------------------------------------------------

# param -> (field offset in the params struct, kind) where kind is
# one of: "value" (range-checked dword store), "qword" (range-checked
# 64-bit store), "bool-ne" ((value != 0) dword store),
# "bool-eq" ((value == 0) dword store), "checked-bool-ne" (range
# check first, then a (value != 0) store — param 1012 only).
# Params 100, 130, 1015 and 10 have special arms handled in apply()
# directly.
_APPLY_ARMS = {
    101: (0x04, "value"),
    102: (0x0C, "value"),
    103: (0x08, "value"),
    104: (0x10, "value"),
    105: (0x14, "value"),
    106: (0x18, "value"),
    107: (0x1C, "value"),
    160: (0x60, "value"),
    161: (0x64, "value"),
    162: (0x6C, "value"),
    163: (0x68, "value"),
    164: (0x70, "value"),
    200: (0x20, "bool-ne"),
    201: (0x24, "bool-ne"),
    202: (0x28, "bool-eq"),
    1000: (0x30, "bool-ne"),
    1001: (0x44, "value"),
    1002: (0x48, "value"),
    1004: (0x40, "value"),
    1005: (0x78, "bool-ne"),
    1006: (0x7C, "value"),
    1007: (0x80, "value"),
    1008: (0x84, "value"),
    1009: (0x88, "value"),
    1010: (0x8C, "value"),
    1011: (0x90, "value"),
    1012: (0x94, "checked-bool-ne"),
    1013: (0xB0, "value"),
    1014: (0xB4, "value"),
    1016: (0xD0, "value"),
}


def apply_param(params, param, value):
    """0x6211a10: write one parameter into the params struct
    (CCtx+0x10) and return the zstd size_t code (negative on error).

    `params` maps field offsets to stored values. Unlisted params
    return -40; params 400..402 and 500 return 0 iff value == 0.
    """
    if param == 10:
        if not range_ok(10, value):
            return ERR_RANGE_CHECK
        params[0x00] = value
        return value
    if param == 100:
        # Clamp to bounds(-131072, 22); 0 means the default level 3.
        _, lo, hi = bounds_for(100)
        clamped = max(value, lo)
        clamped = min(clamped, hi)
        if clamped == 0:
            params[0x2C] = 3
            return 3
        params[0x2C] = clamped
        return 0 if clamped < 0 else clamped
    if param == 130:
        if value == 0:
            params[0x38] = 0
            return 0
        value = max(value, 0x53C)
        if not range_ok(130, value):
            return ERR_RANGE_CHECK
        params[0x38] = value
        return value
    if param == 1015:
        if value == 0:
            params[0xC8] = 0
            return 0
        if not range_ok(1015, value):
            return ERR_RANGE_CHECK
        params[0xC8] = value
        return value
    if param in (400, 401, 402, 500):
        return 0 if value == 0 else ERR_PARAM_OUT_OF_BOUND
    arm = _APPLY_ARMS.get(param)
    if arm is None:
        return ERR_PARAM_OUT_OF_BOUND
    offset, kind = arm
    if kind == "value":
        if not range_ok(param, value):
            return ERR_RANGE_CHECK
        params[offset] = value
        return value
    if kind == "qword":
        if not range_ok(param, value):
            return ERR_RANGE_CHECK
        params[offset] = value
        return value
    if kind == "bool-ne":
        params[offset] = 1 if value != 0 else 0
        return params[offset]
    if kind == "checked-bool-ne":
        if not range_ok(param, value):
            return ERR_RANGE_CHECK
        params[offset] = 1 if value != 0 else 0
        return params[offset]
    # bool-eq
    params[offset] = 1 if value == 0 else 0
    return params[offset]


# ---------------------------------------------------------------------------
# The setter (0x6212010).
# ---------------------------------------------------------------------------

# Params accepted while the +0xe18 flag is set (they also set the
# +0x4 dirty flag on the context).
_FLAGGED_ACCEPT = {100, 102, 103, 104, 105, 106, 107}

# Params accepted while the +0xe18 flag is clear (no dirty write).
_UNFLAGGED_ACCEPT = {
    10, 100, 101, 102, 103, 104, 105, 106, 107, 130,
    160, 161, 162, 163, 164, 200, 201, 202,
    400, 401, 402, 500, 999, 1000, 1001, 1002, 1004, 1005,
    1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014,
    1015, 1016,
}


def set_parameter(ctx, param, value):
    """0x6212010: the gate, then the apply worker on CCtx+0x10.

    `ctx` maps offsets to values: +0x04 dirty flag, +0xe18 the flag
    selecting the gate table, +0x388 the param-400 guard, and
    "params" holds the params-struct dict. Returns the apply result
    or the gate error (-40 / -60)."""
    if ctx.get(0xE18, 0) != 0:
        if param not in _FLAGGED_ACCEPT:
            return ERR_PARAM_UNSUPPORTED
        ctx[0x04] = 1
        return apply_param(ctx.setdefault("params", {}), param, value)
    if param == 400:
        if value != 0 and ctx.get(0x388, 0) != 0:
            return ERR_PARAM_OUT_OF_BOUND
    elif param not in _UNFLAGGED_ACCEPT:
        return ERR_PARAM_OUT_OF_BOUND
    return apply_param(ctx.setdefault("params", {}), param, value)


# ---------------------------------------------------------------------------
# The kind-7 holder factory (0x61c1c10) and the refresh caller (0x5f041d0).
# ---------------------------------------------------------------------------

def make_holder(kind, template, arg3, arg4, create, set_parameter_fn):
    """0x61c1c10 (catalogue rocksdb::StreamingCompress::Create).
    Any kind other than 7 returns None; kind 7 builds the 0x70-byte
    object, copies the 0x30-byte template to +0x10, creates a fresh
    CCtx at +0x50, sets parameter 201 to 1 on it through the setter,
    and zeroes +0x58/+0x60..+0x70. `create` is create_cctx (as a
    zero-arg factory over the caller's CPUID values);
    `set_parameter_fn` is set_parameter."""
    if kind != KIND_ZSTD:
        return None
    cctx = create()
    ctx = dict(cctx["fields"])
    ctx["params"] = {}
    ctx[0xE18] = 0
    ctx[0x388] = 0
    set_parameter_fn(ctx, 201, 1)
    return {
        "size": HOLDER_SIZE,
        "table": FACTORY_TABLE,
        "kind_byte": KIND_ZSTD,
        "template": tuple(template),
        "field_40": arg3,
        "field_48": arg4,
        "cctx": ctx,
        "field_58": 0,
        "field_60": 0,
    }


def refresh_template(owner_flag18):
    """The template the refresh caller builds: the global qword,
    zeroes, 0x100000000 at +0x10, flag byte 1 at +0x28; plus the
    array size, 0x7ff5, or 0x7ff9 when owner+0x18 is 0."""
    size = 0x7FF5 + (4 if owner_flag18 == 0 else 0)
    return TEMPLATE_QWORDS, size


def add_compression_type_record(owner, emit, create, set_param):
    """0x5f041d0 (catalogue rocksdb::log::Writer::AddCompressionTypeRecord).

    `owner` maps the owner fields: "kind" (+0x45), "flag44" (+0x44),
    "flag18" (+0x18), "holder" (+0x48), "array" (+0x50). `emit`
    is EmitPhysicalRecord(type, payload_bytes) returning a status
    code (0 = ok). Returns the 16-byte out status as an int code.
    Kind 0 zeroes the out and returns 0 without emitting. An emit
    failure clears the owner's kind byte and returns the status.
    Otherwise the factory product is installed at +0x48 and a fresh
    array at +0x50 (the old array is released)."""
    if owner.get("kind", 0) == 0:
        return 0
    kind_dword = owner["kind"] & 0xFFFFFFFF
    status = emit(RECORD_TYPE_COMPRESSION,
                  kind_dword.to_bytes(4, "little"))
    if status != 0:
        owner["kind"] = 0
        return status
    template, size = refresh_template(owner.get("flag18", 0))
    holder = make_holder(owner["kind"], template, 2, size, create,
                         set_param)
    owner["holder"] = holder
    owner["array"] = {"size": size}
    return status
