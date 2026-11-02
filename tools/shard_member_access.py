"""Model of node #94 sharded member access 0x516a390 (RE-001).

Reconstructed semantics, from
research/work-items/RE-001-shard-member-access-94/:

    access(host, opts58, arg3, use_global, cpuid, rng, builder)

``host`` carries the bucket array (``host.buckets``, 16-byte
shared_ptr slots at host +0xd10), the bucket shift (host +0xd18),
the global member (host +0xce0) and the host8 object (host +0x8).
``opts58`` is the value at the options object's +0x58 field (an
object with a ``second`` field, or None). ``cpuid`` is a
(max_leaf, ebx_leaf1) pair for the 0x53356a0 stub. ``rng`` is the
calling thread's RNG state for the 0x5423a50 slot, advanced by the
caller's minstd_rand step when the CPUID seed is negative.
``builder`` stands for the 0xe8 member constructor 0x5196de0 (by
contract: 2593 bytes, not implemented on this VM); it is called
only on the lazy-install path.

The wrapper layouts follow the two constructors literally:
0x5190d50 (global variant) and 0x5190f70 (shard variant).
"""

MODULUS = 0x7FFFFFFF
MULTIPLIER = 16807
HASH_SEED = 0xC70F6907


def cpuid_index(max_leaf, ebx_leaf1):
    """The 0x53356a0 stub: -1 when CPUID leaf 0 reports no leaves,
    otherwise leaf-1 EBX shifted right 24 (the EBX top byte)."""
    if max_leaf == 0:
        return -1
    return (ebx_leaf1 >> 24) & 0xFF


def seed_rng(hash_bytes, pthread_self):
    """The 0x5423a50 first-use seed: Hash_bytes(pthread_self, 8,
    0xc70f6907) masked to 31 bits, or 1 when that mask is 0."""
    value = hash_bytes(pthread_self, 8, HASH_SEED) & MODULUS
    return value if value != 0 else 1


def minstd_rand(state):
    """The caller's fallback step, exactly as the binary computes
    it in 32-bit arithmetic: state * 16807 mod (2^31 - 1) via
    (x & 0x7fffffff) + (x >> 31), subtracting 0x7fffffff when the
    sum's sign bit is set. For valid states (1..2^31-2) this
    equals the big-int modulus; the 0x7fffffff state is a fixed
    point of the literal reduction and is unreachable from a valid
    seed (the seed step forces a nonzero 31-bit value)."""
    x = state * MULTIPLIER
    total = (x & MODULUS) + (x >> 31)
    total &= 0xFFFFFFFF
    if total & 0x80000000:
        total = (total - MODULUS) & 0xFFFFFFFF
    return total


def bucket_index(seed, shift):
    """index = seed & ((1 << shift) - 1)."""
    return seed & ((1 << shift) - 1)


class Member:
    """A member object: only its +0x8 and +0x20 fields are read
    by the wrapper constructors."""

    def __init__(self, f8, f20):
        self.f8 = f8
        self.f20 = f20


class Shard:
    """One bucket's shard: the lazily installed member, the
    installed flag (+0x30), a simulated control-block refcount
    and a simulated mutex."""

    def __init__(self, member=None, installed=False, lock_fail=False):
        self.member = member
        self.installed = installed
        self.lock_fail = lock_fail
        self.refcount = 1  # the bucket's own shared_ptr reference


class Host:
    """The host object: buckets, shift, global member and host8."""

    def __init__(self, buckets, shift, global_member, host8_f8):
        self.buckets = buckets
        self.shift = shift
        self.global_member = global_member
        self.host8_f8 = host8_f8


class Opts58:
    """The options +0x58 object; only its +0x8 field matters."""

    def __init__(self, second):
        self.second = second


def _wrap_global(member, host8_f8, arg3, opts58):
    return {
        "kind": "global",
        "member": member,
        "shared_ptr_held": False,
        "host8_dup": (host8_f8, host8_f8),
        "arg3": arg3,
        "view80": opts58,
        "view88": (member.f8, member.f20),
        "view98": (member.f8, member.f20),
        "viewa0": member.f20,
        "string": "",
    }


def _wrap_shard(shard, host8_f8, arg3, opts58):
    member = shard.member
    if opts58 is not None and opts58.second == 0:
        opts58_view = None
    else:
        opts58_view = opts58
    shard.refcount += 1  # the wrapper's shared_ptr copy
    return {
        "kind": "shard",
        "member": member,
        "shared_ptr_held": True,
        "host8_dup": (host8_f8, host8_f8),
        "arg3": arg3,
        "view80": (opts58_view, member.f8),
        "view88": None,
        "view90": (member.f20, member.f8),
        "view98": None,
        "viewa0": member.f20,
        "string": "",
    }


def access(host, opts58, arg3, use_global, cpuid, rng_state, builder):
    """Run one access; returns (wrapper, new_rng_state, log).

    ``log`` records the observable steps (index, path, installs)
    for the tests. Raises SystemError when the shard mutex lock
    fails, as the binary's system-error throw does.
    """
    log = []
    if use_global:
        log.append("path:global")
        return _wrap_global(host.global_member, host.host8_f8,
                            arg3, opts58), rng_state, log
    seed = cpuid_index(*cpuid)
    if seed < 0:
        rng_state = minstd_rand(rng_state)
        seed = rng_state
        log.append("index:random")
    else:
        log.append("index:cpuid")
    idx = bucket_index(seed, host.shift)
    log.append("bucket:%d" % idx)
    shard = host.buckets[idx]
    shard.refcount += 1  # atomic bucket load bump
    if not shard.installed:
        if shard.lock_fail:
            raise SystemError("mutex lock failed")
        log.append("lock:acquired")
        if shard.member is None:
            # The binary reads the old member before the install
            # store and destroys it when nonzero, but the re-check
            # above guarantees it is None here, so that destroy is
            # defensive only and never fires on this path.
            shard.member = builder()
            log.append("install:built")
            shard.installed = True
            log.append("install:flag-set")
        else:
            log.append("recheck:already-installed")
        log.append("lock:released")
    else:
        log.append("path:fast")
    wrapper = _wrap_shard(shard, host.host8_f8, arg3, opts58)
    shard.refcount -= 1  # the caller's bucket copy is released
    return wrapper, rng_state, log
