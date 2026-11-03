"""Node #115 lazy-materialize predicate (0x5f77190), the match rule of
the two-phase filtered accumulation scan (0x5f77330, PR #2362).

RE-001 work item. This is a complete behavior, not a lone-window
fragment: the 406-byte predicate is the scan's only match test in
both phases (its two direct call sites are the scan's phase-1 site
0x5f773ae and phase-2 site 0x5f774ed), and it decides, per element,
whether the scan accumulates it. The scan tests the returned byte
and skips the element on zero, so a return of 1 is exactly a match.

Native layout (all offsets from the disassembly of
work/hl-node-115.bin, bound to provenance/artifacts.json digest
a6e2897c...5301):

  lazy_materialize_predicate(obj, element):
    flag = element + 0xb5 (byte); p78 = element + 0x78 (qword).
    If flag is nonzero: return 0 at once. No oracle call, no field
    read besides the flag, no mutation. A previously attempted
    element never matches again.
    If flag is zero and p78 is nonzero: return 0 at once, flag
    left at zero. No oracle call. A later call retries the init.
    Otherwise call the materializer oracle 0x5f76a00 with
    (output struct at a stack slot, obj, element, 0); the oracle
    writes a status byte and, on success, a result object pointer
    plus two buffers. The oracle itself is NOT modelled: the model
    takes it as a callable returning (status_byte, result or None).
    Set flag = 1 BEFORE reading the status, so every attempt --
    success, error, or null result -- marks the element attempted.
    If status is nonzero (error path): report through callee
    0x5fcf060 with code 3, the target at [obj + 0x1020] + 0xd0
    + 0x30, the element's +0x08 field masked with
    0x3fffffffffffffff, and the oracle's message string; the
    report's effect on the target is NOT claimed, only the call
    itself is recorded. Free the oracle's buffers and return 0.
    If status is zero and the result pointer is null: free the
    buffers and return 0 (flag stays 1).
    If status is zero and the result pointer is non-null: copy
    result + 0x58 -> element + 0x80, result + 0x68 ->
    element + 0x88, result + 0x48 -> element + 0x98,
    result + 0x40 -> element + 0x90, result + 0x78 ->
    element + 0xa0; free the buffers; return 1.

  The trailing stubs at 0x5f77302..0x5f77326 inside the FDE range
  are landing-pad stubs (each: endbr64, mov exception to rbx, jump
  to a shared resume path below the predicate); they are not
  predicate instructions and carry no predicate behavior.

Assumptions recorded explicitly:
  * Element dictionaries must carry the fields the predicate reads
    (flag, p78, p08) and, on the success path, the five fields the
    copy writes (f80, f88, f90, f98, fa0); a missing field raises
    ValueError instead of faulting, which is model-only.
  * The oracle callable stands in for 0x5f76a00; its argument
    registers and its own semantics are not claimed here.
  * The error-report call's destination effect is not claimed;
    the model records the call (code, target, masked field,
    status) in the optional error_calls list.
  * The model does not reproduce the stack canary check or the
    operator-delete calls; freed buffers have no observable
    effect on the return value or the element fields.
"""

MASK64 = (1 << 64) - 1
MASK_P08 = 0x3FFFFFFFFFFFFFFF
ERROR_CODE = 3

# Element fields the predicate reads or writes, by native offset.
FLAG_FIELD = "flag"      # +0xb5, byte
P78_FIELD = "p78"       # +0x78, qword
P08_FIELD = "p08"       # +0x08, qword (error path, masked)
COPY_FIELDS = (("f58", "f80"), ("f68", "f88"), ("f48", "f98"),
               ("f40", "f90"), ("f78", "fa0"))


def _need(mapping, field):
    if field not in mapping:
        raise ValueError("missing field: %s" % field)
    return mapping[field]


def lazy_materialize_predicate(obj, elt, oracle, error_calls=None):
    """Model the predicate 0x5f77190. Returns 1 for a match, 0 else.

    obj: dict; only obj.get("error_target") is read, for the
        error-report call record (the native target is
        [obj + 0x1020] + 0xd0 + 0x30).
    elt: dict with flag, p78, p08; mutated in place (flag set to 1
        on any attempt; the five copy fields written on success).
    oracle: callable(obj, elt) -> (status_byte, result or None),
        where result is a dict with f58, f68, f48, f40, f78.
    error_calls: optional list; each error-path report appends a
        dict with code, target, masked_p08 and status.
    """
    flag = _need(elt, FLAG_FIELD)
    if flag != 0:
        return 0
    p78 = _need(elt, P78_FIELD)
    if p78 != 0:
        return 0
    status, result = oracle(obj, elt)
    elt[FLAG_FIELD] = 1
    if status != 0:
        if error_calls is not None:
            error_calls.append({
                "code": ERROR_CODE,
                "target": obj.get("error_target"),
                "masked_p08": _need(elt, P08_FIELD) & MASK_P08,
                "status": status,
            })
        return 0
    if result is None:
        return 0
    for src, dst in COPY_FIELDS:
        elt[dst] = _need(result, src)
    return 1
