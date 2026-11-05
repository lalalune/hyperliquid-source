# Node115 mixed-order / saturated-threshold semantic family

Independent MIT safe no_std scalar implementation for three complete leaves:
55ff9e0,2c6f290 and55ff970. Two unique encodings/three physical bodies are measured
in one packet; an alternate object's field offsets do not create a separate PR.

`select(a,b,t,x,c)` compares `(a[0]as i32,a[1],a[2])` with the corresponding B
triple. A>=B and T>=C returns raw2; otherwise it returns whether
T>=X.saturating_add(5000). Equality and saturation atUINT64_MAX are observable.
The API accepts logical raw fields, not an original object layout or public ABI.

See [contract/evidence](../../research/work-items/RE-001-mixed-tuple-threshold-115/README.md).
No dependencies/root Cargo graph, units/time policy, original compiler recipe,
Linux execution, target-byte equivalence or whole-component gate is claimed.
