# Node115 u32 twin cursor search

Independent `no_std` projection of node115 `0x35bf500..0x35bf592`, using the
u32-key layout and the standard four-field cursor record.

The logical API validates at most eleven ascending keys and `n+1` children,
then returns found flag, final node, remaining height and equal/insertion
position. Native pointer layout, malformed trees and caller effects remain out
of scope.
