# Node #115 tracker: selected floating comparison

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence only; semantic names are not inferred.

After the separately traced 20-byte tree-key matching helper returns a vector, `0x5377747` converts its length m to binary64. The caller converts the nonzero input count n to binary64 and divides m by n at `0x5377775`. `0x5377779` loads an eight-byte literal from ELF VA `0x4592b0`; its authenticated bytes `000000000000f03f` decode as IEEE-754 binary64 1.0. The code subtracts the ratio from 1.0, loads tracker +0x40 as binary64, and uses `ucomisd`/`jae` at `0x537778b..0x537779f`.

For finite tracker value t, 0 <= m <= 2^53 and 0 < n <= 2^53, assuming the conversions execute normally, the branch to `0x53777b4` is taken exactly when `t >= fl(1.0 - fl(m/n))`, with binary64 rounding. Equality therefore takes that branch. For unordered comparison the `jae` branch is not taken. The earlier compare to zero at `0x5377572` sends either positive or negative zero to a skip path, whereas NaN reaches the nonzero/unordered arm; this does not imply any later outcome. No validity constraints on m/n, protocol meaning, runtime values or effects of later paths are asserted.

Run `python3 research/work-items/RE-017-node115-tracker-match-ratio/verify.py` to authenticate the target and validate instructions, the literal and the direct call with anchor mutation controls. `windows.txt` contains the selected instructions. No target code is executed.
