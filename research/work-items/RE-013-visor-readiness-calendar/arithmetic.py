#!/usr/bin/env python3
"""Finite integer certificates for the stated calendar domain, not an emulator.

No instruction stream, register state, program counter or target function is
evaluated. Scalar number-theory identities and table formulas are checked.
The address-bound argument connecting them to native code is in PROOF.md.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import struct
from collect import Image, bind, canonical_tables, digest, encoded, leap, require

MIN_YEAR, MAX_YEAR = -262143, 262142
MASK64 = (1 << 64)-1

def trunc_div(n,d):
    return n//d if n >= 0 else -((-n)//d)

def certificate(image):
    bind(image)
    prefix, flags = canonical_tables()
    u32 = lambda va: struct.unpack("<I",image.at(va,4))[0]
    u64 = lambda va: struct.unpack("<Q",image.at(va,8))[0]
    m86400 = u64(0x4458df)
    m400, mcycle, m365 = u32(0x44407f),u32(0x4440db),u32(0x44410c)
    checks = []
    # Exact complete finite domains used by this proof, not random grids.
    for y in range(MIN_YEAR,MAX_YEAR+1):
        product = y*m400
        require((product>>39)+(product<0) == trunc_div(y,400), "year /400 identity")
    checks.append({"name":"signed-year-division","cases":MAX_YEAR-MIN_YEAR+1,
                   "domain":[MIN_YEAR,MAX_YEAR],"formula":"(y*M400 >> 39) + [y*M400<0] = trunc(y/400)"})
    for x in range(60,86460):
        require((x*m86400)>>77 == x//86400, "seconds /86400 identity")
    checks.append({"name":"seconds-division","cases":86400,"domain":[60,86459],
                   "formula":"x*M86400 >> 77 = floor(x/86400)"})
    for x in range(146098):
        require((x*mcycle)>>47 == x//146097, "cycle /146097 identity")
    checks.append({"name":"cycle-division","cases":146098,"domain":[0,146097],
                   "formula":"x*Mcycle >> 47 = floor(x/146097)"})
    for x in range(146097):
        a = (x*m365)>>32
        require((((x-a)>>1)+a)>>8 == x//365, "cycle-day /365 identity")
    checks.append({"name":"year-estimate","cases":146097,"domain":[0,146096],
                   "formula":"(((x-(x*M365>>32))>>1)+(x*M365>>32))>>8 = floor(x/365)"})
    year_end = []
    for y in range(400):
        length = 365+leap(y)
        start_next = 365*y+prefix[y]+length
        require(start_next == 365*(y+1)+prefix[y+1], "year-start identity")
        cycle,day = divmod(start_next,146097)
        guess = day//365
        require(0 <= guess < 400 and day-365*guess-prefix[guess] == 0,
                "year-end has exact year guess and zero day remainder")
        require(guess == (y+1)%400 and cycle == (y==399), "year-end rollover")
        year_end.append(f"{y} {length} {cycle} {guess} {day} 1")
    checks.append({"name":"year-end-case-partition","cases":400,
                   "rowSha256":digest(encoded(year_end)),"allNoBorrow":True})
    # Classify every canonical ordinal in one 400-year cycle for delta0 and1.
    fast0=fast1=slow1=0
    for y in range(400):
        length = 365+leap(y)
        require((flags[y]&8 == 0) == leap(y), "leap flag")
        for ordinal in range(1,length+1):
            code = (ordinal<<4)|flags[y]
            require((code&0x1ff8) < 0x16e1, "canonical ordinal validity")
            fast0 += 1
            if ordinal+1 <= length:
                fast1 += 1
            else:
                slow1 += 1
    require((fast0,fast1,slow1)==(146097,145697,400),"date path counts")
    # The output year can only be input year or input year+1.
    year_gate_bias, year_gate_bound = u32(0x4441cb),u32(0x4441d1)
    for y in range(MIN_YEAR,MAX_YEAR+2):
        admitted = ((y+year_gate_bias)&0xffffffff) >= year_gate_bound
        require(admitted == (MIN_YEAR<=y<=MAX_YEAR), "year gate")
    checks.append({"name":"output-year-gate","cases":MAX_YEAR-MIN_YEAR+2,
                   "domain":[MIN_YEAR,MAX_YEAR+1]})
    # The two native carry guards admit both possible whole-day carries.
    gate_rows=[]
    for carry in (0,86400):
        first=(carry+u64(0x5b43f4))&MASK64
        second=(carry+u64(0x5b4410))&MASK64
        first_ok=first>u64(0x5b4401)
        second_ok=second>=u64(0x5b441d)
        require(first_ok and second_ok,"caller carry gate")
        require((carry*m86400)>>77 == carry//86400,"caller carry /86400")
        gate_rows.append({"wholeDaySeconds":carry,"firstUnsigned":first,
                          "secondUnsigned":second,"bothAdmitted":True,
                          "dayDelta":carry//86400})
    # Fixed binary64 certificate: exponent5, integral significand, no fraction.
    bits=u64(0x6e748)
    exp=(bits>>52)&0x7ff
    significand=(bits&((1<<52)-1))+(1<<52)
    integer=significand>>(0x433-exp)
    fraction=(bits<<(exp-0x3ff))&((1<<52)-1)
    require(exp==0x404 and integer==60 and fraction==0,"fixed60 bit algebra")
    nanos=60*1000000000
    multiplier=u64(0x5b43bd)
    recovered=(nanos*multiplier)>>90
    require(recovered==60 and nanos-recovered*1000000000==0
            and nanos<(1<<63)-1,"caller fixed duration")
    maximum=(MAX_YEAR<<13)|(365<<4)|flags[MAX_YEAR%400]
    # Explicit boundary facts, including a counterexample to an overbroad theorem.
    boundaries=[
        {"inputSecond":86339,"inputNano":999999999,"outputSecond":86399,
         "outputNano":999999999,"dayDelta":0},
        {"inputSecond":86340,"inputNano":0,"outputSecond":0,"outputNano":0,"dayDelta":1},
        {"inputSecond":86399,"inputNano":1999999999,"outputSecond":59,
         "outputNano":999999999,"dayDelta":1},
    ]
    # These examples are formulas, not executions of code extracted from the ELF.
    for row in boundaries:
        q,r=divmod(row["inputSecond"]+60,86400)
        n=row["inputNano"]%1000000000
        require((r,n,q)==(row["outputSecond"],row["outputNano"],row["dayDelta"]),
                "boundary arithmetic")
    fallback=(maximum,86399,999999999)
    counterexample=(maximum,86399,1000000000)
    require(counterexample>fallback,"extended-current counterexample")
    return {"kind":"finite scalar mathematical certificates",
            "targetExecution":False,"instructionEvaluation":False,
            "nativeBindingsChecked":True,"checks":checks,
            "constantsFromImage":{"M86400":hex(m86400),"M400":hex(m400),
                                  "Mcycle":hex(mcycle),"M365":hex(m365)},
            "canonicalTableBytes":[len(prefix),len(flags)],
            "datePathsOneCycle":{"delta0Fast":fast0,"delta1Fast":fast1,"delta1Slow":slow1},
            "yearEndColumns":["yearModulo400","days","nextCycle",
                              "nextYearModulo400","cycleDay","ordinal"],
            "yearEndRowFormat":"space-separated decimal integers",
            "yearEndRows":year_end,"callerCarryRows":gate_rows,
            "fixedDuration":{"binary64Bits":hex(bits),"exponent":exp,
                             "integer":integer,"fractionBits":fraction,
                             "nanoseconds":nanos,"recoveredSeconds":recovered},
            "boundaryExamples":boundaries,
            "counterexampleToUniversalMaximum":{"fallback":fallback,
                                                "extendedCurrent":counterexample,
                                                "currentStrictlyGreater":True},
            "limitations":"The native-to-formula argument, input canonicality, memory and ABI premises require review; no general duration/calendar or runtime proof."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    require(not a.output.exists(),"output already exists; preserve receipts")
    result=certificate(Image(a.binary.read_bytes()))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_bytes(encoded(result))
    print("Complete finite domains and 400 year-end cases passed; no instruction evaluation.")

if __name__=="__main__":
    main()
