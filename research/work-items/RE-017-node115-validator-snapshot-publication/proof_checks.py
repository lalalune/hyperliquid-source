#!/usr/bin/env python3
"""Check the calendar algebra, not captured instructions or an instruction emulator."""
import json

def native_calendar_terms(year, ordinal):
    # High-level arithmetic read from36cabc3..36cac36 (and its new-time copy).
    previous = year - 1
    cycles = (1-year)//400 + 1 if year <= 0 else 0
    previous += 400*cycles
    century = previous//100
    return (1461*previous)//4 - century + century//4 + ordinal - 146097*cycles - 719163

def civil_days(year, ordinal):
    y=year-1
    return 365*y+y//4-y//100+y//400+ordinal-719163

def main():
    count=0
    for year in range(-262144,262144):
        for ordinal in (1,59,60,365,366):
            assert native_calendar_terms(year,ordinal)==civil_days(year,ordinal)
            count+=1
    # Direct anchors and deliberate negative-year-cycle/Unix-constant corruption.
    assert native_calendar_terms(1970,1)==0
    assert native_calendar_terms(2000,60)==11016
    assert native_calendar_terms(0,1)==-719528
    assert native_calendar_terms(0,1)+146097 != civil_days(0,1)
    assert native_calendar_terms(1970,1)+1 != civil_days(1970,1)
    print(json.dumps({'calendar_formula_cases':count,'logical_corruption_controls':2,'target_execution':False},indent=2))

if __name__=='__main__':main()
