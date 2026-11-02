"""Read retained native records; no instruction evaluation."""
from pathlib import Path
import json, struct
HERE=Path(__file__).resolve().parent
SUMMARY=json.loads((HERE/'observed/summary.json').read_bytes())
def ranges():
    return [dict(row,gnu=(HERE/'observed/records'/(row['label']+'.txt')).read_text()) for row in SUMMARY['ranges']]
def data(va):return next(row for row in SUMMARY['data'] if int(row['va'],16)==va)
def table(va,count):
    row=data(va);raw=bytes.fromhex(row['bytes'])
    if len(raw)!=count*4:raise ValueError('Wrong signed table extent')
    return dict(row,destinations=[hex(va+struct.unpack_from('<i',raw,i*4)[0]) for i in range(count)])
