#!/usr/bin/env python3
"""Reconstruct exact stdout and reject two deliberate archive corruptions."""
import gzip
import json
import tempfile
from pathlib import Path
from verify import HERE,archive_check

def main():
    result=json.loads((HERE/'native/result.json').read_text());path=HERE/'native/raw-streams.json.gz';count=archive_check(path,result);controls=[]
    initial=archive_check(HERE/'initial/raw-streams.json.gz',json.loads((HERE/'initial/result.json').read_text()))
    with tempfile.TemporaryDirectory(prefix='unsigned-clamp-archive-') as temp:
        for name in ('byte-count','line-index'):
            a=json.loads(gzip.decompress(path.read_bytes()))
            if name=='byte-count':a['streams'][0]['bytes']+=1
            else:a['streams'][0]['line_ids'][0]=len(a['lines'])
            bad=Path(temp)/'bad.json.gz';bad.write_bytes(gzip.compress(json.dumps(a).encode('ascii'),mtime=0))
            try:archive_check(bad,result)
            except ValueError as error:controls.append({'name':name,'rejection':str(error)})
            else:raise ValueError('archive control survived')
    print(json.dumps({'final_exact_streams':count,'initial_exact_streams':initial,'controls':controls},indent=2))
if __name__=='__main__':main()
