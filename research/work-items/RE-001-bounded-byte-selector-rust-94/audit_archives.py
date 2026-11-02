#!/usr/bin/env python3
"""Check both retained raw-stream archives and deliberate archive corruptions."""
import gzip
import json
import tempfile
from pathlib import Path
from verify import HERE,archive_check,sha,require

def main():
    initial=HERE/'initial';meta=json.loads((initial/'result.json').read_text());a=json.loads(gzip.decompress((initial/'raw-streams.json.gz').read_bytes()))
    expected={x['name']:x['sha256'] for x in meta['streams']}
    require(len(a['streams'])==len(expected) and {x['name'] for x in a['streams']}==set(expected),'initial archive labels')
    for stream in a['streams']:
        raw=''.join(a['lines'][i] for i in stream['line_ids']).encode('ascii')
        require(len(raw)==stream['bytes'] and sha(raw)==stream['sha256']==expected[stream['name']],'initial archive integrity')
    result=json.loads((HERE/'native/result.json').read_text());path=HERE/'native/raw-streams.json.gz';count=archive_check(path,result)
    controls=[]
    with tempfile.TemporaryDirectory(prefix='byte-selector-archive-') as temp:
        for name in ('byte-count','line-index'):
            a=json.loads(gzip.decompress(path.read_bytes()))
            if name=='byte-count':a['streams'][0]['bytes']+=1
            else:a['streams'][0]['line_ids'][0]=len(a['lines'])
            bad=Path(temp)/'bad.json.gz';bad.write_bytes(gzip.compress(json.dumps(a).encode('ascii'),mtime=0))
            try:archive_check(bad,result)
            except ValueError as error:controls.append({'name':name,'rejection':str(error)})
            else:raise ValueError('archive control survived')
    print(json.dumps({'initial_exact_streams':len(expected),'final_exact_streams':count,'controls':controls},indent=2))
if __name__=='__main__':main()
