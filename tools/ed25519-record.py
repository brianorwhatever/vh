"""Retain issue #7 Python/Node raw-library and resolver observations as JSON.

--root may point to an unmodified archive of the audited commit. Expected
results come from the checked-in independent corpus, not either verifier.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, default=HERE)
p.add_argument('--commit', required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
root = a.root.resolve()
cases = json.loads((HERE/'vectors/ed25519/boundaries.json').read_text())
corpus = json.loads((HERE/'vectors/ed25519/cctv.json').read_text())
reject = {'low_order_A', 'low_order_R', 'non_canonical_A', 'non_canonical_R', 'low_order_residue'}
raw = [dict(id='CCTV-'+str(v['number']), key=v['key'], sig=v['sig'], msg=v['msg'].encode().hex(),
            expected=not reject.intersection(v['flags'] or [])) for v in corpus]
for g in json.loads((HERE/'vectors/ed25519/wycheproof.json').read_text())['testGroups']:
    raw += [dict(id='Wycheproof-'+str(v['tcId']), key=g['publicKey']['pk'], sig=v['sig'], msg=v['msg'],
                 expected=v['result']=='valid') for v in g['tests']]

def run(cmd, cwd, data=''):
    return subprocess.run(cmd, cwd=cwd, input=data, text=True, capture_output=True, check=True).stdout

record = dict(commit=a.commit, platform=os.uname().sysname+' '+os.uname().release+' '+os.uname().machine,
              fixture_sha256=hashlib.sha256((HERE/'vectors/ed25519/boundaries.json').read_bytes()).hexdigest(),
              implementations={})
for name in ['typescript', 'python']:
    cwd = root/'implementations'/name
    if name == 'typescript':
        versions = json.loads(run(['node','-p','JSON.stringify(process.versions)'],cwd))
        command = ['node','src/driver.ts']
        script = """import {verifySignature} from './src/ed25519.ts';
import {readFileSync} from 'node:fs';
console.log(JSON.stringify(JSON.parse(readFileSync(0,'utf8')).map(v=>verifySignature(Buffer.from(v.key,'hex'),Buffer.from(v.msg,'hex'),Buffer.from(v.sig,'hex')))));"""
        direct = ['node','--input-type=module','-e',script]
    else:
        run(['uv','sync','--quiet'],cwd)
        versions = json.loads(run(['uv','run','--no-sync','python','-c',
            'import json,sys,cryptography; from cryptography.hazmat.backends.openssl.backend import backend; print(json.dumps(dict(python=sys.version,cryptography=cryptography.__version__,openssl=backend.openssl_version_text())))'],cwd))
        command = ['uv','run','--no-sync','python','-m','vh_log.driver']
        direct = ['uv','run','--no-sync','python','-c',
            'import sys,json; from vh_log.ed25519 import verify_signature; print(json.dumps([verify_signature(bytes.fromhex(v["key"]),bytes.fromhex(v["msg"]),bytes.fromhex(v["sig"])) for v in json.load(sys.stdin)]))']
    actual_raw = json.loads(run(direct,cwd,json.dumps(raw)))
    assert len(actual_raw) == len(raw)
    groups = defaultdict(list)
    for v, r in zip(raw, actual_raw):
        groups[(v['expected'], r)].append(v['id'])
    responses = [json.loads(s) for s in run(command,cwd,''.join(json.dumps(dict(id=i,op=v['op'],input=v['input']))+'\n' for i,v in enumerate(cases))).splitlines()]
    assert len(responses) == len(cases)
    record['implementations'][name] = dict(versions=versions,
        raw_library=[dict(expected=expected,actual=actual,count=len(ids),ids=ids) for (expected,actual),ids in groups.items()],
        boundaries=[dict(name=v['name'],op=v['op'],expected=v['expected'],actual=dict(
            firstInvalidVersion=r.get('result',{}).get('firstInvalidVersion'),ok=r['ok'],valid=r.get('result',{}).get('valid'),error=(r.get('result',{}).get('error') or {}).get('code')))
            for v,r in zip(cases,responses)])
a.out.write_text(json.dumps(record,indent=2)+'\n')
print(a.out)
