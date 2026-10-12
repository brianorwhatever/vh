"""Independent issue #7 construction: stdlib only, no VH-Log implementation.

Uses RFC 8032 Edwards arithmetic for known-scalar signatures. This is test
construction, NOT production cryptography (variable-time; public scalars).
Run python3 tools/ed25519-fixtures.py to regenerate boundary fixtures.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
IDENTITY = (0, 1)


def decode(b):
    n = int.from_bytes(b, 'little')
    y = (n & (2**255 - 1)) % P
    x2 = (y*y - 1) * pow(D*y*y + 1, -1, P) % P
    x = pow(x2, (P+3)//8, P)
    if x*x % P != x2:
        x = x * pow(2, (P-1)//4, P) % P
    assert x*x % P == x2
    if x % 2 != n >> 255:
        x = -x % P
    return x, y


def add(a, b):
    x, y = a
    u, v = b
    t = D*x*u*y*v % P
    return ((x*v+y*u)*pow(1+t, -1, P) % P,
            (y*v+x*u)*pow(1-t, -1, P) % P)


def mul(a, n):
    r = IDENTITY
    while n:
        if n & 1:
            r = add(r, a)
        a = add(a, a)
        n >>= 1
    return r


def encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


B = decode(bytes.fromhex('58' + '66'*31))
# Known, nonzero prime-subgroup scalar. No secret material is involved.
A = encode(B)
R = encode(mul(B, 2))


def b58(b):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(b, 'big')
    s = ''
    while n:
        n, r = divmod(n, 58)
        s = alphabet[r] + s
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + s


def jcs(obj):
    # Fixture domain: ASCII keys, strings, small integers. RFC 8785 reduces to this.
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def digest(obj):
    return hashlib.sha256(jcs(obj)).digest()


def hash58(obj):
    return b58(b'\x12\x20' + digest(obj))


def key(a):
    return 'z' + b58(b'\xed\x01' + a)


def proof(doc, a=A, r=R, scalar=None):
    mk = key(a)
    config = dict(type='DataIntegrityProof', cryptosuite='eddsa-jcs-2022',
                  verificationMethod=f'did:key:{mk}#{mk}', proofPurpose='assertionMethod')
    message = digest(config) + digest(doc)
    k = int.from_bytes(hashlib.sha512(r+a+message).digest(), 'little') % L
    s = (2+k) % L if scalar is None else scalar(k)
    return dict(config, proofValue='z'+b58(r+s.to_bytes(32, 'little')))


def genesis(a=A, witness=None, nonce=0):
    params = dict(logVersion='vh-log:1.0', scid='{SCID}', updateKeys=[key(a)])
    if witness:
        params['witness'] = dict(threshold=1, witnesses=[dict(id='did:key:'+key(witness))])
    doc = dict(versionId='{SCID}', versionTime='2026-01-01T00:00:00Z',
               parameters=params, state=dict(id='example:{SCID}', nonce=nonce))
    scid = hash58(doc)
    doc = json.loads(json.dumps(doc).replace('{SCID}', scid))
    doc['versionId'] = '1-' + hash58(doc)
    return doc


cases = []

def append(name, doc, p, valid, witness=None):
    log = json.dumps(dict(doc, proof=[p]), separators=(',', ':'))+'\n'
    cases.append(dict(name=name, op='verify', input=dict(document=doc, proof=p),
                      expected=dict(valid=valid)))
    inp = dict(log=log, now='2026-06-01T00:00:00Z')
    if witness is not None:
        inp['witness'] = witness
    cases.append(dict(name=name, op='resolve', input=inp,
                      expected=dict(valid=valid, error=None if valid else 'invalid-proof')))


doc = genesis()
append('ordinary-known-scalar-control', doc, proof(doc), True)
# Ordinary RFC 8032 seed-derived signing control, independently implemented.
seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
h = hashlib.sha512(seed).digest()
secret = (int.from_bytes(h[:32], 'little') & ((1 << 254) - 8)) | (1 << 254)
a = encode(mul(B, secret))
doc = genesis(a)
mk = key(a)
config = dict(type='DataIntegrityProof', cryptosuite='eddsa-jcs-2022',
              verificationMethod=f'did:key:{mk}#{mk}', proofPurpose='assertionMethod')
message = digest(config) + digest(doc)
r_scalar = int.from_bytes(hashlib.sha512(h[32:]+message).digest(), 'little') % L
r = encode(mul(B, r_scalar))
p = proof(doc, a, r, lambda k: (r_scalar + k*secret) % L)
append('ordinary-RFC8032-seed-control', doc, p, True)
tampered = dict(doc, state=dict(id='changed'))
append('tampered-ordinary-signature', tampered, p, False)

# Low-order encodings independently sourced from CCTV README, including aliases.
source = json.loads((ROOT/'vectors/ed25519/cctv.json').read_text())
low = sorted({v['key'] for v in source if 'low_order_A' in (v['flags'] or [])})
assert len(low) == 14
for h in low:
    a = bytes.fromhex(h)
    doc = genesis(a)
    append('low-order-A-'+h, doc, proof(doc, a, A, lambda k: 1), False)
    doc = genesis()
    append('low-order-R-'+h, doc, proof(doc, A, a, lambda k: k), False)

for name, s in [('S-equals-L', lambda k: L), ('S-plus-L', lambda k: (2+k) % L + L)]:
    doc = genesis()
    append(name, doc, proof(doc, scalar=s), False)

# Explicit on-curve decoding failure and field boundary encodings.
for name, a in [('off-curve', (2).to_bytes(32,'little')), ('y-equals-p', P.to_bytes(32,'little'))]:
    doc = genesis(a)
    append(name+'-A', doc, proof(doc, a), False)
    doc = genesis()
    append(name+'-R', doc, proof(doc, r=a), False)

# Mixed-order points: nontrivial prime-order components are admissible,
# but the torsion residue must cancel in the UNCOFACTORED equation.
torsion = decode(bytes.fromhex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'))
for mixed_a, mixed_r in [(True, False), (True, True), (False, True)]:
    a = encode(add(B, torsion)) if mixed_a else A
    r = encode(add(mul(B, 2), torsion)) if mixed_r else R
    for valid in ([True, False] if mixed_a else [False]):
        for nonce in range(256):
            doc = genesis(a, nonce=nonce)
            mk = key(a)
            config = dict(type='DataIntegrityProof', cryptosuite='eddsa-jcs-2022',
                          verificationMethod=f'did:key:{mk}#{mk}', proofPurpose='assertionMethod')
            k = int.from_bytes(hashlib.sha512(r+a+digest(config)+digest(doc)).digest(), 'little') % L
            equation = mul(B, (2+k) % L) == add(decode(r), mul(decode(a), k))
            if equation == valid:
                append(f'mixed-A-{mixed_a}-R-{mixed_r}-valid-{valid}', doc, proof(doc, a, r), valid)
                break
        else:
            raise AssertionError('could not construct mixed-order fixture')

# Witness threshold uses the same policy; an honest entry cannot lend validity
# to a degenerate witness. Include a valid witness control.
for name, a, r, scalar, valid in [('valid-witness', A, R, None, True),
        ('identity-witness', encode(IDENTITY), A, lambda k: 1, False)]:
    doc = genesis(witness=a)
    p = proof(doc)
    w = [dict(versionId=doc['versionId'], proof=[proof(dict(versionId=doc['versionId']), a, r, scalar)])]
    inp = dict(log=json.dumps(dict(doc, proof=[p]), separators=(',', ':'))+'\n',
               witness=w, now='2026-06-01T00:00:00Z')
    cases.append(dict(name=name, op='resolve', input=inp,
                      expected=dict(valid=valid, error=None if valid else 'witness-threshold-not-met')))

# Partial validity: a weak key is syntactically authorised by an honest
# genesis proof; using it in entry two must fail at the proof step.
weak = encode(IDENTITY)
base = genesis(weak)
# Both keys must be committed before computing SCID and entry hash.
params = dict(logVersion='vh-log:1.0', scid='{SCID}', updateKeys=[key(A), key(weak)])
base = dict(versionId='{SCID}', versionTime='2026-01-01T00:00:00Z',
            parameters=params, state=dict(id='example:{SCID}'))
scid = hash58(base)
base = json.loads(json.dumps(base).replace('{SCID}', scid))
base['versionId'] = '1-' + hash58(base)
second = dict(versionId=base['versionId'], versionTime='2026-01-02T00:00:00Z',
              parameters={}, state=dict(id=base['state']['id'], changed=True))
second['versionId'] = '2-' + hash58(second)
log = '\n'.join(json.dumps(dict(d, proof=[p]), separators=(',', ':')) for d,p in
                [(base,proof(base)),(second,proof(second,weak,A,lambda k: 1))])+'\n'
for target, valid in [(None, True), (1, True), (2, False)]:
    inp = dict(log=log, now='2026-06-01T00:00:00Z')
    if target is not None:
        inp['options'] = dict(versionNumber=target)
    expected = dict(valid=valid, error='invalid-proof')
    if valid:
        expected['firstInvalidVersion'] = 2
    cases.append(dict(name=f'partial-validity-target-{target}', op='resolve', input=inp, expected=expected))

(ROOT/'vectors/ed25519/boundaries.json').write_text(json.dumps(cases, indent=2)+'\n')
print(f'wrote {len(cases)} independent proof/resolver cases')
