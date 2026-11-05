"""The configured wire profile is independent of the installed tools package version."""
import hashlib
import json

PROFILE = '2.0'
TOOLS_REF = 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'
GO_REF = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'


def inspect(params):
    required = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'I1'}
    if not required.issubset(params): raise ValueError('Incomplete AWG 2.0 wire profile')
    numeric = {key: int(params[key]) for key in ('Jc','Jmin','Jmax','S1','S2','S3','S4')}
    if not 0 <= numeric['Jmin'] <= numeric['Jmax'] <= 65535: raise ValueError('Invalid AWG padding range')
    if numeric['S1'] + 56 == numeric['S2']: raise ValueError('Overlapping AWG handshake sizes')
    ranges=[]
    for key in ('H1','H2','H3','H4'):
        values = list(map(int, str(params[key]).split('-')))
        low, high = values[0], values[-1]
        if not 0 <= low <= high < 2**32 or any(low <= b and high >= a for a,b in ranges):
            raise ValueError('Invalid or overlapping AWG header ranges')
        ranges.append((low,high))
    return {'wire_profile': PROFILE, 'tools_source': TOOLS_REF, 'engine_source': GO_REF,
            'parameters_sha256': hashlib.sha256(json.dumps(params,sort_keys=True).encode()).hexdigest()}
