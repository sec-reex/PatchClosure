#!/usr/bin/env python3
"""Assemble smoke-test packages for build_guide.py (mimics runner/package.sh layout).
Uses only case_id lookup from case.json for the v1_sources slug; ships no secrets.
"""
import json, os, re, shutil, sys

REPO = '.'

def make(cid):
    case = os.path.join(REPO, 'benchmark/cases', cid)
    meta = json.load(open(os.path.join(case, 'case.json')))
    slug = meta['case_id']
    v1 = os.path.join(REPO, 'benchmark/v1_sources', slug)
    pkg = f'/tmp/pcg_smoke/{cid}'
    shutil.rmtree(pkg, ignore_errors=True)
    os.makedirs(pkg + '/poc'); os.makedirs(pkg + '/work')
    with open(os.path.join(case, 'patch.diff'), errors='replace') as f:
        txt = f.read()
    lines = txt.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('diff --git'):
            txt = "\n".join(lines[i:]); break
    with open(pkg + '/patch.diff', 'w') as f:
        f.write(txt)
    shutil.copy(os.path.join(case, 'poc/original_poc.py'), pkg + '/poc/original_test.py')
    if os.path.isdir(v1):
        os.symlink(v1, pkg + '/v1_source')
    else:
        os.makedirs(pkg + '/v1_source')
        print(f'WARN: no v1_source for {slug}')
    with open(pkg + '/env.json', 'w') as f:
        f.write('{"port": 41000}\n')
    print('ok', pkg, 'v1=', bool(os.path.isdir(v1)))

if __name__ == '__main__':
    for cid in sys.argv[1:]:
        make(cid)
