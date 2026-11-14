"""Prints the watch events run.sh kept, in the order kubectl got them."""
import json
from pathlib import Path
import sys


def events(path):
    text, dec, i = path.read_text(), json.JSONDecoder(), 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return
        try:
            ev, i = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            yield {'type': 'TEXT', 'text': text[i:].strip()}
            return
        yield ev


def job_line(o):
    st = o.get('status', {})
    conds = ['%s=%s(%s, %s)' % (c['type'], c['status'], c.get('reason', ''), c.get('lastTransitionTime', ''))
             for c in st.get('conditions', [])]
    return 'active=%s failed=%s terminating=%s conditions=[%s]' % (
        st.get('active', 0), st.get('failed', 0), st.get('terminating', '-'), '; '.join(conds))


def pod_line(o):
    md, st = o['metadata'], o.get('status', {})
    out = 'phase=%s reason=%s deletionTimestamp=%s' % (st.get('phase'), st.get('reason', ''),
                                                        md.get('deletionTimestamp', '-'))
    for cs in st.get('containerStatuses', []):
        for k, v in cs.get('state', {}).items():
            if k == 'terminated':
                msg = v.get('message', '')
                out += ' %s: terminated exitCode=%s reason=%s finishedAt=%s message=%s' % (
                    cs['name'], v.get('exitCode'), v.get('reason'), v.get('finishedAt'),
                    json.dumps(msg[:300]) if msg else '(empty)')
            else:
                out += ' %s: %s %s' % (cs['name'], k, v.get('reason', ''))
    return out


here = Path(sys.argv[1])
for which in ('supervisor', 'bare'):
    print('== %s' % which)
    for kind in ('job', 'pod'):
        print('-- %s events (%s.%s-events.json)' % (kind, which, kind))
        for n, ev in enumerate(events(here / ('%s.%s-events.json' % (which, kind))), 1):
            if ev['type'] == 'TEXT':
                print('%2d  %s' % (n, ev['text'][:300]))
                continue
            o = ev['object']
            line = job_line(o) if kind == 'job' else pod_line(o)
            print('%2d  %-8s rv=%s %s' % (n, ev['type'], o['metadata'].get('resourceVersion'), line))
