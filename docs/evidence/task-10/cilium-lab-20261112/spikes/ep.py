import json,sys
d=sys.argv[1]
ip=open(d+'/info').read().split()[1]
for f in ('ep-before.json','ep-during.json'):
    for e in json.load(open(d+'/'+f)):
        a=[x.get('ipv4') for x in e['status']['networking']['addressing']]
        if ip in a:
            st=e['status']
            print(f, e['id'], st['identity']['id'], [l for l in st['identity']['labels'] if 'warden' in l], st['policy']['realized'].get('policy-revision'), st['policy']['realized'].get('policy-enabled'))
