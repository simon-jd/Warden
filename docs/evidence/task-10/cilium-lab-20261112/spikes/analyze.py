import sys
d=sys.argv[1] if len(sys.argv)>1 else '.'
import os
os.chdir(d)
t0=float(open('t0').read()); t1=float(open('t1').read()); t2=float(open('t2').read()); t3=float(open('t3').read())
print('label cmd took', round((t1-t0)*1000), 'ms; release at +', round(t3-t0,2))
srv=[l.split() for l in open('server.log') if l.strip()]
for f in srv:
    if len(f)>=2 and f[1] in ('open','close'): print('server', round(float(f[0])-t0,3), ' '.join(f[1:]))
def series(name):
    return [float(f[0]) for f in srv if len(f)>=4 and f[1]=='rx' and f[3]==name]
for nm,log in ((sys.argv[2],'t.log'),(sys.argv[3],'c.log')):
    up=series(nm)
    down=[]; other=[]
    for l in open(log):
        f=l.split()
        if len(f)>=3 and f[1]=='rx' and f[2]=='hb': down.append(float(f[0]))
        elif len(f)>=2 and f[1]!='rx': other.append(str(round(float(f[0])-t0,3))+' '+' '.join(f[1:]))
    print(nm,'up n',len(up),'down n',len(down))
    for lab,ts in (('up',up),('down',down)):
        before=[x for x in ts if t0<=x<t3]
        after=[x for x in ts if x>=t3]
        gaps=sorted(b-a for a,b in zip(sorted(before),sorted(before)[1:]))
        print(' ',lab,'last in [t0,t3):', round(max(before)-t0,3) if before else None, 'count [t0+1,t3):', sum(1 for x in ts if t0+1<=x<t3),
              'first after release:', round(min(after)-t3,3) if after else None, 'n after', len(after), 'maxgap', round(gaps[-1],3) if gaps else None)
    print('  other', other[:6])
