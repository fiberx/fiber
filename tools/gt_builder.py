#!/usr/bin/python

import sys

def split_patch(p):
    inf = {}
    with open(p,'r') as f:
        p_buf = f.readlines()
    diff_index = [i for i in range(len(p_buf)) if p_buf[i].startswith('diff')] + [len(p_buf)]
    for i in range(len(diff_index)-1):
        st = diff_index[i]
        ed = diff_index[i+1]
        #First get the changed source file
        fp = None
        fn = None
        for j in range(st,ed):
            if fp is not None and fn is not None:
                break
            if p_buf[j].startswith('---'):
                fn = p_buf[j][6:].strip()
            elif p_buf[j].startswith('+++'):
                fp = p_buf[j][6:].strip()
        inf[(fn,fp)] = []
        #Get @@ of this diff
        at_index = [j for j in range(st,ed) if p_buf[j].startswith('@@')] + [ed]
        for j in range(len(at_index)-1):
            inf[(fn,fp)].append(''.join(p_buf[at_index[j]:at_index[j+1]]))
    return inf

#sys.argv[1]: patch list
#user input:
#p: patch exists
#n: patch not exists
#x: patch doesn't apply
#d: next diff
#a: next @@
def build():
    with open(sys.argv[1],'r') as pl:
        res_vec = []
        for p in pl:
            p = p.strip()
            if p[0] == '#':
                continue
            cve = p[p.rfind('/')+1:]
            p_inf = split_patch(p)
            print '>>>>>>>>>>>>>>>>>' + cve + '>>>>>>>>>>>>>>>>>'
            for k in p_inf:
                for at in p_inf[k]:
                    print '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
                    print k[0]
                    print k[1]
                    print at
                    s = raw_input('-->')
                    if s[0] in ('p','n','d','x'):
                        break
                if s[0] in ('p','n','x'):
                    break
            if not s[0] in ('p','n','x'):
                print '!! All @@ sections have been iterated, plz make a p/n/x decision'
                s = raw_input('-->')
            res_vec += [(cve,s[0].capitalize())]
            print '=============================================='
            for t in res_vec:
                print '%s %s' % t
            print '=============================================='

if __name__ == '__main__':
    build()
