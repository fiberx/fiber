#!/usr/bin/python

import sys

def get_match_inf(mf,limit):
    res = {}
    s_time = 0.0
    cve_vec = []
    with open(mf,'r') as f:
        #e.g. CVE-2014-0206-sig-0 0 5.06
        for r in f:
            tokens = r.split(' ')
            sig = tokens[0]
            cnt = int(tokens[1])
            time = float(tokens[2])
            stks = sig.split('-')
            if len(stks) == 5:
                cve = sig[:-6]
                ind = int(sig[-1])
            elif len(stks) == 6:
                cve = sig[:-8]
                ind = int(sig[-3])
            else:
                print 'Invalid line: ' + r
                continue
            if ind > limit:
                continue
            s_time += time
            if not cve_vec or cve <> cve_vec[-1]:
                cve_vec += [cve]
            old_cnt = res.setdefault(cve,{}).get(ind,(10000,0))[0]
            res.setdefault(cve,{})[ind] = (min(cnt,old_cnt),time)
    return (res,s_time,cve_vec)

#sys.argv[1]: The base match result (match against the src kernel itself)
#sys.argv[2]: The reverse base match result (match against un-patched src kernel)
#sys.argv[3]: The target match result
#sys.argv[4]: limit
#sys.argv[5]: ground truth file
def analyze_res():
    limit = int(sys.argv[4])
    (b_res,b_time,_) = get_match_inf(sys.argv[1],limit)
    (r_res,r_time,_) = get_match_inf(sys.argv[2],limit)
    (t_res,t_time,t_vec) = get_match_inf(sys.argv[3],limit)
    #Compare the b_res and r_res to filter out those signatures that are not unique at binary level.
    for c in b_res:
        if not c in r_res:
            continue
        #Pick out those different signatures, but if all are the same, then just reserve them.
        sig_ind = []
        for ind in b_res[c]:
            if b_res[c][ind][0] > r_res[c][ind][0]:
                sig_ind += [ind]
        if sig_ind:
            for ind in list(b_res[c]):
                if not ind in sig_ind:
                    b_res[c].pop(ind)
        else:
            #It means that for this cve, our signatures cannot differentiate base and reverse base kernel image.
            #Maybe it's because they both have been patched, maybe it's picker's fault.
            print 'No difference sig: ' + c
    print 'base time: %f' % b_time
    print 'target time: %f' % t_time
    f_res = []
    for c in t_vec:
        flag = False
        for ind in t_res[c]:
            if not ind in b_res[c]:
                continue
            if t_res[c][ind][0] >= b_res[c][ind][0]:
                flag = True
        f_res += [(c,'P' if flag else 'N')]
        #print c + (' P' if flag else ' N')
    if len(sys.argv) < 6:
        #No ground truth file is supplied, then simply output our test results.
        for c in f_res:
            print '%s %s' % c
    else:
        #Obtain ground truth.
        answer = {}
        with open(sys.argv[5],'r') as gtf:
            for l in gtf:
                l = l.strip()
                tokens = l.split(' ')
                answer[tokens[0]] = tokens[1]
        err = 0
        for c in f_res:
            if c[1] <> answer[c[0]] and answer[c[0]] <> 'X':
                print '%s %s #' % c
                err += 1
            else:
                print '%s %s' % c
        print 'Err: %d' % err

#Picker and translator can generate candidate signatures from a certain patch, then we need to test the uniqueness
#and performance of these signatures by matching them against patched and unpatched reference kernels. This function
#will analyze the test results, filter out non-unique signatures and rank unique signatures by performance. 
#sys.argv[1]: match result against patched kernel
#sys.argv[2]: match result against unpatched kernel
#output: the match list that can be used to test target kernel images
def analyze_sig_verify_res():
    limit = 6
    (b_res,b_time,_) = get_match_inf(sys.argv[1],limit)
    (r_res,r_time,_) = get_match_inf(sys.argv[2],limit)
    #Compare the b_res and r_res to filter out those signatures that are not unique at binary level.
    for c in sorted(list(b_res)):
        if not c in r_res:
            continue
        #Pick out those different signatures, but if all are the same, then just reserve them.
        sig_ind = []
        for ind in b_res[c]:
            if not ind in r_res[c]:
                sys.stderr.write('%s-sig-%d does not exist in the match result of unpatched reference kernel.\n' % (c,ind))
                continue
            if b_res[c][ind][0] > max(r_res[c][ind][0],0):
                sig_ind += [ind]
        if sig_ind:
            for ind in sorted(sig_ind,key=lambda x:b_res[c][x][1]):
                print '%s-sig-%d %d' % (c,ind,b_res[c][ind][0])
        else:
            #It means that for this cve, our signatures cannot differentiate base and reverse base kernel image.
            #Maybe it's because they both have been patched, maybe it's simply that all signatures are not unique. 
            for ind in sorted(list(b_res[c]),key=lambda x:b_res[c][x][1]):
                print '#%s-sig-%d %d' % (c,ind,b_res[c][ind][0])

def _parse_cve_from_file(f):
    s = set()
    with open(f,'r') as fi:
        for l in fi:
            l = l.strip()
            t = l.split(' ')[0]
            t = t[t.rfind('/')+1:]
            if t.count('-') == 2:
                cve = t
            elif t.count('-') > 2:
                tks = t.split('-')
                cve = '-'.join(tks[:3])
            else:
                continue
            s.add(cve)
    return s

#Given two files, identify which CVEs are missing from 1st file to the 2nd.
def miss_cve_analysis(f1,f2):
    s1 = _parse_cve_from_file(f1)
    s2 = _parse_cve_from_file(f2)
    print 'Set 1: %d, Set 2: %d' % (len(s1),len(s2))
    for c in s1 - s2:
        print c

def print_time_vec(t_vec):
    v = sorted(t_vec)
    for i in v:
        print i
    print 'cnt: %d' % len(v)
    print 'sum: %f' % sum(v)
    step = len(v)/10
    print '10th:'
    for i in range(step-1,len(v),step):
        print v[i]
    print 'Max: %f' % v[-1]

def analyze_time_ext(res):
    t_vec = []
    with open(res,'r') as f:
        for l in f:
            #No subsub sigs in these files.
            #[sig] time
            l = l.strip()
            tks = l.split(' ')
            t_vec += [float(tks[1])]
    print_time_vec(t_vec)

def analyze_time_match(res,train=False):
    inf = {}
    with open(res,'r') as f:
        for r in f:
            tokens = r.split(' ')
            sig = tokens[0]
            cnt = int(tokens[1])
            time = float(tokens[2])
            stks = sig.split('-')
            if len(stks) == 5:
                cve = sig[:-6]
                ind = int(sig[-1])
            elif len(stks) == 6:
                cve = sig[:-8]
                ind = int(sig[-3])
            else:
                print 'Invalid line: ' + r
                continue
            (old_c,old_t) = inf.setdefault(cve,{}).get(ind,(10000,10000.0))
            inf.setdefault(cve,{})[ind] = (min(old_c,cnt),min(old_t,time))
    #Data used in training phase.
    #Time of every signature.
    t_vec = []
    for c in inf:
        for i in inf[c]:
            t_vec += [inf[c][i][1]]
    #Data used in online matching phase.
    #Per-CVE matching time, in optimized order.
    m_vec = []
    for c in inf:
        v = []
        for i in inf[c]:
            v += [inf[c][i]]
        v = sorted(v,key=lambda x:x[1])
        s = 0.0
        for i in v:
            s += i[1]
            if i[0] > 0:
                break
        m_vec += [s]
    if train:
        print_time_vec(t_vec)
    else:
        print_time_vec(m_vec)

if __name__ == '__main__':
    #analyze_time_ext(sys.argv[1])
    #analyze_time_match(sys.argv[1],False)
    #analyze_res()
    analyze_sig_verify_res()
    #miss_cve_analysis(sys.argv[1],sys.argv[2])
