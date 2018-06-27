#!/usr/bin/python
#Given a patch file, this program aims to pick the best change-sites to use as signatures.
#sys,argv[1]: path/to/patch_list
#sys.argv[2]: path/to/kernel-source
#sys.argv[3]: path/to/output_file
#sys.argv[4:]: symbol tables for kernels (can provide multiple)

import sys
from sym_table import Sym_Table
from src_parser import *
import time

#TODO List:
#(1) Patches with '#if' '#else', e.g. CVE-2015-8839

dbg_out = True
#The goal of this function is to generate a list, each entry is line numbers in source kernel files that we can use to
#extract a signature. This is generated according to the patch information and simply specify the changed lines as candidates.
def generate_line_candidates(p_inf):
    cands = []
    for k in p_inf:
        if p_inf[k]['type'] == 'aft':
            if 'add' in p_inf[k]:
                for t in p_inf[k]['add']:
                    cand = {'file':k[0],'func':k[1],'func_range':p_inf[k]['func_range']}
                    cand['line'] = t
                    cands += [cand]
            else:
                #This is a pure deletion patch.
                #TODO: One possibility is that we can utilize the 'bridge' between lines before and after the deletion site created by the patch.
                pass
        else:
            #The src kernel is pre-patched version.
            #TODO: we may do this later.
            pass
    return cands

def _is_decl_cand(cand):
    src = src_map[cand['file']]
    (i,j) = cand['line']
    while i <= j:
        tags = classify_line(src[i])
        if not 'decl' in tags:
            return False
        elif 'call' in tags:
            #If it's something like 'int a=func()', we may still want to use the func invocation as the signature.
            return False
        i += 1
    return True

def _get_tag_for_line(l,f_inf):
    tag = {}
    for k in f_inf:
        for e in f_inf[k]:
            if l >= e[0] and l <= e[1]:
                #The 'range' is st and ed line No.
                inf = {'range':(e[0],e[1])}
                if k == 'func':
                    inf['name'] = e[2]
                    inf['args'] = e[3]
                elif k in ('if','while','for'):
                    inf['cond'] = e[2]
                    inf['ed_blk'] = e[3]
                tag.setdefault(k,[]).append(inf)
    return tag

def _get_tags_for_lines(l_range,f_inf):
    tags = {}
    i = l_range[0]
    while i <= l_range[1]:
        tags[i] = _get_tag_for_line(i,f_inf)
        i += 1
    return tags

#Some functions may exist in the symbol table, but in practice they may still be inlined based on the arguments.
#(e.g. if the 'size' argument of memset is small enough.)
ext_inline_list = ['memset','memcpy']
def func_exists(n):
    global sym_tabs
    if n in ext_inline_list:
        return False
    if not sym_tabs:
        return True
    for s in sym_tabs:
        if not s.lookup_func_name(n):
            return False
    return True

fmt_func = ('pr_err','pr_dbg','pr_info','printk','snprintf','write_str')
def _is_fmt_func(name):
    #First we have a whitelist.
    if name in fmt_func:
        return True
    #Then we have some heuristics.
    fmt_func_suff = ('_err','_ERR','_info','_INFO','_dbg','_DBG','_printf','printk')
    for suf in fmt_func_suff:
        if name.endswith(suf):
            return True
    return False

def _is_fmt_str_patch(src,patch,call_inf):
    name = call_inf['name']
    if not _is_fmt_func(name):
        return -1
    rang = call_inf['range']
    o_args = call_inf['args']
    o_call_lines = src[rang[0]:rang[1]+1]
    if patch['type'] == 'aft':
        #The added lines have already been there in 'src', we need to see those deleted lines,
        #whether there are changes for the fmt str arg of the function under inspection.
        if not 'del' in patch:
            #Add some function calls, but not fmt str change.
            return -1
        for k in patch['del']:
            i = max(k[0],rang[0])
            j = min(k[1],rang[1])
            if i > j:
                continue
            call_lines = list(o_call_lines)
            call_lines[i-rang[0]:j+1-rang[0]] = patch['del'][k][i-k[0]:j+1-k[0]]
            if j+1-rang[0] >= len(o_call_lines) and len(patch['del'][k]) > j+1-k[0]:
                #This suggests the deleted lines are more than added lines.
                call_lines += patch['del'][k][j+1-k[0]:]
            c_inf = parse_func_from_str(''.join(call_lines))
            if c_inf is None:
                continue
            if c_inf[0] <> name:
                #The function name itself has been changed.
                return -1
            #Compare o_args and c_args, whether there is fmt str change. 
            #TODO: May refine the heuristics here later.
            c_args = c_inf[1]
            ind = -1
            for (o,c) in zip(o_args,c_args):
                ind += 1
                if (o[0],o[-1]) == ('"','"') or (c[0],c[-1]) == ('"','"'):
                    if o <> c:
                        return ind
            break
    else:
        print '!!! TODO: implement bfr type fmt_str_change detection.'
    return -1

#Sometimes a patch will only change the arguments of a same callee, this function identifies the changed args,
#returning something like (0,1,3) representing the order of changed args.
def _get_changed_args(src,patch,call_inf):
    name = call_inf['name']
    rang = call_inf['range']
    o_args = call_inf['args']
    o_call_lines = src[rang[0]:rang[1]+1]
    res = []
    if patch['type'] == 'aft':
        #The added lines have already been there in 'src', we need to see those deleted lines,
        #whether there are changes for the fmt str arg of the function under inspection.
        if not 'del' in patch:
            #Add some function calls, but not func arg change.
            return res
        for k in patch['del']:
            i = max(k[0],rang[0])
            j = min(k[1],rang[1])
            if i > j:
                continue
            call_lines = list(o_call_lines)
            call_lines[i-rang[0]:j+1-rang[0]] = patch['del'][k][i-k[0]:j+1-k[0]]
            if j+1-rang[0] >= len(o_call_lines) and len(patch['del'][k]) > j+1-k[0]:
                #This suggests the deleted lines are more than added lines.
                call_lines += patch['del'][k][j+1-k[0]:]
            c_inf = parse_func_from_str(''.join(call_lines))
            if c_inf is None:
                continue
            if c_inf[0] <> name:
                #The function name itself has been changed.
                return None
            #Compare o_args and c_args to identify changed args. 
            c_args = c_inf[1]
            i = 0
            for (o,c) in zip(o_args,c_args):
                if o <> c:
                    res.append(i)
                i += 1 
            if len(o_args) > len(c_args):
                res += [i for i in range(len(c_args),len(o_args))]
            elif len(o_args) < len(c_args):
                #(1)If res is null, then we simply have deleted some parameters for the function call now,
                #in this case we should add some contexts to the callee, so return null (current res is null).
                #(2)If res is not null, then there are still some differences in the parameters, we will
                #simply return res.
                #So in either case, we should simply return res.
                pass

    else:
        print '!!! TODO: implement bfr type fmt_str_change detection.'
    return res

def get_aft_patch_func(src,patch):
    (st,ed) = patch['func_range']
    src_func = src[st:ed+1]
    if patch['type'] == 'bfr':
        #The src is bfr-patch version, we should add the 'added' lines and remove 'deleted' lines.
        if 'del' in patch:
            for k in patch['del']:
                src_func[k[0]-st:k[1]+1-st] = ['24K MAGIC'] * (k[1] - k[0] + 1)
        if 'add' in patch:
            for k in patch['add']:
                src_func = src_func[0:k[0]-st] + patch['add'][k] + src_func[k[0]-st:]
        #Delete previously marked deleted lines.
        src_func = filter(lambda x:x <> '24K MAGIC',src_func)
    return src_func

def get_bfr_patch_func(src,patch):
    (st,ed) = patch['func_range']
    src_func = src[st:ed+1]
    if patch['type'] == 'aft':
        #The src is aft-patch version, we should add the 'deleted' lines and remove 'added' lines.
        if 'add' in patch:
            for k in patch['add']:
                src_func[k[0]-st:k[1]+1-st] = ['24K MAGIC'] * (k[1] - k[0] + 1)
        if 'del' in patch:
            for k in patch['del']:
                src_func = src_func[0:k[0]-st] + patch['del'][k] + src_func[k[0]-st:]
        #Delete previously marked added lines.
        src_func = filter(lambda x:x <> '24K MAGIC',src_func)
    return src_func

def _strip_text(t):
    return t.translate(None,' \t\n')

#Test whether certain lines are unique in pre/aft patched functions.
#src: the source code for the target file, which is an array of lines.
#text: the code snippet string to test
#patch: the patch information for the target function.
#strip: whether to trim the white spaces when doing comparison.
def test_uniqueness(src,text,patch,strip=False):
    b_src = get_bfr_patch_func(src,patch)
    a_src = get_aft_patch_func(src,patch)
    b_text = ''.join(b_src)
    a_text = ''.join(a_src)
    if strip:
        text = _strip_text(text)
        b_text = _strip_text(b_text)
        a_text = _strip_text(a_text)
    cnt_b = b_text.count(text)
    cnt_a = a_text.count(text)
    if cnt_a == 0 and cnt_b == 0:
        #Nowhere, so really 'unique'.
        return True
    if patch['type'] == 'aft':
        return cnt_b == 0 and cnt_a > 0
    else:
        return cnt_a == 0 and cnt_b > 0 

#This function test whether a callee and its parameters are unique in the parent function.
def test_uniqueness_func(call_inf,src,patch):
    text = call_inf['name'] + '(' + ','.join(call_inf['args']) + ')'
    return test_uniqueness(src,text,patch,strip=True)

#Test whether a condition is unique between pre- and aft- patched version.
def test_uniqueness_cond(keyword,cond,src,patch):
    #The overall idea is that we shouldn't use strict string comparison to decide
    #uniqueness. E.g. 'a==b' and 'a!=b' are actually the same from the CFG's view.
    c_vec = [cond]
    if cond.count('==') > 0:
        c_vec += [cond.replace('==','!=')]
    if cond.count('!=') > 0:
        c_vec += [cond.replace('!=','==')]
    return all([test_uniqueness(src,x,patch,strip=True) for x in c_vec])

#Add some special options to the candidates according to the call-site information.
#This function is mainly hackings and heuristics.
def add_extra_options(cands,call_inf):
    name = call_inf['name']
    if name in ('memset'):
        for c in cands:
            c.setdefault('opts',{})['match_store_single_mapping'] = 'True'
            if not '+cont' in c['type']:
                #It should be all 'store' 0 instructions, so we must match this '0'.
                c.setdefault('opts',{})['match_sym_conc_policy'] = 'strict'

#We are faced with (maybe) multiple src lines, but in many cases we don't need (and shouldn't) include all of them
#into the signature. We should pick up those most unique (and simple, which means not related to too many BBs) lines. 
def trim_line_candidates(cand,patch):
    #Currently, this function is mainly about my own experience in line selection.
    #That's to say, I will encode my experiences into some heuristics here as guidelines, so we cannot guarantee
    #the 100% success rate. If no experience exists for a certain candidate, we will simply use the original cand lines
    #if they are unique.
    c_file = cand['file']
    c_func = cand['func']
    fi = func_inf[(c_file,c_func,cand['func_range'][0])]
    tags = _get_tags_for_lines(cand['line'],fi)
    res_cand = []
    #H1: any function calls in the candidate lines?
    #TODO: Currently we assume one line only has one function call, this may not be correct..
    line_func = [(k,tags[k]['func'][0]) for k in tags if 'func' in tags[k]]
    line_func = sorted(line_func,key=lambda x:x[0])
    i = 0
    while i < len(line_func):
        l_no = line_func[i][0]
        inf = line_func[i][1]
        name = inf['name']
        args = inf['args']
        rang = inf['range']
        inlined = not func_exists(name)
        fmt_str_patch = _is_fmt_str_patch(src_map[c_file],patch,inf)
        changed_args = _get_changed_args(src_map[c_file],patch,inf)
        func_name_unique = test_uniqueness(src_map[c_file],name+'(',patch,strip=True) 
        #Here the l_no is the first cand line regarding current callee, because we will skip remaining lines in the end of the loop.  
        j = i
        while j+1 < len(line_func) and line_func[j+1][0] <= rang[1]:
            j += 1
        old_len = len(res_cand)
        #line_func[j][0] is the last cand line regarding this callee.
        if fmt_str_patch >= 0:
            #TODO: Do we need to do something special about inlined/non-inlined? Maybe not because in many cases we see function
            #like 'pr_err' is inlined to 'printk', while the later still involves the fmt_str change, the extractor should be able to handle this.
            #First test uniqueness.
            if test_uniqueness(src_map[c_file],args[fmt_str_patch],patch,strip=True):
                c = {'file':c_file,'func':c_func}
                c['line'] = [(rang[0],line_func[j][0])]
                c['opts'] = {'match_fmt_str':'True','trim_tail_call_args':'True'}
                c['type'] = 'fmt_str' if not inlined else 'fmt_str_inline'
                res_cand.append(c)
            else:
                cs = add_context_no_guarantee(src_map[c_file],rang,patch,fi)
                for c in cs:
                    c['file'] = c_file
                    c['func'] = c_func
                    c['type'] = 'fmt_str+cont' if not inlined else 'fmt_str_inline+cont'
                    c.setdefault('opts',{})['match_fmt_str'] = 'True'
                    res_cand.append(c)
        if func_name_unique:
            if inlined:
                #TODO: the callee has a unique name but it will be inlined. *** Maybe we can detect whether it will be inlined in target binary,
                #if not, we can simply 'fabricate' a signature purely about the function name and do the matching, even without symbolic execution.  
                c = {'file':c_file,'func':c_func}
                c['line'] = [(rang[0],line_func[j][0])]
                c['opts'] = {'trim_non_tail_roots':'True'}
                c['type'] = 'func_name_inline'
                res_cand.append(c)
            else:
                #This is an ideal candidate, we simply need to look at whether the function name exists.
                #NOTE: To use this kind of signature, symbol table must be available for the target binary. 
                c = {'file':c_file,'func':c_func}
                c['line'] = [(rang[0],line_func[j][0])]
                c['opts'] = {'func_existence_test':name}
                c['type'] = 'func_name'
                res_cand.append(c)
        if fmt_str_patch >= 0:
            new_len = len(res_cand)
            add_extra_options(res_cand[old_len:new_len],inf)
            i = j + 1
            continue
        is_func_uniq = test_uniqueness_func(inf,src_map[c_file],patch)
        if is_func_uniq and changed_args:
            #The func name plus arg list (i.e. call-site) is unique according to the source code literature.
            #Besides, some arguments have been explicitly changed by the patch. 
            #Although the call-site passed uniqueness test, we still try to add some contexts for:
            #(1) performance opt (2) in case our string comparison based uniqueness test is not correct.
            cs = add_context_no_guarantee(src_map[c_file],rang,patch,fi)
            if not inlined:
                #Make a candidate based on the changed callee arguments.
                c = {'file':c_file,'func':c_func}
                c['line'] = [(rang[0],line_func[j][0])]
                arg_reg = []
                for a in changed_args:
                    arg_reg.append('x%d' % a)
                if not arg_reg:
                    #This should be impossible...
                    print '!!! No callee arguments have been changed @ file: %s func: %s line: %d' % (c_file,c_func,l_no+LINE_BASE)
                else:
                    if len(arg_reg) == 1:
                        arg_reg.append(arg_reg[0])
                    arg_opt = 'farg-%d-%d' % adj_lno_tuple(c['line'][0])
                    c['opts'] = {arg_opt:','.join(arg_reg)}
                    c['type'] = 'func_arg'
                    res_cand.append(c)
                    #Also consider the signature with contexts.
                    for c in cs:
                        c['file'] = c_file
                        c['func'] = c_func
                        c['type'] = 'func_arg+cont'
                        c.setdefault('opts',{})[arg_opt] = ','.join(arg_reg)
                        res_cand.append(c)
            else:
                #TODO: Can we really use this kind of signature? Since the function will be inlined I don't know whether
                #the parameter differences can still be reflected in the signature graph.
                c = {'file':c_file,'func':c_func}
                c['line'] = [(rang[0],line_func[j][0])]
                c['type'] = 'func_arg_inline'
                res_cand.append(c)
                #Also consider the signature with contexts.
                for c in cs:
                    c['file'] = c_file
                    c['func'] = c_func
                    c['type'] = 'func_arg_inline+cont'
                    res_cand.append(c)
        else:
            if is_func_uniq:
            #The callee name plus arg list has already passed the uniqueness test but we have no changed_args, why?
            #Reason #1: the parameter change is not in-place (i.e. the callee location has been changed)
            #Reason #2: the patch simply deletes some tailing parameters.
            #Anyway, since the call-site is unique, we can still make a candidate by itself.
                c = {'file':c_file,'func':c_func}
                c['line'] = [(rang[0],line_func[j][0])]
                c['type'] = 'func_inline' if inlined else 'func'
                res_cand.append(c)
            #Add contexts to make the candidate unique.
            cs = add_context_no_guarantee(src_map[c_file],rang,patch,fi)
            for c in cs:
                c['file'] = c_file
                c['func'] = c_func
                if inlined:
                    c['type'] = 'func_inline+cont'
                else:
                    c['type'] = 'func+cont'
                res_cand.append(c)
        #Skip the candidate lines that belong to a same function call site. 
        new_len = len(res_cand)
        add_extra_options(res_cand[old_len:new_len],inf)
        i = j + 1
    #H2: Consider the condition evaluation statements, like 'if'.
    #TODO: Same as H1, we still assume every single line has one 'if' or 'while', etc.
    line_if = [(k,'if',tags[k]['if'][0]) for k in tags if 'if' in tags[k]]
    line_while = [(k,'while',tags[k]['while'][0]) for k in tags if 'while' in tags[k]]
    line_cond = line_if + line_while
    line_cond = sorted(line_cond,key=lambda x:x[0])
    i = 0
    while i < len(line_cond):
        l_no = line_cond[i][0]
        keyword = line_cond[i][1]
        inf = line_cond[i][2]
        rang = inf['range']
        cond = inf['cond']
        j = i
        while j+1 < len(line_cond) and line_cond[j+1][0] <= rang[1]:
            j += 1
        #Uniqueness test regarding this statement.
        #if test_uniqueness(src_map[c_file],keyword+'('+cond+')',patch,strip=True):
        if test_uniqueness_cond(keyword,cond,src_map[c_file],patch):
            #Even though we passed the uniqueness test here, we may still need contexts based on two reasons: 
            #(1)There may still exist some structurally similar cond statements, which cannot be detected
            #by current string comparison based uniqueness test.
            #(2)Proper context can help to reduce match time, a simple cond statement usually leads to many candidates when matching.
            #So, the idea here is, if we find there are "good" contexts (e.g. non-inline function call), we will include it.
            cs = add_context_no_guarantee(src_map[c_file],rang,patch,fi)
            for c in cs:
                if True:
                #if c['cont_type'] in ('func_aft','func_bfr'):
                    c['file'] = c_file
                    c['func'] = c_func
                    c['type'] = 'cond+cont'
                    res_cand.append(c)
            #We also generate the candidate based on this pure body cond statement.
            c = {'file':c_file,'func':c_func}
            c['line'] = [(rang[0],line_cond[j][0])]
            #This is about conditions, so we can ignore non-tail root instructions.
            c['opts'] = {'trim_non_tail_roots':'True'}
            c['type'] = 'cond'
            res_cand.append(c)
        else:
            cs = add_context_no_guarantee(src_map[c_file],rang,patch,fi)
            for c in cs:
                c['file'] = c_file
                c['func'] = c_func
                c['type'] = 'cond+cont'
                res_cand.append(c)
        i = j + 1
    #H3: Fallback logic for all other boring cand lines.
    cond_lno = map(lambda x:x[0],line_cond)
    func_lno = map(lambda x:x[0],line_func)
    line_unk = [(k,tags[k]) for k in tags if not k in cond_lno + func_lno]
    line_unk = sorted(line_unk,key=lambda x:x[0])
    #Only consider unk lines when we have no other choices.
    if not res_cand:
        i = 0
        while i < len(line_unk):
            l_no = line_unk[i][0]
            #Filter out null line
            if not src_map[c_file][l_no].strip():
                i += 1
                continue
            ltag = line_unk[i][1]
            #NOTE: Other types of interest have already been processed previously.
            #TODO: To deal with cases like 'a=b //XXX', 'int a=b', etc.
            if _in_tag(ltag,('ret','else','goto','decl','comm')):
                i += 1
                continue
            #Decide the continuous 'unk' statements range
            l_no_ed = l_no
            j = i + 1
            while j < len(line_unk) and line_unk[j][0] == l_no_ed + 1:
                j += 1
                l_no_ed += 1
            #Uniqueness test.
            if test_uniqueness(src_map[c_file],''.join(src_map[c_file][l_no:l_no_ed+1]),patch,strip=True):
                #Similar as H2.
                cs = add_context_no_guarantee(src_map[c_file],(l_no,l_no_ed),patch,fi)
                for c in cs:
                    if True:
                    #if c['cont_type'] in ('func_aft','func_bfr'):
                        c['file'] = c_file
                        c['func'] = c_func
                        c['type'] = 'unk+cont'
                        if 'bfr' in c['cont_type']:
                            #Since the tail is 'unk', we still need to take some cares.
                            c.setdefault('opts',{})['trim_tail_abs_jmp'] = 'False'
                        res_cand.append(c)
                #Also generate the pure-body based candidate.
                c = {'file':c_file,'func':c_func}
                c['line'] = [(l_no,l_no_ed)]
                c['type'] = 'unk'
                c['opts'] = {'trim_tail_abs_jmp':'False'}
                res_cand.append(c)
            else:
                cs = add_context_no_guarantee(src_map[c_file],(l_no,l_no_ed),patch,fi)
                for c in cs:
                    c['file'] = c_file
                    c['func'] = c_func
                    c['type'] = 'unk+cont'
                    if 'bfr' in c['cont_type']:
                        c.setdefault('opts',{})['trim_tail_abs_jmp'] = 'False'
                    res_cand.append(c)
            i = j
    #Before returning, we should de-duplicate the candidates list. 
    return deduplicate_cands(res_cand)

def _in_tag(tag,tl):
    return not set(tag).isdisjoint(set(tl))

#Given a tag set of a line, decide its main type.
def _get_main_type(tags):
    ty = 'unk'
    #For main type, we should have some priorities (i.e. what if one line has multiple tags?)
    if _in_tag(tags,('if','while')):
        ty = 'cond'
    elif 'func' in tags:
        ty = 'func'
    return ty

#We try to add some contexts by heuristic, but the uniqueness of the result cand lines is not guaranteed. 
#We assume that the main body is of one type.
def add_context_no_guarantee(src,lines,patch,f_inf):
    (func_st,func_ed) = patch['func_range']
    tags = _get_tags_for_lines(patch['func_range'],f_inf)
    body_tags = set()
    for i in range(lines[0],lines[1]+1):
        body_tags = body_tags.union(set(tags[i]))
    body_type = _get_main_type(body_tags)
    first = lines[0]
    last = lines[-1]
    c_cands_aft = []
    MAX_UNK_CNT = 2
    #First search downward to find statements of interest (func call and cond evaluation)
    #When searching downward, we should consider not only continuous lines but also non-continuous ones (e.g. x and y in if(x){.....}y). 
    st_l = set([last+1])
    for k in ('if','while'):
        if k in tags[last]:
            #Get the ending line of the statement block. 
            st_l.add(tags[last][k][0]['ed_blk'])
    for st in st_l:
        i = st
        unk_cnt = 0
        while i <= func_ed:
            ltag = tags[i]
            if 'if' in ltag:
                if unk_cnt < MAX_UNK_CNT:
                    c_cands_aft += [ltag['if'][0]['range']]
                    break
            elif 'while' in ltag:
                if unk_cnt < MAX_UNK_CNT:
                    c_cands_aft += [ltag['while'][0]['range']]
                    break
            elif 'func' in ltag:
                if unk_cnt < MAX_UNK_CNT:
                    c_cands_aft += [ltag['func'][0]['range']]
                    break
            #We should stop searching when encountering certain types.
            elif _in_tag(ltag,('for','ret','else','goto','decl')):
                if i > st:
                    c_cands_aft += [(st,i-1)]
                break
            elif 'comm' in ltag or len(src[i].strip()) <= 1:
                #Regard comment or empty lines as non-existent.
                pass
            else:
                #Strictly, the 'unk' means the statements which cannot affect the control flow.
                unk_cnt += 1
                if unk_cnt >= MAX_UNK_CNT:
                    c_cands_aft += [(i-unk_cnt+1,i)]
                    break
            i += 1
    #Search upward for contexts.
    #Similar as before, we also need to consider non-continuous predecessor of current statement.
    c_cands_bfr = []
    blk_map = {}
    for i in tags:
        ltag = tags[i]
        for k in ltag:
            for inf in ltag[k]:
                if 'ed_blk' in inf:
                    l = inf['range'] if 'range' in inf else (i,i)
                    blk_map.setdefault(inf['ed_blk'],set()).add(l)
    st_l = set([first-1])
    if first in blk_map:
        st_l = st_l.union(set(map(lambda x:x[1],blk_map[first])))
    for st in st_l:
        i = st
        unk_cnt = 0
        while i >= func_st:
            ltag = tags[i]
            #if i in blk_map:
            #    for l in blk_map[i]:
            #        c_cands_bfr += [l]
            if 'if' in ltag:
                if unk_cnt < MAX_UNK_CNT:
                    c_cands_bfr += [ltag['if'][0]['range']]
                    break
            elif 'while' in ltag:
                if unk_cnt < MAX_UNK_CNT:
                    c_cands_bfr += [ltag['while'][0]['range']]
                    break
            elif 'func' in ltag:
                if unk_cnt < MAX_UNK_CNT:
                    c_cands_bfr += [ltag['func'][0]['range']]
                    break
            elif _in_tag(ltag,('for','ret','else','goto','decl')):
                if i < st:
                    c_cands_bfr += [(i+1,st)]
                break
            elif 'comm' in ltag or len(src[i].strip()) <= 1:
                #Regard comment lines as non-existent.
                pass
            else:
                unk_cnt += 1
                if unk_cnt >= MAX_UNK_CNT:
                    c_cands_bfr += [(i,i+unk_cnt-1)]
                    break
            i -= 1
    #Pick the 'best' context lines, we may have multiple choices here: the context lines are before or after original candidate,
    #the context lines are func or cond statements, etc.
    fallback_c = []
    res_c = []
    c_cands_aft_func = filter(lambda x:_get_main_type(tags[x[0]])=='func',c_cands_aft)
    c_cands_bfr_func = filter(lambda x:_get_main_type(tags[x[0]])=='func',c_cands_bfr)
    def _pick_cont_func(cands,reverse=False):
        inlined = True
        cands = sorted(cands,key=lambda x:x[0],reverse=reverse)
        for c_func in cands:
            fi = tags[c_func[0]]['func'][0]
            if func_exists(fi['name']):
                yield (c_func,False)
            else:
                yield (c_func,True)
    if c_cands_aft_func:
        for (c_func,inlined) in _pick_cont_func(c_cands_aft_func):
            c = {}
            c['line'] = combine_line_range(lines,c_func)
            if inlined:
                if body_type == 'cond':
                    c['opts'] = {'trim_non_tail_roots':'True'}
                else:
                    c['opts'] = {'trim_tail_call_args':'True'}
                c['cont_type'] = 'func_aft_inline'
                fallback_c += [c]
            else:
                if body_type == 'cond':
                    c['opts'] = {'trim_non_tail_roots':'True'}
                else:
                    c['opts'] = {'trim_tail_call_args':'True'}
                c['cont_type'] = 'func_aft'
                res_c += [c]
    if c_cands_bfr_func:
        for (c_func,inlined) in _pick_cont_func(c_cands_bfr_func,reverse=True):
            c = {}
            c['line'] = combine_line_range(lines,c_func)
            if inlined:
                if body_type == 'cond':
                    c['opts'] = {'trim_non_tail_roots':'True'}
                else:
                    c['opts'] = {'trim_non_tail_roots-%d-%d' % adj_lno_tuple(c_func):'True'}
                c['cont_type'] = 'func_bfr_inline'
                fallback_c += [c]
            else:
                if body_type == 'cond':
                    c['opts'] = {'trim_non_tail_roots':'True'}
                else:
                    c['opts'] = {'trim_non_tail_roots-%d-%d' % adj_lno_tuple(c_func):'True'}
                c['cont_type'] = 'func_bfr'
                res_c += [c]
    #Then consider the cond statements as contexts.
    c_cands_aft_cond = filter(lambda x:_get_main_type(tags[x[0]])=='cond',c_cands_aft)
    c_cands_bfr_cond = filter(lambda x:_get_main_type(tags[x[0]])=='cond',c_cands_bfr)
    def _pick_cont_cond(cands,reverse=False):
        for c in sorted(cands,key=lambda x:x[0],reverse=reverse):
            yield c
    if c_cands_bfr_cond:
        for c_cond in _pick_cont_cond(c_cands_bfr_cond,reverse=True):
            c = {}
            c['line'] = combine_line_range(lines,c_cond)
            c['cont_type'] = 'cond_bfr'
            if body_type == 'cond':
                c['opts'] = {'trim_non_tail_roots':'True'}
            else:
                c['opts'] = {'trim_non_tail_roots-%d-%d' % adj_lno_tuple(c_cond):'True'}
            res_c += [c]
    if c_cands_aft_cond:
        for c_cond in _pick_cont_cond(c_cands_aft_cond):
            c = {}
            c['line'] = combine_line_range(lines,c_cond)
            c['cont_type'] = 'cond_aft'
            if body_type == 'cond':
                c['opts'] = {'trim_non_tail_roots':'True'}
            else:
                c['opts'] = {'trim_non_tail_roots-%d-%d' % adj_lno_tuple(c_cond):'True'}
            res_c += [c]
    #Finally consider other normal statements as contexts.
    #We've reached here, this means we cannot find anything special as contexts, so simply use the surrounding lines.
    if res_c:
        return res_c
    if fallback_c:
        return fallback_c
    if c_cands_aft:
        c = {}
        c['line'] = combine_line_range(lines,c_cands_aft[0])
        c['cont_type'] = 'unk_aft'
        c['opts'] = {'trim_tail_abs_jmp':'False'}
        res_c += [c]
    if c_cands_bfr:
        c = {}
        c['line'] = combine_line_range(lines,c_cands_bfr[0])
        c['cont_type'] = 'unk_bfr'
        res_c += [c]
    return res_c

def combine_line_range(l1,l2):
    if l1[1] < l2[0] - 1:
        return [l1,l2]
    elif l1[0] > l2[1] + 1:
        return [l2,l1]
    else:
        #They are overlapped.
        return [(min(l1[0],l2[0]),max(l1[1],l2[1]))]

#Deduplicate the cands by line range.
def deduplicate_cands(cands):
    #First sort the line range of each candidate.
    for c in cands:
        c['line'] = sorted(c['line'],key=lambda x:x[0])
    range_map = {}
    for c in cands:
        range_map.setdefault(tuple(c['line']),[]).append(c)
    res_cands = []
    #For the candidates with the same line range, pick the highest scored one. (Although they are actually the same...)
    for r in range_map:
        res_cands += [sorted(range_map[r],key=_calc_cand_score_type,reverse=True)[0]]
    return res_cands

#NOTE: 'line candidates' refer to actual, existing source code lines present in kernel source tree specified in sys.argv[2]. 
#So these candidate lines can be pre-patch or aft-patch version.
def refine_line_candidates(cands,p_inf):
    res_cand = []
    for c in cands:
        patch = p_inf[(c['file'],c['func'],c['func_range'][0])]
        trm_cands = trim_line_candidates(c,patch)
        for tc in trm_cands:
            tc['file'] = c['file']
            tc['func'] = c['func']
            tc['func_range'] = c['func_range']
        res_cand += trm_cands
    return res_cand

#Calculate a 'score' for a candidate, the higher, the better.
#fmt_str, fmt_str+cont*
#func_name, func_name_inline 
#func_arg, func_arg_inline, func_arg+cont*, func_arg_inline+cont*
#func+cont*, func_inline+cont*
#cond, cond+cont*
#unk, unk+cont*
type_score_map = {
    'func_name':1000,
    'func+cont-func_aft':950,
    'func+cont-func_bfr':950,
    'cond+cont-func_aft':900,
    'cond+cont-func_bfr':900,
    'func+cont-cond_aft':900,
    'func+cont-cond_bfr':900,
    'cond':850,
    'cond+cont-cond_bfr':800,
    'cond+cont-cond_aft':800,
    'fmt_str':600,
    'default':500,
    'func_name_inline':250,
    'unk':200,
    'func_inline':150,
    'func_arg_inline':150,
}
def _calc_cand_score_type(cand):
    global type_score_map
    b_ty = cand['type']
    ty = b_ty
    c_ty = ''
    if 'cont_type' in cand:
        c_ty = cand['cont_type']
        ty += '-' + c_ty
    #Candidate types without contexts have been covered in the score map.
    #We also explicitly included certain preferred and un-preferred types with contexts in the map.
    #Cover other types in below code.
    if ty in type_score_map:
        return type_score_map[ty]
    bad_context = ('func_aft_inline','func_bfr_inline')
    trv_context = ('unk_bfr','unk_aft')
    if b_ty in ('func_name_inline+cont','func_inline+cont','func_arg_inline+cont'):
        #Contexts make no difference here.
        return type_score_map[b_ty[:-5]]
    if b_ty in ('func+cont','func_arg+cont'):
        score = type_score_map.get(b_ty[:-5],type_score_map['default'])
        if c_ty in bad_context:
            score -= 250
        elif c_ty in trv_context:
            #We decrease some scores here because the add_context has no guarantee about uniqueness,
            #and unk type possibly cannot increase the uniqueness.
            score -= 50
        return score
    if b_ty == 'cond+cont':
        score = type_score_map.get(b_ty[:-5],type_score_map['default'])
        if c_ty in bad_context:
            score -= 250
        elif c_ty in trv_context:
            score -= 200
        return score
    if b_ty == 'unk+cont':
        score = type_score_map.get(b_ty[:-5],type_score_map['default'])
        if not c_ty in bad_context and not c_ty in trv_context:
            score += 50
        return score
    if b_ty in ('fmt_str+cont','fmt_str_inline+cont'):
        score = type_score_map.get(b_ty[:-5],type_score_map['default'])
        if c_ty in bad_context:
            score -= 350
        return score
    return type_score_map['default']

def _calc_cand_score_func_len(cand):
    return cand['func_range'][1] - cand['func_range'][0]

def _calc_cand_score_pos(cand):
    return cand['line'][0][0] - cand['func_range'][0]

#Decide which candidate is better, which is worse...
def rank_candidate(cands,p_inf):
    if not cands:
        return cands
    #'sorted' function in python will guarantee the stability, utilizing this, we do a
    #multi-phases sorting, considering both cand line position, func length and cand type.
    #The least important factor will appear in the first sorting phase..
    #(1) cand line position inside a function --> extraction speed
    #(2) func length --> matching speed
    #(3) cand type --> matching accuracy, simplicity, stability...
    s = sorted(cands,key=_calc_cand_score_pos)
    s = sorted(s,key=_calc_cand_score_func_len)
    s = sorted(s,key=_calc_cand_score_type,reverse=True)
    return s

func_inf = {}
def do_pick_sig(patch_inf):
    #It's time to decide the source code lines that we can mark to extract signatures.
    cands = generate_line_candidates(patch_inf)
    if not cands:
        print '****** Pure deletion patch or pre-patched.'
        return []
    #We must ensure that the cand functions do exist in src kernel binary, since the extraction is based on the binary.
    if sym_tabs:
        #cands = filter(lambda x:sym_tabs[0].lookup_func_name(x['func']) is not None,cands)
        cands = filter(lambda x:func_exists(x['func']),cands)
    if not cands:
        print '****** No function name in the symbol table.'
        return []
    #Do a simple syntax analysis for the functions involved in the patch. 
    global func_inf
    func_inf = parse_funcs_in_patch(patch_inf)
    #Do a filtering since some lines (e.g. variable declaration) cannot be used in signature extraction.
    cands = filter(lambda x:not _is_decl_cand(x),cands)
    if dbg_out:
        print '****Candidate lines after filtering out variable declarations****'
        for c in cands:
            print '%s %s %s' % (c['file'],c['func'],c['line'])
    #For each candidate change site, we need to do some adjustments, if it's not unique, contexts need to be added,
    #if it contains multiple lines, it may need to be trimmed.
    res_cand = refine_line_candidates(cands,patch_inf)
    #Pick up the most promising candidates.
    res_cand = rank_candidate(res_cand,patch_inf)
    for c in res_cand:
        c['arg_cnt'] = patch_inf[(c['file'],c['func'],c['func_range'][0])]['arg_cnt']
    if not res_cand:
        return []
    else:
        if dbg_out:
            print '==============Ranked Candidates=============='
            for r in res_cand:
                print '=============='
                print r
        return res_cand[:3] if len(res_cand) >= 3 else res_cand
        #return res_cand

sym_tabs = []
def pick_sig():
    #Load symbol tables if there are any.
    global sym_tabs
    for f in sys.argv[4:]:
        sym_tabs.append(Sym_Table(f,dbg_out=dbg_out))
    #Deal with patches in patch_list one by one.
    exts = []
    fails = []
    t0 = time.time()
    with open(sys.argv[1],'r') as patch_list:
        for patch in patch_list:
            #Parse the patch to figure out which lines in which functions of which files are added/deleted.
            patch_name = patch.strip()
            if not patch_name:
                continue
            #Simple comment mechanism.
            if patch_name[0] == '#':
                continue
            print '------------' + patch_name + '----------------'
            patch_inf = parse_patch(patch_name,sys.argv[2])
            if not patch_inf:
                fails += [patch_name]
                print '****** Fail to match the patch.'
                continue
            if dbg_out:
                print_patch_inf(patch_inf)
            cs = do_pick_sig(patch_inf)
            if cs:
                for c in cs:
                    #Use the patch file name as the signature name.
                    c['name'] = patch_name[patch_name.rfind('/')+1:]
                    exts += [c]
            else:
                fails += [patch_name]
                print '****** No candidate generated for %s' % patch_name
    #Make the 'ext_list' file
    with open(sys.argv[3],'w') as f:
        for c in exts:
            s = c['name'] + ' ' + c['func'] + ' '
            #s += '---%s|%d--- ' % (c['type'],c['func_range'][1]-c['func_range'][0])
            #Append the line range
            for l in c['line']:
                (l1,l2) = adj_lno_tuple(l)
                if l1 == l2:
                    s += '%d' % l1
                else:
                    s += '%d-%d' % (l1,l2)
                s += ','
            #Delete the tailing ','
            s = s[:-1]
            #Append the 'match_reg_set'
            if c['arg_cnt'] == 0:
                pass
            elif c['arg_cnt'] == 1:
                s += ' match_reg_set:x0,x0'
            elif c['arg_cnt'] > 1:
                s += ' match_reg_set:' + ','.join(['x%d' % x for x in range(c['arg_cnt'])])
            #Append other options
            opts = c.get('opts',{})
            for o in opts:
                s += ' ' + o + ':' + opts[o]
            #Write to the output file.
            f.write(s + '\n')
    print 'Time: %.2f' % (time.time() - t0)
    if fails:
        with open(sys.argv[3]+'_fail','w') as f:
            for c in fails:
                f.write(c+'\n')

def try_lex():
    toks = lex('/*if(asd)    \n     a=c;    \n   //"asd"*/\n       if(a)b=c;         \n//dfgr\nreturn c;',process=False)
    for t in toks:
        print t

if __name__ == '__main__':
    pick_sig()
    #try_lex() 
