#!/usr/bin/python
#This program aims to match a signature in a target binary.

import angr,simuvex,claripy
import sys,os
import logging,traceback
import copy,re
import time
import traceback

from networkx.algorithms import isomorphism
from utils_sig import *
from claripy import operations
from fuzzywuzzy import fuzz
try:
    import cPickle as pickle
except ImportError:
    import pickle
from sym_tracer import Sym_Tracer
from sym_table import Sym_Table
from sym_executor import Sym_Executor

default_options = {}

#We will use the DiGraph matcher provided in networkx package to do the subgraph match.
#This matcher class can also do some semantic comparison for nodes and edges besides syntactic checks.
#This function init some superficial attributes for each node in the target function cfg that will be used
#as the semantics of nodes in later matching process.
def prep_node_attributes_for_match(proj,cfg,sym_tab=None):
    for node in cfg.nodes():
        block = proj.factory.block(node.addr,size=node.size,opt_level=0)
        irsb = block.vex
        cfg.node[node]['block'] = block
        cfg.node[node]['jumpkind'] = irsb.jumpkind
        if irsb.jumpkind == 'Ijk_Call':
            n = get_exit_func_name(proj,irsb,sym_tab)
            if n is not None:
                cfg.node[node]['exit_func_name'] = n
        cfg.node[node]['in_d'] = cfg.in_degree(node)
        cfg.node[node]['out_d'] = cfg.out_degree(node)

#When doing graph match, we do semantic match of nodes in this function.
#The parameters are attribute dictionaries of two nodes in comparison.
def node_matcher(d1,d2):
    #Don't perform further comparison if one node is purely for padding.
    if 'padding' in d1 or 'padding' in d2:
        return True
    if d1['jumpkind'] <> d2['jumpkind']:
        return False
    if d1['jumpkind'] == 'Ijk_Call':
        #Match the function name if any.
        if 'exit_func_name' in d1 and 'exit_func_name' in d2:
            if not _cmp_func_name(d1['exit_func_name'],d2['exit_func_name']):
                return False
    #if d1['out_d'] <> d2['out_d'] or d1['in_d'] <> d2['in_d']:
    #    return False
    if d1['out_d'] <> d2['out_d']:
        return False
    return True

#Given the 'formulas' dictionary in a signature, count the number of each 'type'.
#Return a type-->num dictionary.
def _cnt_formula_type(formulas):
    m = {}
    for addr in formulas:
        ty = formulas[addr]['type']
        if m.has_key(ty):
            m[ty] = m[ty] + 1
        else:
            m[ty] = 1
    m['load'] = m.get('load',0) + m.get('other',0)
    if 'other' in m:
        m.pop('other')
    if m['load'] == 0:
        m.pop('load')
    return m

#Both t1 and t2 are returned by _cnt_formula_type(), this function decide whether t1 contains t2.
#That's to say, for all types in t2, t1 also has them and the amount is no less than that in t2.
def _type_contains(t1,t2):
    for k in t2:
        if not t1.has_key(k):
            return False
        elif t1[k] < t2[k]:
            return False
    return True

#This function intends to do some preliminary quick filtering for candidate code areas in target function.
#For now we check whether the semantics of root instructions are matched. 
#Params: mapping: nodes of sl --> nodes of sr, sl and sr are both sigs.
#NOTE: sl is the candidate, sr is the original signature.
def pre_filter(sl,sr,mapping):
    for nl in mapping:
        nr = mapping[nl]
        #Ignore the padding nodes.
        if 'padding' in sr.node[nr]:
            set_padding_node(sl,nl)
            continue
        #The check here is that we should guarantee all the root instruction semantics in original sig should also
        #appear in the candidate.
        typer = _cnt_formula_type(sr.node[nr]['formulas'])
        typel = _cnt_formula_type(sl.node[nl]['formulas'])
        if not _type_contains(typel,typer):
            return False
    return True

#Do a simple subgraph match for the original signature and target function cfg, mainly on the syntactic level. 
def graph_match(sig,proj,cfg,sym_tab=None):
    #The sig DiGraph already has all the necessary node attributes for matching, but target cfg doesn't.
    #So the first step is to generate these necessary node attributes for target cfg.
    prep_node_attributes_for_match(proj,cfg,sym_tab=sym_tab)
    #Do the subgraph match, node_matcher() is a simple node-level semantic matcher.
    digm = isomorphism.DiGraphMatcher(cfg,sig,node_match=node_matcher)
    candidates = []
    for it in digm.subgraph_isomorphisms_iter():
        #Each iter here is a possible match (i.e. a candidate)
        #At first wrap it into a sig structure.
        addrs = [x.addr for x in it.keys()]
        print '[TOPO MATCH] ' + hex_array_sorted(addrs)
        #We guarantee in extraction phase that every signature is connected, so here the candidate signature must also be connected, thus we
        #can directly use init_signature(...)[0].
        c_sig = init_signature(proj,cfg,addrs,sym_tab=sym_tab)[0]
        #The 'it' is the mapping from the whole func_cfg to original sig, now we just want the mapping from
        #candidate sig to original sig.
        mapping = {}
        for k in it:
            #L: Candidates R: Original Signature
            mapping[get_node_by_addr(c_sig,k.addr)] = it[k]
        #show_signature(c_sig)
        #Do some preliminary filtering before the real symbolic execution.
        if pre_filter(c_sig,sig,mapping):
            candidates.append((c_sig,mapping))
    print '%d candidates after graph_match()' % len(candidates)
    return candidates

#Compare two function name strings, we should give this some flexibility (not strict string comparison).
def _cmp_func_name(n1,n2,ratio=85):
    policy = default_options.get('match_func_name_policy','default')
    if policy == 'strict':
        return n1 == n2
    elif policy == 'free':
        return True
    else:
        ##We use fuzzy string match implemented in the package 'fuzzywuzzy'
        if n1 in n2 or n2 in n1:
            return True
        return n1 == n2
        #return fuzz.ratio(n1,n2) >= ratio

#Now we have two symbolic leaf nodes and 'hz_extra' information associated with them.
#We need to compare their 'hz_extra' trace information to decide whether they can be regarded as the same.
def cmp_hz_extra(f1,f2,options):
    h1 = f1.hz_extra
    h2 = f2.hz_extra
    if h1['type'] <> h2['type']:
        return False
    ty = h1['type']
    if ty == Sym_Tracer.REG_TYPE:
        #Assume the translated reg name is 'reg_N', N is uniq number assigned by execution engine.
        r1 = h1['name'].split('_')[0]
        r2 = h2['name'].split('_')[0]
        if r1 == r2:
            return True
        #For some special regs (like the parameter registers) we may want exact matching.
        #User can specify such a reg list to be exactly matched.
        m_set = options['match_reg_set'] if options.has_key('match_reg_set') else set()
        if r1 in m_set or r2 in m_set:
            return False
        return True
    elif ty == Sym_Tracer.MEM_TYPE:
        #We need to look at the addr formula behind this mem symbolic value.
        if not h1.has_key('mem_formula') or not h2.has_key('mem_formula'):
            if 'mem_formula' in h1 or 'mem_formula' in h2:
                #One has and one not.
                return False
            else:
                return True
        return cmp_formula(h1['mem_formula'],h2['mem_formula'],options,is_mem_addr=True)
    elif ty == Sym_Tracer.RET_TYPE:
        #This is a function return value.
        policy = options['match_ret_policy'] if options.has_key('match_ret_policy') else 'free'
        if policy == 'free':
            return True
        elif policy == 'by_name':
            n1 = h1['func_name'] if h1.has_key('func_name') else None
            n2 = h2['func_name'] if h2.has_key('func_name') else None
            if n1 is None or n2 is None:
                #TODO: is it proper to use 'free' policy as fall back here?
                return True
            return _cmp_func_name(n1,n2)
        else:
            print 'Unrecognized match_ret_policy: ' + policy
            return True
    elif ty == Sym_Tracer.UNK_TYPE:
        #TODO: is it proper to do it conservatively here?
        return True
    return True

#Compare two ASTs to see whether they are the same.
#NOTE: By 'same' we don't mean the very 'accurate same', but to some degrees the 'structurally same'. 
#NOTE: Implicitly, 'f1' is original signature, 'f2' is candidate.
def cmp_formula(f1,f2,options,**kwargs):
    if not isinstance(f1,claripy.ast.Base) or not isinstance(f2,claripy.ast.Base):
        #An ast may have various kinds of args, some kinds may not be the AST type, such as the offset arg for 'Lshift' op AST. 
        #print '[CMP] Not of type AST, f1: %s ||| f2: %s' % (str(f1),str(f2))
        if type(f1) != type(f2):
            return False
        # They are not ASTs
        return False if f1 <> f2 else True
    #We have two layers of AST to compare: the original AST and our 'hz_extra' comments on its leaf symbolic nodes.
    #So basically we will do a standard recursive AST match here, but whenever we meet a symbolic leaf node, we also
    #try to match its 'hz_extra' information, which may include another formula AST.
    #print '**********************************'
    #print '%s,%s' % (f1,f1.op)
    #print '%s,%s' % (f2,f2.op)
    #print '**********************************'
    if f1.op == f2.op:
        op = f1.op
        if op in operations.leaf_operations_symbolic:
            #It's time to check 'hz_extra'
            if f1.hz_extra.has_key('type') and f2.hz_extra.has_key('type'):
                return cmp_hz_extra(f1,f2,options=options)
            else:
                #One or all formulas haven't even been processed by Sym_Tracer.
                print '[CMP] No trace information, f1: %s %s ||| f2: %s %s' % (str(f1),str(f1.hz_extra.has_key('type')),str(f2),str(f2.hz_extra.has_key('type')))
                #TODO: we may need to develop a more complicated logic here.
                return (not f1.hz_extra.has_key('type') and not f2.hz_extra.has_key('type'))
        elif op in operations.leaf_operations_concrete:
            _cmp_conc = lambda x,y:str(x).split(' ')[1] == str(y).split(' ')[1]
            _to_int = lambda x:int(str(x).split(' ')[1][:-1],16)
            #These are concrete values, the comparison is based on user-specified policy.
            policy = options.get('match_conc_policy','free')
            if policy == 'free':
                return True
            elif policy == 'strict':
                if op <> 'BoolV':
                    threshold = 0x2000
                    if _to_int(f1) > threshold and _to_int(f2) > threshold:
                        return True
                return _cmp_conc(f1,f2)
            elif policy == 'data':
                is_mem_addr = kwargs.get('is_mem_addr',True)
                return True if is_mem_addr else _cmp_conc(f1,f2)
            else:
                print 'Unrecognized match_conc_policy: ' + policy
                return True
        elif op == 'If':
            policy = options.get('match_ite_2_policy','contain')
            if policy == 'contain':
                #Currently we use such a strategy to compare 'If' statements:
                #(1)We ignore all the conditions and only care about the terms.
                #(2)If all original signature's terms are contained in candidate, we say it's matched. 
                t1 = _extract_if_terms(f1)
                t2 = _extract_if_terms(f2)
                return _match_ast_sets(t1,t2,options=options,**kwargs)
            elif policy == 'strict':
                return general_ast_match(f1,f2,options,**kwargs)
            else:
                print 'Unrecognized match_ite_2_policy: ' + policy
                return False
        elif op in operations.commutative_operations.union({'__eq__','__ne__'}):
            #For these ASTs, their args are commutative, so we should do order-insensitive comparison here.
            s1 = list(f1.args)
            s2 = list(f2.args)
            return _match_ast_sets(s1,s2,single_mapping=True,options=options,**kwargs)
        elif op in ('Extract',):
            #Ignore non-ast args
            return cmp_formula(f1.args[2],f2.args[2],options,**kwargs)
        else:
            #The ultimate fall back comparison method is strict structure match.
            return general_ast_match(f1,f2,options,**kwargs)
    else:
        #Now the OPs are different... But we may still do comparison in some special situations.
        if f1.op == 'If' or f2.op == 'If':
            policy = options.get('match_ite_1_policy','no')
            if policy == 'no':
                return False
            elif policy == 'contain':
                fi = f1 if f1.op == 'If' else f2
                fj = f2 if f1.op == 'If' else f1
                ti = _extract_if_terms(fi)
                return _match_ast_sets(set([fj]),ti,options,**kwargs)
            else:
                print 'Unrecognized match_ite_1_policy: ' + policy
                return False
        elif (f1.op in operations.leaf_operations_symbolic and f2.op in operations.leaf_operations_concrete) or \
             (f2.op in operations.leaf_operations_symbolic and f1.op in operations.leaf_operations_concrete):
            #We want to capture a special case here:
            #1 mov X0, 0xffff0000
            #2 ldr X1, [X0]
            #3 ldr X2, [X1]
            #We can see that X0 in 2 is concrete, but the [0xffff0000] may be different in two images, say in image 1 it's 0x40 and in image 2 it's 0xffffc000.
            #Then in 3, it's possible that '0x40' holds nothing, so it has to create 'mem_40', while '0xffffc000' holds a constant.
            #In this situation, the semantics are totally the same, but formulas for X2 in 3 are different (one symbolic value and one constant).
            policy = options.get('match_sym_conc_policy','hz')
            if policy == 'hz':
                fs = f1 if f1.op in operations.leaf_operations_symbolic else f2
                fc = f2 if f1.op in operations.leaf_operations_symbolic else f1
                ty = fs.hz_extra.get('type',None)
                if ty <> Sym_Tracer.MEM_TYPE:
                    return False
                else:
                    return True if fs.hz_extra.get('mem_formula',None) is None else False
            elif policy == 'strict':
                return False
            elif policy == 'free':
                return True
            else:
                print 'Unrecognized match_sym_conc_policy: ' + policy
                return False
        elif f1.op == 'Concat' or f2.op == 'Concat':
            fc = f1 if f1.op == 'Concat' else f2
            ft = f2 if f1.op == 'Concat' else f1
            if not fc.symbolic and not ft.symbolic:
                return True
            if _is_sp_symbolic_aarch64(fc) and not ft.symbolic:
                return True
            return False
        #TODO: Deal with [X0] VS [X0+off] comparison here, that's to say, one offset is 0, which can cause 'op' to be different, but we still want to capture this.
        elif False:
            pass
        else:
            #No more special cases, return False in the end.
            return False
    return True

def _is_sp_symbolic_aarch64(ast):
    if ast is None:
        return True
    for leaf in ast.recursive_leaf_asts:
        if leaf.symbolic and not leaf.args[0].startswith('reg_108'):
            return False
    return True

#A general matcher for 2 ASTs, it's similar to structurally_match() defined in 'ast/base.py' but we use cmp_formula() as the leaf comparator.
def general_ast_match(f1,f2,options,**kwargs):
    if f1.op != f2.op:
        return False

    if len(f1.args) != len(f2.args):
        return False

    for arg_a, arg_b in zip(f1.args, f2.args):
        if not cmp_formula(arg_a,arg_b,options,**kwargs):
            return False

    return True

#For a 'if' statement like if A then B else if C then D else E
#We will extract B,D and E
def _extract_if_terms(f):
    if f.op == 'If':
        return _extract_if_terms(f.args[1]).union(_extract_if_terms(f.args[2]))
    else:
        return set([f])

#Match two sets of formulas, decide whether all formulas in original signature are contained in candidate signature.
def _match_ast_sets(sigs,cands,options,single_mapping=False,**kwargs):
    cands = list(cands)
    for sf in sigs:
        matched = False
        for i in range(len(cands)):
            cf = cands[i]
            if cmp_formula(sf,cf,options,**kwargs):
                matched = True
                if single_mapping:
                    cands.pop(i)
                break
        if not matched:
            return False
    return True

#Match two sets of formula tuples.
def _match_ast_tuple_sets(sigs,cands,options,single_mapping=False,data_ind=set(),**kwargs):
    for sft in sigs:
        for ci in range(len(cands)):
            cft = cands[ci]
            if len(sft) <> len(cft):
                continue
            for i in range(len(sft)):
                is_mem_addr = False if i in data_ind else True
                if not cmp_formula(sft[i],cft[i],options,is_mem_addr=is_mem_addr,**kwargs):
                    break
            else:
                #We now have a pair of matched sft and cft.
                if single_mapping:
                    cands.pop(ci)
                break
        else:
            #No match for current sft..
            return False
    return True

#Match two set of 'load' type formulas, decide whether all formulas in original signature are contained in candidate signature.
def _formula_match_load(sig_forms,cand_forms):
    single_mapping = default_options.get('match_load_single_mapping',False)
    return _match_ast_sets(sig_forms,cand_forms,default_options,single_mapping=single_mapping)

#Match two set of 'store' type formulas, decide whether all formulas in original signature are contained in candidate signature.
def _formula_match_store(sig_forms,cand_forms):
    sig_ad = map(lambda (a,d,l):(a,d),sig_forms)
    cand_ad = map(lambda (a,d,l):(a,d),cand_forms)
    single_mapping = default_options.get('match_store_single_mapping',False)
    return _match_ast_tuple_sets(sig_ad,cand_ad,default_options,data_ind=set([1]),single_mapping=single_mapping)

#Match two set of 'exit' type formulas, decide whether all formulas in original signature are contained in candidate signature.
def _formula_match_exit(sig_forms,cand_forms):
    sig_g = map(lambda (a,g,k):g,sig_forms)
    cand_g = map(lambda (a,g,k):g,cand_forms)
    single_mapping = default_options.get('match_exit_single_mapping',False)
    return _match_ast_sets(sig_g,cand_g,default_options,single_mapping=single_mapping)

#Given a formulas dict, put these formulas into different categorizations, return a tuple.
def classify_formulas(formulas):
    loads = set()
    stores = set()
    exits = set()
    for ins_addr in formulas:
        f = formulas[ins_addr]
        if f['type'] == 'load' or f['type'] == 'other':
            #We have some formulas here, each associated with a register.
            non_reg_keys = ['type']
            for k in f:
                if k not in non_reg_keys:
                    loads = loads.union(set(f[k]))
        elif f['type'] == 'store':
            #The formulas here is an addr-data-length tuple list.
            stores = stores.union(set(f['a-d-l']))
        elif f['type'] == 'exit':
            #The formulas here is an addr-guard-kind tuple list.
            exits = exits.union(set(f['a-g-k']))
        else:
            print '[classify_formulas()] Unrecognized type: ' + f['type']
    return (loads,stores,exits)

#Match two format strings, the core idea here is that we only look at the 'formatters' and ignore other trivial words. 
def _match_fmt_str(a,b):
    #What if we are lucky...
    if a == b:
        return True
    re_fmt = '%[\da-zA-Z]+'
    fa = re.findall(re_fmt,a)
    fb = re.findall(re_fmt,b)
    return fa == fb

#Compare the original signature and a candidate by their semantics (i.e. the formulas collected during symbolic execution)
#'mapping' is the node-node mapping between candidate and original signatures.
#Return True if matched.
def semantic_match(mapping,cand,sig,options):
    #The key in 'mapping' is the node in candidate signature, value is the original signature node.
    if options.get('match_fmt_str',False):
        for nc in mapping:
            ns = mapping[nc]
            fc = cand.node[nc].get('fmt_str',None)
            fs = sig.node[ns].get('fmt_str',None)
            if fc is None and fs is None:
                continue
            elif fc is not None and fs is not None:
                if not _match_fmt_str(fs,fc):
                    return False
            else:
                return False
    for nc in mapping:
        ns = mapping[nc]
        if 'padding' in cand.node[nc] and 'padding' in sig.node[ns]:
            continue
        elif 'padding' in cand.node[nc] or 'padding' in sig.node[ns]:
            return False
        sig_form = sig.node[ns]['formulas']
        cand_form = cand.node[nc]['formulas']
        (sig_loads,sig_stores,sig_exits) = classify_formulas(sig_form)
        (cand_loads,cand_stores,cand_exits) = classify_formulas(cand_form)
        if not _formula_match_load(sig_loads,cand_loads):
            return False
        if not _formula_match_store(sig_stores,cand_stores):
            return False
        if not _formula_match_exit(sig_exits,cand_exits):
            return False
    return True

#Param:
#sig --> the patch/bug signature
#proj --> Angr project of target binary
#cfg --> cfg of target function to be matched, a DiGraph
#cfg_bounds --> the start and end of the cfg area
#cfg_acc --> Angr's accurate cfg
def do_match_sig(sig,proj,cfg,cfg_bounds,cfg_acc,sym_tab,options):
    #First do a subgraph match that is mainly based on the graph syntactics.
    candidates = graph_match(sig,proj,cfg,sym_tab=sym_tab)
    if not candidates:
        print 'No candidates after initial graph match'
        return (False,0)
    candidate_sigs = [x for (x,y) in candidates]
    #Now basically we need to do the symbolic execution from function entry to each of the candidates and
    #collect semantic formulas along the process.
    exe = Sym_Executor(dbg_out=True,options=options)
    targets = get_cfg_bound(candidate_sigs)
    smg = exe.try_sym_exec(proj=proj,cfg=cfg_acc,cfg_bounds=cfg_bounds,targets=targets,start=cfg_bounds[0],new_tracer=True,new_recorder=True,sigs=candidate_sigs,sym_tab=sym_tab)
    matched = 0
    for (cand,mapping) in candidates:
        simplify_signature(cand)
        analyze_func_args_aarch64(sys.argv[1],BASE,cand,options)
        print '---------------Candidate-----------------'
        show_signature(cand)
        if semantic_match(mapping,cand,sig,options):
            print '^-^ ^-^ ^-^ ^-^ ^-^ ^-^ ^-^ ^-^ SIG MATCHED!!! ^-^ ^-^ ^-^ ^-^ ^-^ ^-^ ^-^ ^-^'
            matched = matched + 1
            #break
    if matched == 0:
        print 'No Matches...'
    return (exe.tracer.addr_collision,matched)

def test_func_existence(proj,func_cfg,sym_tab,target_func):
    cnt = 0
    for n in func_cfg.nodes():
        block = proj.factory.block(n.addr,size=n.size,opt_level=0)
        irsb = block.vex
        if irsb.jumpkind == 'Ijk_Call':
            name = get_exit_func_name(proj,irsb,sym_tab)
            if name and name == target_func:
                cnt += 1
    return cnt

ARCH = 'aarch64'
BASE = 0xffffffc000080000;

#sys.argv[1] --> path/to/kernel-image (target image)
#sys.argv[2] --> path/to/symbol-table (for target image)
#sys.argv[3] --> path/to/match-list (a file stores a list of pickled signature)
def match_sig():
    global default_options,BASE
    symbol_table = Sym_Table(sys.argv[2])
    BASE = symbol_table.probe_arm64_kernel_base()
    code_segments = symbol_table.get_code_segments(BASE)
    b = load_kernel_image(sys.argv[1],ARCH,BASE,segments=code_segments)
    res_vec = []
    res_dic = {}
    miss_sigs = []
    prev_cve = ''
    td = 0
    applicable = True
    with open(sys.argv[3],'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line[0] == '#':
                continue
            tks = line.split(' ')
            cve = tks[0][tks[0].rfind('/')+1:tks[0].rfind('-sig')]
            applicable = True
            if len(tks) > 1:
                if cve in res_dic:
                    continue
                elif prev_cve and cve != prev_cve:
                    if not prev_cve in res_dic:
                        res_dic[prev_cve] = ('N',td)
                    td = 0
            try:
                with open(tks[0],'rb') as fsig:
                    sig = pickle.load(fsig)
            except:
                print 'No sig file: ' + tks[0]
                miss_sigs += [tks[0]]
                applicable = False
                continue
            func_name = sig.graph['func_name']
            sig_name = sig.graph['sig_name']
            default_options = sig.graph['options']
            entry = symbol_table.lookup_func_name(func_name)
            if entry is None:
                applicable = False
                print 'Cannot locate the function %s for sig %s in specified kernel image symbol table' % (func_name,sig_name)
                continue
            t0 = time.time()
            (ty,addr,size) = entry
            cfg_acc = get_cfg_acc(b,addr,addr+size) 
            func_cfg = get_func_cfg(cfg_acc,addr,proj=b,sym_tab=symbol_table,simplify=True)
            if 'func_existence_test' in default_options:
                #Do a pure function existence testing here, no need to do symbolic execution.
                target_func = default_options['func_existence_test']
                print 'Func Existence Test for sig: %s, func_name: %s, target_func: %s' % (sig_name,func_name,target_func)
                cnt = test_func_existence(b,func_cfg,symbol_table,default_options['func_existence_test'])
            else:
                #Below is normal symbolic execution based matching.
                retry_cnt = 1
                while retry_cnt > 0:
                    cnt = 0
                    try:
                        (collision,cnt) = do_match_sig(sig,b,func_cfg,[addr,addr+size],cfg_acc,symbol_table,default_options)
                    except:
                        traceback.print_exc()
                        if cnt == 0:
                            cnt = -1
                        break
                    if collision:
                        print 'Addr collision when matching, retry...'
                    else:
                        break
                    retry_cnt = retry_cnt - 1
            t1 = time.time() - t0
            if len(tks) > 1:
                td = td + t1
                prev_cve = cve
                if cnt >= int(tks[1]):
                    res_dic[cve] = ('P',td)
                    td = 0
                    continue
            else:
                res_vec += [(sig_name,cnt,t1)]
                print '%s has %d matches, taking %.2f s' % res_vec[-1]
    if len(tks) > 1:
        if not cve in res_dic and applicable:
            res_dic[cve] = ('N',td)
        td = 0
        print '----------------RESULTS----------------'
        with open('match_res_%s_%.0f_m1' % (sys.argv[1][sys.argv[1].rfind('/')+1:],time.time()),'w') as f:
            for k in sorted(list(res_dic)):
                td = td + res_dic[k][1]
                l = '%s %s %.2f' % (k,res_dic[k][0],res_dic[k][1])
                print l
                f.write(l+'\n')
            f.write('Time: ' + str(td) + '\n')
            print 'Time: ' + str(td)
    else:
        print '----------------RESULTS----------------'
        with open('match_res_%s_%.0f_m0' % (sys.argv[1][sys.argv[1].rfind('/')+1:],time.time()),'w') as f:
            for v in res_vec:
                l = '%s %d %.2f' % v
                print l
                f.write(l+'\n')
    print '----------------MISSED----------------'
    for v in miss_sigs:
        print v

if __name__ == '__main__':
    match_sig()
