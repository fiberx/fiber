#!/usr/bin/python

import angr,claripy
import sys,os
import logging
import copy,re
import networkx
from networkx.algorithms import approximation
import itertools

#logging.basicConfig(level=logging.DEBUG) # adjust to the wanted debug level
dbg_out = True

def test_loader(b,base):
    print b.loader.min_addr
    print b.loader.max_addr
    print b.loader.memory[base+0x38]
    print b.arch

    blk = b.factory.block(addr=base+0xc440c4).capstone
    for ins in blk.insns:
        print ins

    irsb = b.factory.block(addr=base+0xc440c4).vex
    irsb.pp()

    for stmt_idx, stmt in enumerate(irsb.statements):
        print stmt_idx
        if hasattr(stmt,'expressions'):
            for expr in stmt.expressions:
                print expr.tag
                print expr

def load_kernel_image(path,arch,base,segments=None):
    load_options = {}
    load_options['auto_load_libs'] = False
    load_options['main_opts'] = {'backend': 'blob', 'custom_arch': arch, 'custom_base_addr': base, 'segments':segments}

    #Use loader.provide_symbol() or loader.provide_symbol_batch() to import symbol table.
    #-----------------------------------------------------------------------------------
    #def provide_symbol(self, owner, name, offset, size=0, sym_type=None):
    #    return self.provide_symbol_batch(owner, {name: (offset, size, sym_type)})
    #-----------------------------------------------------------------------------------
    #Usage: owner --> the Backend object, we can use loader.main_bin
    #       offset --> the offset relative to 0, not actual kernel load address
    #       sym_type --> https://github.com/angr/cle/blob/master/cle/backends/__init__.py#L148
    b = angr.Project(path, load_options=load_options, arch=arch)
    
    #test_loader(b,base)
    return b;

re_reg = 'reg_[\da-f]+_[\d]+_[\d]+' 
re_mem = 'mem_[\da-f]+_[\d]+_[\d]+' 
re_ret = 'fake_ret_value_[\d]+_[\d]+'

translate_arch = None
#We assume that the reg str looks like "reg_[offset Hex num]_N_[size in bits]"
def translate_reg_name(reg):
    #Since this can be called from re.sub(), the parameter is a 'SRE_Match' object, thus we should convert it to string if necessary.
    if reg is not str:
        reg = reg.group(0)
    global translate_arch
    if translate_arch == None:
        print 'translate_reg_name: set the translate_arch at first!'
        return reg
    if not reg.startswith('reg'):
        return reg
    tokens = reg.split('_')
    if len(tokens) <> 4:
        return reg
    offset = int(tokens[1],base = 16)
    size = int(tokens[3])/8
    return translate_arch.translate_register_name(offset = offset, size = size) + '_' + tokens[2]

#Replace the reg name in the string with a human-readable form
def make_reg_readable(arch,s):
    global translate_arch
    translate_arch = arch
    return re.sub(re_reg,translate_reg_name,s)

#Given a instruction address, this function will identify which registers/mems are read/write.
#This is done by parsing the generated VEX statements, which should work for all archs.
#Param: addr is the start of a block, size is the block size, if ins_list is provided, only the instructions on the list will be analyzed.
def get_ins_ops_info(proj,addr,size=None,ins_list=None, opt_level=0):
    irsb = proj.factory.block(addr,size=size,opt_level=opt_level).vex
    #info: addr --> {key:val}
    info = {}
    index = {}
    ss = irsb.statements
    for i in range(len(ss)):
        if ss[i].tag == 'Ist_IMark':
            index[ss[i].addr] = i
    ins_list = index.keys() if ins_list is None else [x for x in ins_list if index.has_key(x)]
    #NOTE: this list is arch-dependent
    #x30 is link register
    #ignore_regs = ['ip','pc','sp','xsp','x30']
    ignore_regs = []
    #TODO: it seems that VEX doesn't differentiate X0 and W0? But what if this matters?
    reg_name = lambda off: proj.arch.translate_register_name(offset=off)
    for addr in ins_list:
        info[addr] = {}
        #Skip the initial IMark
        for i in range(index[addr]+1,len(ss)):
            stmt = ss[i]
            if stmt.tag == 'Ist_Put':
                #Reg write
                reg = reg_name(stmt.offset)
                if not reg in ignore_regs:
                    info[addr].setdefault('put',set()).add(reg)
                #Do some recording heres if it's a 'put_ip' stmt.
                #TODO: Add register names if you want to support different archs.
                if reg in ('ip','pc'):
                    e = stmt.expressions
                    if len(e) == 1 and e[0].tag == 'Iex_Const':
                        if 'put_ip' in info[addr]:
                            print '[???]Instruction @ %x has multiple put_ip stmts..' % addr
                        info[addr]['put_ip'] = e[0].con.value
            elif stmt.tag == 'Ist_Store':
                #Mem write
                #We only indicate that there is a mem write in this instruction, actual data and addr will be decided in runtime.
                info[addr]['store'] = True
            elif stmt.tag == 'Ist_Exit':
                info[addr]['exit'] = True
            elif stmt.tag == 'Ist_IMark':
                break
            #NOTE: Reg read is special because it's not a statement, but an expression with tag 'Iex_Get'.
            #Similarly, mem read is 'Iex_Load' So to capture then, we need to iterate the expressions.
            for exp in stmt.expressions:
                if exp.tag == 'Iex_Get':
                    #Reg read
                    reg = reg_name(exp.offset)
                    if not reg in ignore_regs:
                        info[addr].setdefault('get',set()).add(reg)
                elif exp.tag == 'Iex_Load':
                    #Mem read
                    #Similar to mem write, we only indicate that there is a mem read.
                    info[addr]['load'] = True
    return (info,irsb.jumpkind)

def print_vex_blocks(proj,addrs,opt_level=0):
    for addr in addrs:
        print '[VEX] ' + hex(addr)
        irsb = proj.factory.block(addr,opt_level=opt_level).vex
        #irsb.pp()
        for stmt_idx, stmt in enumerate(irsb.statements):
            print '[' + str(stmt_idx) + '] ' + str(stmt) + ' -- ' + stmt.tag + ' -- ' + type(stmt).__name__

def get_cfg_acc(proj,start,end):
    return proj.analyses.CFGAccurate(context_sensitivity_level=0,starts=[start],call_depth=0,normalize=True)

#Get the CFGFast of the function starting from 'start' and ending at 'end'
def get_cfg_fast(proj,start,end):
    # The regions in the image that the CFG should cover 
    regions = [(start,end)]
    # Specify the start addresses of functions need to be analyzed
    function_starts = [start]
    # It seems that 'regions' and 'start_at_entry' parameters are not supported in this version?
    return proj.analyses.CFGFast(symbols=False,regions=regions,start_at_entry=False,function_prologues=False,function_starts=function_starts)

#Get an element from a set
def pick_one(s):
    for e in s:
        break
    return e

#'his' is a sequence of basic block addrs, this function judge whether 'state' has gone through the same history. 
def old_days(state,his):
    so_far = [x for x in state.history.bbl_addrs]
    return str(so_far)[1:-1].startswith(str(his)[1:-1])

#Use DFS to get all the paths from start to target.
#TODO: To deal with paths with loops.
def get_path(cfg,path,target,visited=set()):
    n = path[-1]
    if n.addr == target.addr:
        return path

    if n.addr in visited:
        return
    visited.add(n.addr)

    for x in cfg.successors(n):
        if x.addr not in visited:
            new_path = copy.deepcopy(path)
            new_path.append(x)
            get_path(cfg,new_path,target,visited)

#The cfg is a DiGraph
def get_all_preds_raw(cfg,n,preds):
    preds.add(n)
    for x in cfg.predecessors(n):
        if x not in preds:
            get_all_preds_raw(cfg,x,preds)

#The cfg is a DiGraph
def get_all_preds(cfg,n,preds):
    preds.add(n.addr)
    for x in cfg.predecessors(n):
        if x.addr not in preds:
            get_all_preds(cfg,x,preds)

#Given a subgraph instead of a single node, return all predecessors of this subgraph.
def get_all_preds4graph(cfg,g):
    preds = set()
    en = set([x.addr for x in g.nodes() if g.in_degree(x) == 0])
    en = set([get_node_by_addr(cfg,x) for x in en])
    for n in en:
        t = set()
        get_all_preds(cfg,n,t)
        preds = preds.union(t)
    return preds

#The cfg is a DiGraph
def get_all_succs(cfg,n,succs):
    succs.add(n.addr)
    for x in cfg.successors(n):
        if x.addr not in succs:
            get_all_succs(cfg,x,succs)

#Given a subgraph instead of a single node, return all successors of this subgraph.
def get_all_succs4graph(cfg,g):
    succs = set()
    en = set([x.addr for x in g.nodes() if g.out_degree(x) == 0])
    en = set([get_node_by_addr(cfg,x) for x in en])
    for n in en:
        t = set()
        get_all_succs(cfg,n,t)
        succs = succs.union(t)
    return succs

#Given a CFGAcc or CFGFast and a function start address, return the function CFG which is a DiGraph.
#'simplify' means whether we should optimize the CFG topology to eliminate all absolute control transfer nodes (eg. b,jmp)
def get_func_cfg(cfg,start,normalize=True,sym_tab=None,proj=None,simplify=False):
    func = cfg.functions[start]
    if func is None:
        print 'No function at %x' % start
        return None
    if normalize:
        func.normalize()
    #Different from the 'cfg', func_cfg is a networkx.DiGraph.
    g = copy.deepcopy(func.transition_graph)
    #Do some extra checks
    exception_nodes = [hex(x.addr) for x in g.nodes() if x.size is None]
    if len(exception_nodes) > 0:
        print '[FUNC_CFG] Plz check following nodes, they may contain un-decodable instructions: ' + str(exception_nodes)
    #Issue 0: Sometimes this graph will include size 0 node, which represent functions that are called by current function.
    #We don't need them actually.
    g.remove_nodes_from([x for x in g.nodes() if x.size == 0 or x.size is None])
    #Issue 1: This is a hacking, sometimes a function may call a non-return function in the end (e.g. __stack_chk_fail),
    #we must ensure that callee node will not have any successors..
    #*But* we need Angr proj and sym_table to enable the detection and correction below. 
    non_ret_funcs = ('__stack_chk_fail')
    non_rets = []
    if sym_tab and proj:
        for n in g.nodes():
            irsb = proj.factory.block(n.addr,size=n.size,opt_level=0).vex
            if irsb.jumpkind == 'Ijk_Call':
                name = get_exit_func_name(proj,irsb,sym_tab)
                if name and name in non_ret_funcs:
                    non_rets += [n]
        if non_rets:
            g.remove_edges_from(g.out_edges(non_rets))
    #If specified, optimize out absolute jump nodes.
    if simplify:
        #Note that here 'g' is already a deepcopy of original 'transition_graph' in cfg_acc
        #So modify 'g' will not affect original cfg_acc.
        simplify_cfg_aarch64(proj,g)
    return g

def simplify_cfg_aarch64(proj,g):
    if not proj:
        return g
    def _is_abs_jmp_node(n):
        if not n.size or n.size != 4:
            return False
        succs = g.successors(n)
        if succs and len(succs) > 1:
            return False
        cap = proj.factory.block(n.addr,size=4).capstone
        opc = cap.insns[0].insn.mnemonic
        if opc in ('b','B','prfm'):
            return True
        return False
    absn = [n for n in g.nodes() if _is_abs_jmp_node(n)]
    for n in absn:
        preds = g.predecessors(n)
        succs = g.successors(n)
        g.remove_node(n)
        if preds and succs:
            for p in preds:
                g.add_edge(p,succs[0])
    return g

#The cfg is a DiGraph.
def get_node_by_addr(cfg,addr,any_addr=False):
    nodes = [ x for x in cfg.nodes() if x.addr==addr and x.size is not None]
    if nodes:
        return sorted(nodes,key=lambda x:x.size)[0]
    if any_addr:
        nodes = [ x for x in cfg.nodes() if x.size is not None and x.addr <= addr and addr < x.addr + x.size ]
        if nodes:
            return sorted(nodes,key=lambda x:x.size)[0]
    return None

#Below are some signature-related stuff.

def _calc_next_instruction_addr(proj,addr):
    if proj.arch.name == 'AARCH64':
        return addr + 4
    else:
        print 'Unsupported arch: ' + proj.arch.name
        return addr + 4

#The main purpose is to set up the initial 'formulas' map for the given node in the signature.
#The main task is to identify the address and involved registers for each root instruction in the node.
#Param: g --> sig graph n --> node
def init_sig_node_formulas(proj,g,n,sym_tab=None):
    g.node[n]['formulas'] = {}
    formulas = g.node[n]['formulas']
    (ins_info,jumpkind) = get_ins_ops_info(proj,n.addr,n.size,list(g.node[n]['root_ins']))
    g.node[n]['jumpkind'] = jumpkind
    #'x30' is link register for 'bl'
    ignore_regs = ['ip','pc','sp','xsp','x30','cc_op','cc_ndep','cc_dep1','cc_dep2']
    stack_regs = ['sp','xsp']
    for addr in ins_info:
        if ins_info[addr].has_key('exit'):
            #An exit instruction.
            #'a-g-k' is a addr-guard-jumpkind tuple list. 
            formulas[addr] = {'type':'exit','a-g-k':[]}
        elif 'put_ip' in ins_info[addr] and ins_info[addr]['put_ip'] <> _calc_next_instruction_addr(proj,addr):
            #We want to capture a special case here.
            #The 'exit' type is from 'Ist_Exit' stmt, which usually indicates a conditional jump, but what about unconditional jump?
            #Instructions like 'bl' 'b' usually don't have 'Ist_Exit' stmt, what they do is simply set 'ip' register to target address,
            #but other normal instructions will also set 'ip' to the next instruction, so here we use a heuristic: if an instruction
            #will set 'ip' to somewhere that is not its next instruction (but itself is not of 'exit' type), then it should be an unconditional jump.
            formulas[addr] = {'type':'exit','a-g-k':[]}
            #Parse the function name if possible.
            if sym_tab is not None:
                e = sym_tab.lookup(ins_info[addr]['put_ip'])
                if e is not None:
                    g.node[n]['exit_func_name'] = e[1]
                    formulas[addr]['func_name'] = e[1]
        elif ins_info[addr].has_key('store'):
            #I want to put a special filter here: for the instructions that store sth to stack variables, I want to exclude them from root instructions.
            #Because they are very likely to be retrieved later, that's to say in theory they should have out edges in DFG but unfortunately current DFG
            #analysis cannot recognize dependencies related to memory location. 
            #TODO: may consider to improve the DFG analysis to make it able to deal with simple memory dependencies.
            if ins_info[addr].has_key('get') and any(reg in ins_info[addr]['get'] for reg in stack_regs):
                g.node[n]['root_ins'].remove(addr)
                g.graph['root_ins'].remove(addr)
                continue
            #This is a mem store instruction
            #a-d-l: addr-data-length tuple list
            formulas[addr] = {'type':'store','a-d-l':[]}
        elif ins_info[addr].has_key('load'):
            #This is a mem load instruction
            formulas[addr] = {'type':'load'}
            #For mem load instruction we only need to care about the regs that are written.
            if ins_info[addr].has_key('put'):
                for reg in ins_info[addr]['put']:
                    if reg not in ignore_regs:
                        formulas[addr][reg] = []
        else:
            #This instruction has nothing to do with mem, it should be a data transfer between regs.
            formulas[addr] = {'type':'other'}
            if ins_info[addr].has_key('put'):
                for reg in ins_info[addr]['put']:
                    if reg not in ignore_regs:
                        formulas[addr][reg] = []
    return

#A signature is basically an attributed CFG, we use DiGraph to implement this, which support attributes for nodes/edges.
#Params: cfg is a DiGraph with normal BBs as nodes.
def init_signature(proj,cfg,addrs,insns=None,pos=None,negs=None,sym_tab=None):
    #print [hex(x) for x in addrs]
    nodes = [get_node_by_addr(cfg,x) for x in addrs]
    #Get in_degree and out_degree in original CFG.
    ind = {}
    outd = {}
    for n in nodes:
        ind[n.addr] = cfg.in_degree(n)
        outd[n.addr] = cfg.out_degree(n)
    #Get subgraph
    og = cfg.subgraph(nodes)
    og = copy.deepcopy(og)
    sigs = []
    #Get the weakly connected subgraphs
    for g in networkx.weakly_connected_component_subgraphs(og):
        #Get the DFG for these nodes
        dfgs = get_dfg(proj,[ x for x in g.nodes() if x.size <> 0])
        #This holds all root instruction addrs of the whole signature graph.
        g.graph['root_ins'] = set()
        #Set attributes of the nodes in the subgraph
        void_node = []
        for n in g.nodes():
            #The node is of the type 'angr.knowledge.codenode.BlockNode'
            #print '---------------------------'
            #print '%x,%x' % (n.addr,n.size)
            if n.size == 0:
                #This should be the start of another function which is called in current function.
                #TODO: what information to add here? Maybe the function name?
                continue
            #The DFG is on the VEx statements (opt_level=0) level
            #TODO: do we really need to store DFG for each node?
            if n.addr not in dfgs or dfgs[n.addr] is None:
                print 'No DFG generated for (%x,%x)' % (n.addr,n.size)
                g.node[n]['dfg'] = None
                #This node should contain only one control-transfer instruction.
                root_ins = set([n.addr])
            else:
                g.node[n]['dfg'] = dfgs[n.addr]
                #Identify the root instructions for each node according to its DFG.
                root_ins_d = get_root_ins_addr(dfgs[n.addr])
                #We have two filter modes: pos/neg markers based and accurate instruction list based.
                #If we have DWARF debug information, we should always use the accurate instruction list based filter, which is simply better.
                root_ins = set(root_ins_d.keys())
                if insns is not None:
                    root_ins = set(flt_root_ins_acc(g,n,root_ins_d,_get_in_node_addr(n,insns)))
                elif pos is not None or negs is not None:
                    root_ins = set(flt_root_ins_marker(g,n,root_ins,_get_in_node_addr(n,pos),_get_in_node_addr(n,negs)))
            if not root_ins:
                void_node.append(n)
                continue
            g.node[n]['root_ins'] = root_ins
            g.graph['root_ins'] = g.graph['root_ins'].union(g.node[n]['root_ins'])
            #Original code block
            #TODO: should we set opt_level = 0 here?
            g.node[n]['block'] = proj.factory.block(n.addr,size=n.size)
            #Record the in_degree and out_degree in original CFG
            g.node[n]['in_d'] = ind[n.addr]
            g.node[n]['out_d'] = outd[n.addr]
            #Entry format of the formulas dict: addr --> (reg_name,formula)
            init_sig_node_formulas(proj,g,n,sym_tab=sym_tab)
        for n in void_node:
            if ok_to_remove_node(g,n):
                g.remove_node(n)
            else:
                set_padding_node(g,n)
        sigs.append(g)
    #If the identified patch areas are not within a same sub-graph, we need to organize them into one.
    if len(sigs) > 1:
        print 'Need to combine scattered instructions.'
        sigs = combine_subsigs(cfg,sigs)
    return sigs

#Return true if removing node n from g doesn't break its connectivity.
#TODO: Any simpler way to decide this?
def ok_to_remove_node(g,n):
    g0 = copy.deepcopy(g)
    n0 = get_node_by_addr(g0,n.addr)
    g0.remove_node(n0)
    return len([x for x in networkx.weakly_connected_component_subgraphs(g0)]) <= 1

def combine_subsigs(cfg,sigs):
    if not sigs or len(sigs) <= 1 or not cfg:
        return sigs
    #addrs of all non-padding nodes 
    addrs = {}
    for g in sigs:
        for n in g.nodes():
            addrs[n.addr] = g.node[n]
    #Start to merge the sub-sigs pair by pair.
    sg = sigs[0]
    for i in range(1,len(sigs)):
        sg = _combine_subsigs(cfg,sg,sigs[i])
    #TODO: Do we need to develop some heuristics (eg. give up the combined sig if it contains too many padding nodes.)?
    sg = copy.deepcopy(sg)
    for n in sg.nodes():
        if n.addr in addrs:
            sg.node[n] = addrs[n.addr]
        else:
            set_padding_node(sg,n)
    sg.graph['root_ins'] = set()
    for g in sigs:
        sg.graph['root_ins'] = sg.graph['root_ins'].union(g.graph['root_ins'])
    return [sg]

#Given a DiGraph and two separate sub-graphs, merge them together.
def _combine_subsigs(cfg,g0,g1):
    if not len(g0) or not len(g1):
        return g0 if not len(g1) else g1
    o_cfg = cfg
    #get_cfg_wo_loops() will return a copy of original graph without modifying it.
    cfg = get_cfg_wo_loops(o_cfg)
    g0 = get_cfg_wo_loops(g0)
    g1 = get_cfg_wo_loops(g1)
    a0 = set([x.addr for x in g0.nodes()])
    a1 = set([x.addr for x in g1.nodes()])
    if a0.intersection(a1):
        #No padding nodes are needed.
        t = a0.union(a1)
        nodes = [get_node_by_addr(o_cfg,x) for x in t]
        sg = o_cfg.subgraph(nodes)
        gs = [g for g in networkx.weakly_connected_component_subgraphs(sg)]
        if len(gs) > 1:
            #How can this be possible?
            print '!!!!Fail to merge two signatures with common nodes??'
        return sorted(gs,key=lambda x:len(x))[-1]
    p0 = get_all_preds4graph(cfg,g0)
    p1 = get_all_preds4graph(cfg,g1)
    s0 = get_all_succs4graph(cfg,g0)
    s1 = get_all_succs4graph(cfg,g1)
    if p0.intersection(a1):
        t = p0.intersection(s1)
        gs = cluster_padding_nodes(cfg,t)
        t = set([x.addr for x in gs[0].nodes()])
    elif p1.intersection(a0):
        t = p1.intersection(s0)
        gs = cluster_padding_nodes(cfg,t)
        t = set([x.addr for x in gs[0].nodes()])
    else:
        #In this case, consider both common predecessor and successor, choose the smaller resulting signature.
        #(1)Predecessor
        tp = p0.intersection(p1)
        if not tp:
            print '!!!Null common predecessors'
            print len(g0)
            print len(g1)
            print 'g0 ' + hex_array_sorted([n.addr for n in g0.nodes()])
            print 'a0 ' + hex_array_sorted(a0) 
            print 'p0 ' + hex_array_sorted(p0) 
            print 'g1 ' + hex_array_sorted([n.addr for n in g1.nodes()])
            print 'a1 ' + hex_array_sorted(a1) 
            print 'p1 ' + hex_array_sorted(p1) 
        gs = cluster_padding_nodes(cfg,tp)
        en = set()
        for g in gs:
            en = en.union(set([x.addr for x in g.nodes() if g.out_degree(x) == 0]))
        en = [get_node_by_addr(cfg,x,any_addr=True) for x in en]
        #Choose a preceding node that minimize the number of padding nodes. 
        def _calc_common_pred_path(n):
            succs = set()
            get_all_succs(cfg,n,succs)
            pad0 = succs.intersection(p0)
            pad1 = succs.intersection(p1)
            return pad0.union(pad1) 
        en = map(lambda x:(x,_calc_common_pred_path(x)),list(en))
        en = sorted(en,key=lambda x:len(x[1]))
        #(2)Successor
        ts = s0.intersection(s1)
        if ts:
            gs = cluster_padding_nodes(cfg,ts)
            sn = set()
            for g in gs:
                sn = sn.union(set([x.addr for x in g.nodes() if g.in_degree(x) == 0]))
            sn = [get_node_by_addr(cfg,x,any_addr=True) for x in sn]
            #Choose a succeding node that minimize the number of padding nodes. 
            def _calc_common_succ_path(n):
                preds = set()
                get_all_succs(cfg,n,preds)
                pad0 = preds.intersection(s0)
                pad1 = preds.intersection(s1)
                return pad0.union(pad1) 
            sn = map(lambda x:(x,_calc_common_succ_path(x)),list(sn))
            sn = sorted(sn,key=lambda x:len(x[1]))
        else:
            sn = []
        if not sn and not en:
            #Something very unusual must happen
            print 'Fail to combine two sub-CFG, possibly there are unrecognized instructions in the function...'
            t = set()
        else:
            t = en[0][1] if not sn or len(en[0][1]) <= len(sn[0][1]) else sn[0][1]
    t = t.union(a0).union(a1)
    nodes = [get_node_by_addr(o_cfg,x) for x in t]
    sg = o_cfg.subgraph(nodes)
    gs = [g for g in networkx.weakly_connected_component_subgraphs(sg)]
    if len(gs) > 1:
        #This should be impossible...
        print '!!!After merging sub-sigs, there are still multiple ones..'
    else:
        print '------Sig w/ padding nodes: ' + str([hex(x.addr) for x in gs[0].nodes()])
    return gs[0]

def cluster_padding_nodes(cfg,addrs):
    nodes = [get_node_by_addr(cfg,x) for x in addrs]
    sg = cfg.subgraph(nodes)
    gs = [g for g in networkx.weakly_connected_component_subgraphs(sg)]
    return sorted(gs,key=lambda x:len(x))

def combine_subsigs_steiner(cfg,sigs):
    if not sigs or len(sigs) <= 1 or not cfg:
        return sigs
    #addrs of all non-padding nodes 
    addrs = {}
    for g in sigs:
        for n in g.nodes():
            addrs[n.addr] = g.node[n]
    #steiner tree problem is in general NP-hard, here we use the approximation algorithm in the networkx package.
    u_cfg = cfg.to_undirected()
    nodes = [get_node_by_addr(u_cfg,x) for x in addrs]
    sg = approximation.steiner_tree(u_cfg,nodes)
    c_addrs = [x.addr for x in sg.nodes()]
    nodes = [get_node_by_addr(cfg,x) for x in c_addrs]
    sg = cfg.subgraph(nodes)
    sg = copy.deepcopy(sg)
    for n in sg.nodes():
        if n.addr in addrs:
            sg.node[n] = addrs[n.addr]
        else:
            set_padding_node(sg,n)
    sg.graph['root_ins'] = set()
    for g in sigs:
        sg.graph['root_ins'] = sg.graph['root_ins'].union(g.graph['root_ins'])
    return [sg]

def set_padding_node(cfg,n):
    cfg.node[n] = {'padding':1,'root_ins':set()}

#insns_d: a dict of root_ins_addr --> rooted_ins_addr set
#acc_list: accurate instruction list that composes the signature.
def flt_root_ins_acc(g,n,insns_d,acc_list,include_last=False,root_in_acc=False):
    #(1)First pick up all root instructions from insns_d which are also within acc_list.
    root_ins = set(insns_d.keys())
    root_ins = root_ins.intersection(set(acc_list))
    #(2)See whether all instructions in acc_list have been rooted by root_ins picked in (1), then add those un-rooted instructions to root_ins if root_in_acc is set.
    #Else just add enough root_ins until all instructions in acc_list are rooted.
    #Make a special optimization here: if there is no root instruction in acc_list and current node has no successors in the sig graph, then just return null.
    #Because in this situation, it's very likely that addr2line has added some unnecessary instructions.
    if not root_ins and g.out_degree(n) == 0 and g.number_of_nodes() > 1:
        return set()
    rooted_ins = set()
    for r in root_ins:
        rooted_ins = rooted_ins.union(insns_d[r])
    remain_ins = set(acc_list) - rooted_ins
    if root_in_acc:
        root_ins = root_ins.union(remain_ins)
    else:
        cand_root_ins = set(insns_d.keys()) - root_ins
        for c in cand_root_ins:
            if not remain_ins:
                break
            if insns_d[c].intersection(remain_ins):
                root_ins.add(c)
                remain_ins = remain_ins - insns_d[c]
    #Then we have a complementary rule: add the 'exit' instruction as root_ins if necessary.
    if include_last:
        in_deg = g.in_degree(n)
        out_deg = g.out_degree(n)
        last = n.addr + n.size - 4
        if g.number_of_nodes() <= 1 or out_deg > 0:
            root_ins.add(last)
    return root_ins

def flt_root_ins_marker(g,n,insns,pos,neg):
    _in_node = lambda n,m:m>=n.addr and m<n.addr+n.size
    _is_null = lambda x:x is None or not x
    _flt_pos = lambda ins,m:filter(lambda x:x>=m,ins)
    _flt_neg = lambda ins,m:filter(lambda x:x<=m,ins)
    in_deg = g.in_degree(n)
    out_deg = g.out_degree(n)
    if _is_null(pos):
        if _is_null(neg):
            #Full node is in the signature, no filtering.
            return insns
        else:
            #First few instructions are of interest.
            neg = max(neg)
            f_insns = _flt_neg(insns,neg)
            if _is_null(f_insns):
                #It seems that the marked instructions are not root ones, just return pre-filtering insns.
                return insns
            else:
                #Maybe we still need to include the 'exit' in the end..
                if out_deg > 0 or g.number_of_nodes() <= 1:
                    last = n.addr+n.size-4
                    return set(f_insns).union(set([last])) if last in insns else f_insns
                else:
                    return f_insns
    else:
        pos = min(pos)
        if _is_null(neg):
            #Last few instructions are of interest.
            f_insns = _flt_pos(insns,pos)
            if _is_null(f_insns):
                #This should be impossible
                print '!!!No root instructions after pos marker: ' + hex(pos)
                return insns
            return f_insns
        else:
            #Hang in the middle.
            neg = max(neg)
            fp_insns = _flt_pos(insns,pos)
            fn_insns = _flt_neg(insns,neg)
            fpn_insns = _flt_neg(fp_insns,neg)
            if _is_null(fpn_insns):
                if out_deg == 0 and g.number_of_nodes() > 1 and not _is_null(fn_insns):
                    return fn_insns
                elif in_deg == 0 and not _is_null(fp_insns):
                    return fp_insns
                else:
                    return insns
            else:
                if out_deg == 0 and g.number_of_nodes() > 1:
                    #No successors
                    return fpn_insns
                else:
                    #Have successors, consider 'exit' instruction.
                    last = n.addr+n.size-4
                    return set(fpn_insns).union(set([last])) if last in insns else fpn_insns

_get_in_node_addr = lambda n,ms:[] if ms is None else filter(lambda x:x>=n.addr and x<n.addr+n.size,list(ms))

def show_signature(sig):
    print '---------------------Signature-----------------------'
    print '---------------------Graph Information----------------------'
    if 'sig_name' in sig.graph:
        print '[Sig Name] ' + sig.graph['sig_name']
    if 'func_name' in sig.graph:
        print '[Function Name] ' + sig.graph['func_name']
    if 'options' in sig.graph:
        print '[options]'
        print sig.graph['options']
    print '[Root Instructions]'
    print [hex(x) for x in sig.graph.get('root_ins',[])]
    print '---------------------Node Information----------------------'
    for node in sig.nodes():
        print '>>>>>[%x,%x]<<<<<' % (node.addr,node.size)
        print 'succs: ' + str([hex(x.addr) for x in sig.successors(node)]) 
        print 'preds: ' + str([hex(x.addr) for x in sig.predecessors(node)]) 
        if 'padding' in sig.node[node]:
            print '~~PADDING~~'
            continue
        print 'jumpkind: ' + sig.node[node]['jumpkind']
        if 'exit_func_name' in sig.node[node]:
            print 'func: ' + sig.node[node]['exit_func_name']
        if 'fmt_str' in sig.node[node]:
            print 'fmt_str: ' + sig.node[node]['fmt_str']
        print 'root_ins: ' + str([hex(x) for x in sig.node[node]['root_ins']])
        print 'formulas:'
        for addr in sig.node[node]['formulas']:
            inf = sig.node[node]['formulas'][addr]
            print '###[%s] %x' % (inf['type'],addr)
            if 'a-d-l' in inf:
                adl = inf['a-d-l']
                for (a,d,l) in adl:
                    print '[A] %s [D] %s [L] %s' % _sig_get_str((a,d,l))
            elif 'a-g-k' in inf:
                agk = inf['a-g-k']
                for (a,g,k) in agk:
                    print '[A] %s [G] %s [K] %s' % _sig_get_str((a,g,k))
                if 'func_name' in inf:
                    print '[F] %s' % inf['func_name']
            else:
                for k in inf:
                    if k in ('type') or not isinstance(inf[k],list):
                        continue
                    print '[' + k + ']'
                    for e in inf[k]:
                        print '%s' % _sig_get_str([e])

def _sig_get_str(tlist):
    def _to_str(t):
        if isinstance(t,claripy.ast.Base):
            return t.hz_repr()
        elif isinstance(t,int) or isinstance(t,long):
            return hex(t)
        return str(t)
    return tuple(map(_to_str,tlist))

hex_array = lambda a:str([hex(x) for x in a])
hex_array_sorted = lambda a:str([hex(x) for x in sorted(a)])

#I want to do some trimmings here, reduce some unnecessary (and possibly harmful when matching) nodes in the signature.
def trim_signature(sig,addrs={},options={}):
    if options.get('trim_tail_abs_jmp',False):
        _trim_tail_abs_jmp(sig)
    if options.get('trim_tail_call_args',False):
        _trim_tail_call_args(sig)
    if options.get('trim_non_tail_roots',False):
        _trim_non_tail_roots(sig)
    #trim_non_tail_roots-%d-%d
    range_trim = filter(lambda x:x.find('trim_non_tail_roots-')>=0,list(options))
    for k in range_trim:
        tks = k.split('-')
        (n1,n2) = (int(tks[1]),int(tks[2]))
        aset = get_insns_for_lines(addrs,n1,n2)
        _trim_non_tail_roots(sig,aset)
    #farg-ln0-ln1:Xn,Xm
    farg = filter(lambda x:x.find('farg-')>=0,list(options))
    for fa in farg:
        tks = fa.split('-')
        (n1,n2) = (int(tks[1]),int(tks[2]))
        aset = get_insns_for_lines(addrs,n1,n2)
        _trim_farg_aarch64(sig,aset,options[fa])

#Return the instruction set for a specific line range.
def get_insns_for_lines(addrs,l0,l1):
    aset = set()
    for ln in addrs:
        if ln >= l0 and ln <= l1:
            aset = aset.union(addrs[ln])
    return aset

#Within the instruction set, only reserve the ones filling the specified registers.
def _trim_farg_aarch64(sig,aset,ps):
    for n in sig.nodes():
        if 'padding' in sig.node[n]:
            continue
        formulas = sig.node[n]['formulas']
        for k in list(formulas):
            if not k in aset:
                continue
            if formulas[k]['type'] in ('load','other'):
                regs = set([x for x in formulas[k] if x != 'type' and isinstance(formulas[k][x],list)])
                if not regs.intersection(ps):
                    formulas.pop(k)
                    sig.graph['root_ins'].discard(k)
                    sig.node[n]['root_ins'].discard(k)

#Only reserve the last instruction as the root instruction for each node.
def _trim_non_tail_roots(sig,aset=set()):
    for n in sig.nodes():
        if 'padding' in sig.node[n]:
            continue
        formulas = sig.node[n]['formulas']
        kl = sorted(list(formulas))
        for k in kl[:-1]:
            if k in aset:
                formulas.pop(k)
                sig.graph['root_ins'].discard(k)
                sig.node[n]['root_ins'].discard(k)

#For the tail Ijk_Call node, ignore all the root instructions beside the 'call' instruction itself.
#This is useful when sometimes we want to simply include a call below the patch site into the signature as context, while in the meanwhile
#don't want the args of this call to introduce extra noises with their semantic formulas.  
def _trim_tail_call_args(sig):
    for n in sig.nodes():
        if 'padding' in sig.node[n]:
            continue
        if sig.out_degree(n) <> 0 or sig.node[n]['jumpkind'] <> 'Ijk_Call': 
            continue
        formulas = sig.node[n]['formulas']
        for k in list(formulas):
            if formulas[k]['type'] in ('load','other','store'):
                formulas.pop(k)
                sig.graph['root_ins'].discard(k)
                sig.node[n]['root_ins'].discard(k)

#Eliminate all tail nodes that simply do an absolute jump of Ijk_Boring.
def _trim_tail_abs_jmp(sig):
    if sig.number_of_nodes() <= 1:
        return
    def _pure_abs_jmp(n):
        if n.size > 4 or sig.node[n]['out_d'] > 1 or sig.node[n]['jumpkind'] <> 'Ijk_Boring':
            return False
        form = sig.node[n]['formulas'][n.addr]
        if form['type'] == 'exit':
            for _,g,_ in form['a-g-k']:
                if str(g).split(' ')[1][:-1] <> 'True':
                    return False
        return True
    to_remove = []
    for n in sig.nodes():
        if 'padding' in sig.node[n]:
            continue
        if sig.out_degree(n) == 0 and _pure_abs_jmp(n):
            to_remove.append(n)
    sig.remove_nodes_from(to_remove)

#There can be 'Ijk_Call' nodes in the signature, for these callees, what can we do if we have their function prototype?
#One thing for example is that we can obtain the format string for 'printk', instead of a simple global str pointer loaded into x0. Thus
#we can compare the format string contents to locate patch.
def analyze_func_args_aarch64(image,base,sig,options={}):
    if options.get('match_fmt_str',False):
        _analyze_fmt_str_aarch64(image,base,sig)

fmt_func_map_aarch64 = {
    'printk':'x0',
    'snprintf':'x2',
    '__dynamic_pr_debug':'x1',
    'seq_printf':'x1',
    '_dev_info':'x1',
    'dev_err':'x1',
    'dprintk':'x1',
    'write_str':'x1',
}
#If there is any callee in the signature that has a format string as one parameter, try to extract the format string from the image if possible.
def _analyze_fmt_str_aarch64(image,base,sig):
    with open(image,'r') as f:
        for n in sig.nodes():
            if not 'exit_func_name' in sig.node[n]:
                continue
            fmt_reg = fmt_func_map_aarch64.get(sig.node[n]['exit_func_name'],None)
            if fmt_reg is None:
                continue
            formulas = sig.node[n]['formulas']
            addr_ast = None
            for k in formulas:
                if fmt_reg in formulas[k]:
                    addr_ast = formulas[k][fmt_reg]
                    break
            if addr_ast is None:
                #Maybe the register is assigned a value in other nodes, we'll see..
                print '!!! Cannot find the formulas for fmt arg reg %s in node %x' % (fmt_reg,n.addr)
                continue
            #OK, we get the addr ast for the fmt string. 
            #For now we only process the concrete addr.
            addr = None
            for a in addr_ast:
                if a.op == 'BVV':
                    addr = a.args[0]
                    break
            if addr is None:
                print 'No concrete addr found in: ' + str(addr_ast)
                continue
            #Finally... Extract the string from image.
            offset = addr - base
            f.seek(-1,2)
            size = f.tell()
            if offset < 0 or offset > size:
                #print 'Addr %x out bound.' % addr
                continue
            f.seek(offset)
            fmt_str = ''
            while True:
                c = f.read(1)
                if c == '\0':
                    break
                else:
                    fmt_str += c
            if fmt_str <> '':
                sig.node[n]['fmt_str'] = fmt_str

#This intends to
#(1) reduce the redundant formulas stored in signature.
#(2) extract 'if' terms from state_merge related ITEs.
def simplify_signature(sig):
    #Deduplicate based on str rep.
    def _dedup(tlist):
        seen = set()
        def _f1(x):
            x = x if type(x).__name__ in ('tuple','list') else [x]
            s = str(_sig_get_str(x))
            if s in seen:
                return False
            else:
                seen.add(s)
                return True
        return filter(_f1,tlist)
    for node in sig.nodes():
        if 'padding' in sig.node[node]:
            continue
        for addr in sig.node[node]['formulas']:
            inf = sig.node[node]['formulas'][addr]
            if 'a-d-l' in inf:
                r = []
                for e in inf['a-d-l']:
                    r += excavate_if_tuple(e)
                inf['a-d-l'] = _dedup(r)
            elif 'a-g-k' in inf:
                r = []
                for e in inf['a-g-k']:
                    r += excavate_if_tuple(e)
                inf['a-g-k'] = _dedup(r)
            else:
                for k in inf:
                    if k in ('type'):
                        continue
                    if isinstance(inf[k],list):
                        r = []
                        for e in inf[k]:
                            t = excavate_if(e)
                            r += map(lambda x:x[1],t)
                        inf[k] = _dedup(r)

def excavate_if_tuple(t):
    terms = [excavate_if(e) for e in t]
    res = []
    def _is_consistent(cl):
        seen = set()
        for e in cl:
            for i in e:
                if str(claripy.Not(i)) in seen:
                    return False
                else:
                    seen.add(str(i))
        return True
    for e in itertools.product(*terms):
        if _is_consistent(map(lambda x:x[0],e)):
            #e: ((),(),..)
            res += [tuple(map(lambda x:x[1],e))]
    return res

#Excavate the 'if' conditions and ignore all 'state_merge' conditions.
def excavate_if(f):
    if not isinstance(f,claripy.ast.Base):
        return [([],f)]
    fs = [([],f)]
    prev = 0
    while len(fs) > prev:
        prev = len(fs)
        new = []
        for e in fs:
            ee = e[1].ite_excavated
            if ee.op == 'If':
                if is_state_merge_condition(ee.args[0]):
                    new += [(e[0]+[ee.args[0]],ee.args[1]),(e[0]+[claripy.Not(ee.args[0])],ee.args[2])]
                else:
                    #TODO: What can we do here? Maybe a deeper excavation..
                    new.append(e)
            else:
                new.append(e)
        fs = new
    return fs

#Decide whether a condition is about the state merge flag.
def is_state_merge_condition(f):
    if f.op == '__eq__':
        if str(f.args[0]).find('state_merge_') >= 0 or str(f.args[1]).find('state_merge_') >= 0:
            return True
    return False

#Given an 'irsb' and a symbol table, try to parse the exit function name of it if any.
#NOTE: The irsb should be generated with 'opt_level==0' !
def get_exit_func_name(proj,irsb,sym_tab):
    if irsb.jumpkind <> 'Ijk_Call' or sym_tab is None:
        return None
    reg_name = lambda off: proj.arch.translate_register_name(offset=off)
    ss = irsb.statements
    for i in range(len(ss)-1,-1,-1):
        if ss[i].tag == 'Ist_Put' and reg_name(ss[i].offset) in ('pc','ip'):
            exprs = ss[i].expressions
            if len(exprs) == 1 and exprs[0].tag == 'Iex_Const':
                entry = sym_tab.lookup(exprs[0].con.value)
                return None if entry is None else entry[1]
            else:
                #It's not a call to a concrete function address
                return None
    return None

#'bbs' can be either an address list or a node list.
def get_dfg(proj,bbs):
    #Note that we should choose 'no optimization' to ensure that vex code faithfully reflect relationship between original asm code.
    #E.g.
    # 1 mov x19,x0
    # 2 cbz x19,0xffff6000
    #We want to see that ins 2 depends on ins 1, but with vex optimization, x0 may be stored in t0 previously, and this same t0 will be used directly
    #in both ins 1 and 2, thus we lost the dependency between ins 1 and 2. (now they both depends on t0, but without relationship between themselves). 
    dfg = proj.analyses.DFG(nodes=bbs,opt_level=0)
    return dfg.dfgs

#Given a dfg (on VEX statements), return the root instruction (capstone) address dict:
#root_addr --> all the rooted instruction addr set
def get_root_ins_addr(dfg):
    if dfg is None:
        return None
    roots = get_root_nodes_from_dfg(dfg)
    addrs = {}
    for r in roots:
        preds = set()
        get_all_preds_raw(dfg,r,preds)
        preds = set([x.ins_addr for x in preds if type(x).__name__ == 'Dfg_Node'])
        curs = addrs.get(r.ins_addr,set())
        addrs[r.ins_addr] = curs.union(preds)
    return addrs

#Given a DFG (a DiGraph), return a list of the root nodes that don't depend on other statement nodes (but can still
#depend on other expr or constant nodes).
def get_root_nodes_from_dfg(g):
    roots = []
    for node in g.nodes():
        #All statement nodes are wrapped into 'Dfg_Node's
        if type(node).__name__ <> 'Dfg_Node':
            continue
        #A depends on B --> an edge from B to A --> root nodes have no successors.
        succs = g.successors(node)
        if succs is None or len(succs) == 0:
            #Sometimes due to the low optimization level, there can exist some useless vex instructions.
            #e.g. t10 = t0 but t10 will never be used later. In general, tmp variable must be used later,
            #otherwise, we regard it as useless.
            if node.tag <> 'Ist_WrTmp':
                roots.append(node)
    return roots

#Given a DiGraph CFG, a positive marker addr and a list of neg addrs, return the nodes in the marked area.
#default_cfg_ends: if no 'negs' are provided, whether to use the bounds of cfg as the 'negs', if not, only returns the node where 'pos' locates.
#ignore_leading_neg: if the neg marker is at the start of a node, whether to exclude this node.
#from_func_start: whether the starting node is also the function start.
def get_node_addrs_between(cfg,pos,negs,**kwargs):
    #Get the options.
    default_cfg_ends = kwargs.get('default_cfg_ends',True)
    ignore_leading_neg = kwargs.get('ignore_leading_neg',False)
    drop_neg_node = kwargs.get('drop_neg_node',False)
    from_func_start = kwargs.get('from_func_start',False)
    has_loop = kwargs.get('has_loop',True)
    #NOTE: The loop back edges shouldn't be removed when doing symbolic execution, but sometimes we need.
    #They may interfere when we want to decide the nodes in the signature. (e.g. 0->1->2->3->0 and pos is in 2, neg is in 3)
    #NOTE: the cfg returned by 'get_cfg_wo_loops' is a copy, thus we don't modify the passed-in cfg.
    if not has_loop:
        cfg = get_cfg_wo_loops(cfg)
    succs = set()
    n_pos = get_node_by_addr(cfg,pos,any_addr=True)
    if n_pos is None and not from_func_start:
        print 'Fail to get start node @ ' + hex(pos)
        return set()
    if not from_func_start:
        get_all_succs(cfg,n_pos,succs)
    preds = set()
    if negs:
        for neg in negs:
            n_neg = get_node_by_addr(cfg,neg,any_addr=True)
            if n_neg is None:
                print 'Fail to get end node @ ' + hex(neg)
                continue
            tmp = set()
            get_all_preds(cfg,n_neg,tmp)
            #If the negative marker is just at the start of a node, then exclude it if the option is set.
            if (neg == n_neg.addr and ignore_leading_neg) or drop_neg_node:
                tmp.remove(n_neg.addr)
            preds = preds.union(tmp)
        return succs.intersection(preds) if not from_func_start else preds
    else:
        #One corner case is that we have no negative markers, one example is that the function only has one 'return' statement,
        #thus we can only put one positive marker before 'return' but no negative marker after 'return' since it will (usually) be ignored by compiler.
        #If this is the case, we return nodes according to 'default_cfg_ends'.
        if default_cfg_ends:
            return succs if not from_func_start else set([x.addr for x in cfg.nodes()])
        else:
            return set([n_pos.addr])

#Accepts a DiGraph, return a copy containing no loops.
def get_cfg_wo_loops(cfg):
    #For safety, don't modify original cfg.
    cfg = copy.deepcopy(cfg)
    #Find loops
    loopfinder = angr.analyses.LoopFinder(graph=cfg)
    loopbacks = []
    for loop in loopfinder.loops:
        loopbacks += loop.continue_edges
    cfg.remove_edges_from(loopbacks)
    return cfg

#Identify the bound of a list of DiGraph..
def get_cfg_bound(gs):
    bounds = set()
    for g in gs:
        bounds = bounds.union(set([n.addr for n in g.nodes() if g.out_degree(n) == 0]))
    return bounds
