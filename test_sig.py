#!/usr/bin/python
import angr,simuvex,claripy
import sys,os
import logging,traceback
import copy,re
import time
import networkx
try:
    import cPickle as pickle
except ImportError:
    import pickle

from utils_sig import *

ARCH = 'aarch64'
BASE = 0xffffff8008080000;

def try_dfg():
    b = load_kernel_image(sys.argv[1],ARCH,BASE)
    start = BASE+0xc440c4
    end = BASE+0xc44178
    cfg = get_cfg_acc(b,start,end)
    func = cfg.functions[start]
    n = cfg.get_any_node(addr=start,anyaddr=True)
    '''
    print func
    for n in func.nodes:
        print n
    func.dbg_draw('test.png')
    '''
    #Note that we should choose 'no optimization' to ensure that vex code faithfully reflect relationship between original asm code.
    #E.g.
    # 1 mov x19,x0
    # 2 cbz x19,0xffff6000
    #We want to see that ins 2 depends on ins 1, but with vex optimization, x0 may be stored in t0 previously, and this same t0 will be used directly
    #in both ins 1 and 2, thus we lost the dependency between ins 1 and 2. (now they both depends on t0, but without relationship between themselves). 
    dfg = b.analyses.DFG(nodes=[n.addr],opt_level=0)
    
    print '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'
    print_vex_blocks(b,[n.addr])
    print '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<'
    ndfg = dfg.dfgs[start]
    for node in ndfg.nodes():
        print node
    print '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<'
    for root in get_root_nodes_from_dfg(ndfg):
        print root

def try_vfg():
    b = load_kernel_image(sys.argv[1],ARCH,BASE)
    start = BASE+0xc440c4
    end = BASE+0xc44178
    cfg = get_cfg_fast(b,start,end)

    st = b.factory.blank_state(addr=start)
    st.options.add(simuvex.o.CALLLESS)
    # To prevent the engine from discarding log history
    st.options.add(simuvex.o.TRACK_ACTION_HISTORY)
    st.inspect.b('symbolic_variable', when=simuvex.BP_AFTER, action=sym_capture)
    st.inspect.b('address_concretization', when=simuvex.BP_AFTER, action=addr_conc_capture)

    vfg = b.analyses.VFG(cfg=cfg, context_sensitivity_level=0, start=start, function_start=start, initial_state=None, interfunction_level=0)
    print vfg

def print_cfg_graph(start,end):
    b = load_kernel_image(sys.argv[1],ARCH,BASE)
    #x3
    #print b.arch.translate_register_name(offset = 0x28, size = 8)
    cfg = get_cfg_acc(b,start,end)
    func_cfg = get_func_cfg(cfg,start,normalize=False)
    _get_as = lambda n:(hex(n.addr) if n.addr is not None else str(n.addr),hex(n.size) if n.size is not None else str(n.size))
    n_set = set()
    p_set = set()
    s_set = set()
    for n in func_cfg.nodes():
        (addr,sz) = _get_as(n)
        print '---------%s,%s---------' % (addr,sz)
        n_set.add(addr + '-' + sz)
        preds_str = 'Preds: '
        for x in func_cfg.predecessors(n):
            (addr,sz) = _get_as(x)
            preds_str = preds_str + '[%s,%s] '%(addr,sz)
            p_set.add(addr + '-' + sz)
        succs_str = 'Succs: '
        for x in func_cfg.successors(n):
            (addr,sz) = _get_as(x)
            succs_str = succs_str + '[%s,%s] '%(addr,sz)
            s_set.add(addr + '-' + sz)
        print preds_str
        print succs_str
    print 'Only in n_set: ' + str(n_set.difference(p_set,s_set))
    print 'Only in p_set but not n_set: ' + str(p_set.difference(n_set))
    print 'Only in s_set but not n_set: ' + str(s_set.difference(n_set))

def print_vex(addrs):
    b = load_kernel_image(sys.argv[1],ARCH,BASE)
    print_vex_blocks(b,addrs)

def print_capstone(addrs):
    b = load_kernel_image(sys.argv[1],ARCH,BASE)
    for addr in addrs:
        caps = b.factory.block(addr).capstone
        #print type(caps.insns[0].insn)
        #print dir(caps.insns[0].insn)
        #print type(caps.insns[0].insn.mnemonic)
        print caps.insns[0].insn.mnemonic
        #print caps.insns[0].insn.insn_name
        print caps

def show_pickled_sig():
    with open(sys.argv[1],'rb') as f:
        sig = pickle.load(f)
        show_signature(sig)

def test_segments():
    segments = get_code_segments(sys.argv[1],BASE)
    print [(hex(x),hex(y),hex(z)) for (x,y,z) in segments]

if __name__ == '__main__':
    #print_cfg_graph(0xffffff8008dddbcc,0xffffff8008dddec8)
    #print_vex([0xFFFFFFC0003498A0])
    #print_capstone([0xffffff80088a1510])
    show_pickled_sig()
    #test_segments()
