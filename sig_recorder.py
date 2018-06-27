#!/usr/bin/python
import angr,simuvex
import sys,os

#This class is for recording the formulas required in the signatures when doing the
#symbolic execution.
#TODO: avoid the possible conflicts of the breakpoints used here and in Sym_Tracer.
class Sig_Recorder(object):
    #sigs is a signature list that we want to fill in the symbolic execution process.
    def __init__(self,sigs,tracer,dbg_out=False):
        self.sigs = sigs
        self._cur_sig_node = []
        self.tracer = tracer
        self.dbg_out = dbg_out
        #A (addr_start,addr_end) --> (sig,node) mapping.
        self._sig_map = {}
        #A root_addr --> (sig,node) mapping.
        self._sig_roots = {}
        self._setup_dicts()

    #Set up reference data structures.
    def _setup_dicts(self):
        for sig in self.sigs:
            for node in sig.nodes():
                #NOTE: a same node may be included in multiple sigs... 
                self._sig_map.setdefault((node.addr,node.addr+node.size),[]).append((sig,node))
                for addr in sig.node[node]['root_ins']:
                    self._sig_roots.setdefault(addr,[]).append((sig,node))

    def record(self,states):
        if states is None:
            return
        for st in states:
            st.inspect.b('instruction', when=simuvex.BP_AFTER, action=self._sig_ins_brk_aft)
            st.inspect.b('exit', when=simuvex.BP_BEFORE, action=self._sig_exit_brk)
            st.inspect.b('mem_write',when=simuvex.BP_BEFORE,action=self._sig_mem_w_brk)
        self._cur_sig_node = []

    def stop_record(self,states):
        if states is None:
            return
        for st in states:
            st.inspect.remove_breakpoint('instruction',filter_func=lambda x: x.action==self._sig_ins_brk_aft)
            st.inspect.remove_breakpoint('exit',filter_func=lambda x: x.action==self._sig_exit_brk)
            st.inspect.remove_breakpoint('mem_write',filter_func=lambda x: x.action==self._sig_mem_w_brk)

    #Given an instruction address, this function should decide whether it belongs to any signature code area,
    #if so, set current sig and node. 
    def _sig_brk_get_node(self,ins_addr):
        if not self._sig_roots.has_key(ins_addr):
            return False
        else:
            self._cur_sig_node = self._sig_roots[ins_addr]
            return True

    def _pre_record(self,ins_addr):
        s = self._cur_sig_node[0][0]
        n = self._cur_sig_node[0][1]
        return s.node[n]['formulas'][ins_addr]

    def _post_record(self,ins_addr,formulas):
        #Propagate the formulas to same nodes in different sigs.
        for (s,n) in self._cur_sig_node[1:]:
            s.node[n]['formulas'][ins_addr] = formulas

    def _sig_ins_brk_aft(self,state):
        #print '[sig_ins] ' + hex(state.inspect.instruction if state.inspect.instruction is not None else 0)
        #print [hex(x) for x in state.history.ins_addrs]
        ins_addr = state.inspect.instruction
        if not self._sig_brk_get_node(ins_addr):
            return
        formulas = self._pre_record(ins_addr)
        if formulas['type'] <> 'load' and formulas['type'] <> 'other':
            #these types should be processed in other breakpoints.
            return
        #Record the formulas for pre-determined registers.
        for k in formulas:
            if k in ('type',):
                continue
            formulas[k].append(self.tracer.get_formula(state,getattr(state.regs,k))) 
        self._post_record(ins_addr,formulas)

    def _sig_mem_w_brk(self,state):
        ins_addr = state.history.recent_ins_addrs[-1]
        #print '~~~~[mem w] cur: %s addr: %s len: %s expr: %s' % (hex(ins_addr),str(state.inspect.mem_write_address),str(state.inspect.mem_write_length),str(state.inspect.mem_write_expr)) 
        if not self._sig_brk_get_node(ins_addr):
            return
        formulas = self._pre_record(ins_addr)
        if formulas['type'] <> 'store':
            return
        data = self.tracer.get_formula(state,state.inspect.mem_write_expr)
        addr = self.tracer.get_formula(state,state.inspect.mem_write_address)
        length = state.inspect.mem_write_length
        formulas['a-d-l'].append((addr,data,length))
        self._post_record(ins_addr,formulas)

    def _sig_exit_brk(self,state):
        #print [hex(x) for x in state.history.ins_addrs]
        ins_addr = state.history.recent_ins_addrs[-1]
        #print '~~~~[sig_exit] cur: %s target: %s guard: %s kind: %s' % (hex(ins_addr),str(state.inspect.exit_target),str(state.inspect.exit_guard),str(state.inspect.exit_jumpkind))
        if not self._sig_brk_get_node(ins_addr):
            return
        formulas = self._pre_record(ins_addr)
        if formulas['type'] <> 'exit':
            #Some basic blocks may end just with a normal data instruction.
            print 'This exit instruction is not of type -exit-: ' + hex(ins_addr) + ', ' + formulas['type']
            return
        addr = self.tracer.get_formula(state,state.inspect.exit_target)
        guard = self.tracer.get_formula(state,state.inspect.exit_guard)
        jk = state.inspect.exit_jumpkind
        '''
        #If it's a function call, parse the function name and record it.
        #TODO: Is it possible that we will have multiple different function names in this case?
        if jk == 'Ijk_Call' and self.tracer.symbol_table is not None and 'func_name' not in formulas:
            if not state,state.inspect.exit_target.symbolic:
                e = self.tracer.symbol_table.lookup(state.se.any_int(state.inspect.exit_target))
                if e is not None:
                    formulas['func_name'] = e[1]
        '''
        formulas['a-g-k'].append((addr,guard,jk))
        self._post_record(ins_addr,formulas)
