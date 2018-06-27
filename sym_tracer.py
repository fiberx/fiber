#!/usr/bin/python
import angr,simuvex,claripy
import sys,os
import copy,re
from utils_sig import *

#This class can record information along symbolic execution and generate origination formula for any symbolic variable at any location. 
class Sym_Tracer(object):
    def __init__(self,symbol_table=None,dbg_out=False,collision_retry_time=16):
        #This is the mapping from symbolic value name to the extra information collected.
        #'mem_' --> ast
        #'fake_ret_' --> (call_addr_ast, insn_addr)
        #NOTE: I believe the symbolic value name assigned by angr is unique across the whole execution process and all the paths,
        #That's why we can use this name as the key.
        #TODO: Confirm this is true.
        self._sym_map = {}
        #This is the data structure for recording the expr behind each mem addr concretization, captured by the breakpoint.
        #Note that the history is for deciding to which path this concretization belongs. 
        # [(addr,expr,his),...]
        self._addr_conc_buf=[]
        self.symbol_table = symbol_table
        self.dbg_out = dbg_out
        self.addr_collision = False

    def _sym_capture(self,state):
        if self.dbg_out:
            print '[Sym Create] ' + make_reg_readable(state.arch,str(state.inspect.symbolic_expr)) + ' @ ' + hex(state.history.recent_ins_addrs[-1])
        name = state.inspect.symbolic_name
        #This *should* be impossible, but if it happens, I made some serious mistakes. 
        if self._sym_map.has_key(name):
            print 'sym_capture: multiple entries for the same value: ' + name
            return
        if re.match(re_reg,name) is not None:
            return
        elif re.match(re_mem,name) is not None:
            addr = int(name.split('_')[1],base=16)
            #Look up the addr_conc_buf to match the address
            index = -1
            for i in range(len(self._addr_conc_buf))[::-1]:
                (a,e,h) = self._addr_conc_buf[i]
                #TODO: In the presence of state combination, the 'old_days()' may be unreliable.
                if a <> addr or e is None:
                #if a <> addr or e is None or not old_days(state,h):
                    continue
                else:
                    index = i
                    break
            if index <> -1:
                (a,e,h) = self._addr_conc_buf.pop(index)
                expr = copy.deepcopy(e)
                self._sym_map[name] = expr
        elif re.match(re_ret,name) is not None:
            #We need to record some information about the call
            action = None
            for ao in state.history.recent_actions:
                if type(ao).__name__ == 'SimActionExit':
                    action = ao
            if action is not None:
                #action.target is a SimActionObject
                target_ast = copy.deepcopy(action.target.ast)
                #TODO: I'm not sure how useful 'insn_addr' is currently, so leave it blank for now.
                #If we want it in the future, keep in mind that call instruction will be the last one of an IRSB.
                self._sym_map[name] = (target_ast,None)
            else:
                print 'Cannot find call target for the symbol: ' + name
        else:
            print '[Unusual Symbol] ' + state.inspect.symbolic_name + ': ' + str(state.inspect.symbolic_expr) + ' ' + str(state.inspect.symbolic_size)

    def _addr_conc_capture(self,state):
        mem_addr = state.inspect.address_concretization_result
        expr = state.inspect.address_concretization_expr
        strategy = state.inspect.address_concretization_strategy
        '''
        print state.inspect.address_concretization_strategy
        print state.inspect.address_concretization_action
        print state.inspect.address_concretization_memory
        print state.inspect.address_concretization_expr
        print state.inspect.address_concretization_add_constraints
        print state.inspect.address_concretization_result
        '''
        if mem_addr is None or expr is None:
            return
        if self.dbg_out:
            print '[Addr Conc] ' + str(expr) + ' --> ' + str([hex(x) for x in mem_addr]) + ' @ ' + hex(state.history.recent_ins_addrs[-1]) + ' -- ' + type(strategy).__name__
        #We take the addr sequence of hitted basic blocks so far as a signature for the history. 
        his = tuple([x for x in state.history.bbl_addrs])
        for addr in mem_addr:
            self._addr_conc_buf = self._addr_conc_buf + [(addr,expr,his)]
        if hasattr(strategy,'collision'):
            self.addr_collision = strategy.collision
    
    def trace(self,states):
        self._sym_map = {}
        self._addr_conc_buf=[]
        for st in states:
            st.inspect.b('symbolic_variable', when=simuvex.BP_AFTER, action=self._sym_capture)
            st.inspect.b('address_concretization', when=simuvex.BP_AFTER, action=self._addr_conc_capture)
        self.addr_collision = False
        self._cur_addr_buck = 0x8000
    
    def stop_trace(self,states):
        if states is None:
            return
        for st in states:
            st.inspect.remove_breakpoint('symbolic_variable',filter_func=lambda x: x.action==self._sym_capture)
            st.inspect.remove_breakpoint('address_concretization',filter_func=lambda x: x.action==self._addr_conc_capture)

    MEM_TYPE = 'mem'
    REG_TYPE = 'reg'
    RET_TYPE = 'ret'
    UNK_TYPE = 'unk'

    def _rename_ast(self,ast,new_name):
        args = list(ast.args)
        args[0] = new_name
        ast.args = tuple(args)

    def _is_ast_processed(self,ast):
        if not ast.hz_extra.has_key('processed'):
            return False
        return ast.hz_extra['processed']

    #For a symbolic value with a 'reg' prefixed name, this reg name represents the very initial source/origination of itself.
    #So no further tracking about this reg is needed, here we just simply replace the reg name in the ast to a human-readable format.
    def _process_sym_reg(self,state,ast):
        ast.hz_extra['name'] = make_reg_readable(state.arch,ast.args[0])
        ast.hz_extra['processed'] = True
        ast.hz_extra['type'] = self.REG_TYPE

    #Now we have a symbolic value read from a memory location. We need to extract the expression behind the mem addr.
    #Such information has been collected from action history and mem addr conc breakpoints previously.
    def _process_sym_mem(self,state,ast):
        ast.hz_extra['type'] = self.MEM_TYPE
        if not self._sym_map.has_key(ast.args[0]):
            return
        expr = self._sym_map[ast.args[0]]
        #We may still need to trace the addr expr ast back.
        if not self._is_ast_processed(expr):
            self.get_formula(state,expr,in_place=True)
            expr.hz_extra['processed'] = True
        ast.hz_extra['mem_formula'] = expr
        expr_str = expr.hz_repr() if isinstance(expr,claripy.ast.Base) else str(expr)
        #We assume the name is: mem_[addr]_N_[size]
        mem_size_str = ast.args[0].split('_')[3]
        ast.hz_extra['name'] = '[' + expr_str[expr_str.find(' ')+1:-1] + ']#' + mem_size_str
        ast.hz_extra['processed'] = True

    #For a symbolic value representing the return value from a function call, we record the function addr/name (if symbol table is available)
    def _process_sym_ret(self,state,ast):
        ast.hz_extra['type'] = self.RET_TYPE
        #Retrieve the recorded information about this 'fake_ret' value
        if not self._sym_map.has_key(ast.args[0]):
            print 'We find a fake_ret_ value without any information: ' + str(ast)
            #TODO: Do we need to mark this AST as 'processed'?
            return
        (call_ast,insn_addr) = self._sym_map[ast.args[0]]
        name = None
        if not call_ast.symbolic:
            #The call addr is concrete, try to parse out the function name.
            addr = state.se.any_int(call_ast)
            if self.symbol_table is not None:
                entry = self.symbol_table.lookup(addr)
                if entry is None:
                    print 'Cannot parse function name for ' + hex(addr)
                else:
                    #(ty,name,size)
                    name = entry[1]
        else:
            #The call addr is symbolic, we need to parse it.
            if not self._is_ast_processed(call_ast):
                self.get_formula(state,call_ast,in_place=True)
        ast.hz_extra['processed'] = True
        ast.hz_extra['func_addr'] = call_ast
        ast.hz_extra['func_name'] = name
        #TODO: For the call instruction addr, currently we leave it blank.
        ast.hz_extra['calling_addr'] = None
        #Do some rename to increase readability.
        size_str = ast.args[0].split('_')[4]
        if name is None:
            new_name = call_ast.hz_repr() if isinstance(call_ast,claripy.ast.Base) else str(call_ast)
            new_name = 'ret{' + new_name[new_name.find(' ')+1:-1] + '}#' + size_str
        else:
            new_name = 'ret{' + name + '}#' + size_str
        ast.hz_extra['name'] = new_name

    #We don't know the symbol type.
    def _process_sym_unk(self,state,ast):
        print 'Unrecognized symbolic value name: %s' % str(ast)
        ast.hz_extra['type'] = self.UNK_TYPE
        ast.hz_extra['processed'] = True

    #Given a state and an ast, we want to know the originations of the mem addr and regs in it.
    #Return a new AST with mem addr/regs replaced by their originations.
    def get_formula(self,state,ast,in_place=True):
        if state is None or ast is None:
            return None
        #if self.dbg_out:
        #    print 'I: ' + str(ast)
        ast_c = copy.deepcopy(ast) if not in_place else ast
        # It seems we only need to tell the originations of the symbolic nodes in the AST. 
        for leaf_ast in ast_c.recursive_leaf_asts:
            if not isinstance(leaf_ast,claripy.ast.Base):
                print 'Found a non-Base leaf AST:' + str(type(leaf_ast))
                continue
            if not leaf_ast.symbolic:
                continue
            #For symbolic AST, args[0] should be its name. Symbolic value from a register will have the prefix 'reg' in its name,
            #symbolic value from memory will have a prefix 'mem'. We aim to obtain the expression behind the memory address,
            #e.g. X19+0x24 = 0xXXXXXXXX, we want to know the left side, however the sym name will only contain the right side.
            if not isinstance(leaf_ast.args[0],str):
                print 'Things go out of expectation, arg 0 of the symbolic AST is not a string: %s' % str(leaf_ast)
                continue
            if self._is_ast_processed(leaf_ast):
                continue
            #There are several kinds of symbolic values, currently I know 'reg' and 'mem'.
            #TODO:Deal with more symbolic value categories.
            if re.match(re_reg,leaf_ast.args[0]) is not None:
                self._process_sym_reg(state,leaf_ast)
            elif re.match(re_mem,leaf_ast.args[0]) is not None:
                self._process_sym_mem(state,leaf_ast)
            elif re.match(re_ret,leaf_ast.args[0]) is not None:
                self._process_sym_ret(state,leaf_ast)
            else:
                self._process_sym_unk(state,leaf_ast)
        ast_c.hz_extra['processed'] = True
        #if self.dbg_out:
        #    print 'O: ' + str(ast_c)
        #Below code is for deepcopy debugging, for some reasons, the deepcopy doesn't work very well here
        #because I find that the copy still shares some leaf asts with original ast. So we'd better not
        #modify any fields in the original AST instance other than 'hz_extra' which is added by us.
        '''
        if not in_place:
            print '^^^^^^^^^^^^^^^^^^^^^^^^^'
            #print ast.dbg_repr('+')
            for leaf in ast.recursive_leaf_asts:
                if leaf.symbolic:
                    print hex(id(leaf)) + ' || ' + str(leaf)
            print '------------------------'
            #print ast_c.dbg_repr('+')
            for leaf in ast_c.recursive_leaf_asts:
                if leaf.symbolic:
                    print hex(id(leaf)) + ' || ' + str(leaf)
            print 'vvvvvvvvvvvvvvvvvvvvvvvvv'
        '''
        return ast_c
