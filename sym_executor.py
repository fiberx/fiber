#!/usr/bin/python
import angr,simuvex
import sys,os
import time
from utils_sig import *
from sym_tracer import Sym_Tracer
from sig_recorder import Sig_Recorder

#This class is responsible for performing symbolic execution.
class Sym_Executor(object):
    def __init__(self,options=None,dbg_out=False):
        self.tracer = None
        self.recorder = None
        self.dbg_out = dbg_out
        self._whitelist = set()
        self._all_bbs = set()
        self._num_find = 10
        self.options = options

    def _get_initial_state(self,proj,start):
        if proj is None:
            return None
        st = proj.factory.blank_state(addr=start,symbolic_sp=True)
        # print st.arch.registers.keys()
        # We can customize the symbolic execution by setting various options in the state
        # for a full list of available options:
        # https://github.com/angr/simuvex/blob/master/simuvex/s_options.py
        # E.g. st.options.add(simuvex.o.LAZY_SOLVES) ('options' is a set) 
        # CALLLESS to do intra-procedure analysis
        st.options.add(simuvex.o.CALLLESS)
        # To prevent the engine from discarding log history
        st.options.add(simuvex.o.TRACK_ACTION_HISTORY)
        if self.options.get('simplify_ast',True):
            st.options.add(simuvex.o.SIMPLIFY_EXPRS)
            st.options.add(simuvex.o.SIMPLIFY_MEMORY_READS)
            st.options.add(simuvex.o.SIMPLIFY_MEMORY_WRITES)
            st.options.add(simuvex.o.SIMPLIFY_EXIT_GUARD)
        #TODO: Find a way to deal with function side-effect (i.e. a function call will output to a parameter, then the parameter will be used in a condition later)
        st.options.add(simuvex.o.IGNORE_EXIT_GUARDS)
        st.options.add(simuvex.o.IGNORE_MERGE_CONDITIONS)
        st.options.add(simuvex.o.DONT_MERGE_UNCONSTRAINED)
        #Use customized addr conc strategy
        st.memory.read_strategies = [angr.concretization_strategies.SimConcretizationStrategyHZ(limit=3)]
        st.memory.write_strategies = [angr.concretization_strategies.SimConcretizationStrategyHZ(limit=3)]
        #print st.options
        return st

    #Include all the BBs along the path from start to ends in the cfg into the whitelist.
    #The CFG here is CFGAcc.
    def _prep_whitelist(self,cfg,cfg_bounds,ends,start=None,proj=None,sym_tab=None):
        if cfg is None or cfg_bounds is None or len(cfg_bounds) < 2:
            print '_prep_whitelist(): Incomplete CFG information'
            return
        func_cfg = get_func_cfg(cfg,cfg_bounds[0],proj=proj,sym_tab=sym_tab)
        if func_cfg is None:
            print 'No func_cfg is available at %x' % cfg_bounds[0]
            return
        start = cfg_bounds[0] if start is None else start
        self._all_bbs = set([x.addr for x in func_cfg.nodes()])
        self._whitelist = get_node_addrs_between(func_cfg,start,ends,from_func_start=(start == cfg_bounds[0]))
        
        if self.dbg_out:
            l = list(self._whitelist)
            l.sort()
            print 'whitelist: ' + str([hex(x) for x in l])
        return

    #Why we put a absolutely 'False' find_func here:
    #(1)We rely on an accurate whitelist and all the nodes in the list should be explored, so we don't want
    #to stop at a certain node.
    #(2)With this find_func, basically we will have no states in the 'found' stash in the end, but that's OK
    #because all the things we want to do will be done along the symbolic execution process.
    def _find_func(self,p):
        return False

    def _avoid_func(self,p):
        #print 'avoid_func: ' + str(hex(p.addr)) + ' ' + str(p.addr in whitelist)
        #One problem is that, sometimes p.addr is in the middle of a certain BB, while in whitelist we only have start addresses of BBs.
        #Currently for these cases, we will let it continue to execute because it will align to the BB starts later.
        return False if p.addr not in self._all_bbs else (not p.addr in self._whitelist)

    #This is basically the 'hook_complete' used in 'explorer' technique, simply deciding whether num_find has been reached.
    def _vt_terminator(self,smg):
        return len(smg.stashes['found']) >= self._num_find

    def _prep_veritesting_options(self,find=None,avoid=None,num_find=10):
        if find is None:
            find = self._find_func
        if avoid is None:
            avoid = self._avoid_func
        #We need to construct an 'explorer' as an 'exploration_technique' used in the internal SimManager of Veritesting,
        #which is basically the same one as used in normal DSE SimManager (by invoking 'explore()' method)
        #NOTE that the Veritesting mode will use a separate SimManager, so we have to make TWO 'explorer'.
        exp_tech = angr.exploration_techniques.Explorer(find=find,avoid=avoid,num_find=num_find)
        veritesting_options = {}
        #NOTE: 'loop_unrolling_limit' is compared and considered as 'passed' with '>=' instead of '>', that means if we use '1', no loops will be even entered. 
        #However we want exactly ONE loop execution, so we should should use '2' here actually.
        veritesting_options['loop_unrolling_limit'] = 2
        veritesting_options['tech'] = exp_tech
        #NOTE that original 'explorer' technique will set a 'hook_complete' in SimManager, which will be passed from 'run()' to 'step()'
        #as a 'until_func', however, Veritesting will not invoke 'run()', instead, it calls 'step()' directly, so this hook is basically
        #invalidated. To deal with this, we provide a 'terminator' to Veritesting, which will terminate Veritesting when len(stashes[found]) > num_find
        veritesting_options['terminator'] = self._vt_terminator
        return veritesting_options

    #Do the symbolic execution on the given CFG, from start to target, with Veritesting and Whitelist mechanisms.
    #Params:
    #proj: the angr project.
    #states: if it's None, creates a default initial state@start, if start is None, then @cfg_bounds[0].
    #cfg: cfg_accurate.
    #cfg_bounds: a 2-element list, specifying the area of the target function (to be executed) in the cfg.
    #start: Where to start the symbolic execution? Must be within the cfg_bounds.
    #targets: Where to end the symbolic execution? Must be within the cfg_bounds. Can specify multiple targets in a list.
    #Ret:
    #The resulting SimManager. 
    def try_sym_exec(self,proj,cfg,cfg_bounds,targets,states=None,start=None,new_tracer=False,tracer=None,new_recorder=False,recorder=None,sym_tab=None,sigs=None,num_find=10):
        if cfg is None or cfg_bounds is None or len(cfg_bounds) < 2:
            print 'No CFG information available for sym exec.'
            return None
        #This is the start point of sym exec.
        st = start if start is not None else cfg_bounds[0]
        #Fill initial state.
        if states is None:
            init_state = self._get_initial_state(proj,st)
            states = [init_state]
        
        #Whether we need to create a new Sym_Tracer to trace the symbolic execution
        if new_tracer:
            self.tracer = Sym_Tracer(symbol_table=sym_tab,dbg_out=self.dbg_out)
            #Clear any remaining breakpoints
            self.tracer.stop_trace(states)
            self.tracer.trace(states)
        else:
            self.tracer = tracer

        #Whether we need to create a new Sig_Recorder
        if new_recorder:
            if sigs is None:
                print 'You must provide sigs if you want to use new recorder'
                return
            if self.tracer is None:
                print 'You must provide tracer or specify new_tracer flag if you want to use new recorder'
                return
            self.recorder = Sig_Recorder(sigs,self.tracer,dbg_out=dbg_out)
            #Clear any remaining breakpoints
            self.recorder.stop_record(states)
            #Record structural information (nodes and their relationships) and semantic information of 'root'
            #instructions with per-instruction breakpoint, the structural information has already been partly recorded in the initial signature.
            self.recorder.record(states)
        else:
            self.recorder = recorder
        
        #Set the whitelist of basic blocks, we only want to include the BBs that along the paths from st to targets.
        self._prep_whitelist(cfg,cfg_bounds,targets,st,proj=proj,sym_tab=sym_tab)
    
        self._num_find = num_find
        #Set the VeriTesting options
        veritesting_options = self._prep_veritesting_options(num_find=self._num_find)

        #Construct the simulation execution manager
        smg = proj.factory.simgr(thing=states, veritesting=True, veritesting_options=veritesting_options)

        #TODO: Do we still need to use loop limiter for the main DSE SimManager since Veritesting has already got a built-in loop limiter?
        #limiter = angr.exploration_techniques.looplimiter.LoopLimiter(count=0, discard_stash='spinning') 
        #smg.use_technique(limiter)

        t0 = time.time()
        smg.explore(find=self._find_func, avoid=self._avoid_func, num_find=self._num_find)

        print ['%s:%d ' % (name,len(stash)) for name, stash in smg.stashes.items()]
        print 'Time elapsed: ' + str(time.time() - t0)

        return smg
