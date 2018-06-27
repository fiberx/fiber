#!/usr/bin/python
import sys,os

#This wraps the kernel symbol table.
class Sym_Table(object):
    def __init__(self,f,dbg_out=True):
        #sym_table: addr --> (type,name,size)
        self._sym_table = {}
        #r_sym_table: name --> list of (type,addr,size)
        self._r_sym_table = {}
        self.raw_syms = []
        #Fill the tables
        self._load_symbol_table(f)
        self.dbg_out = dbg_out

    #Load symbol table(s) from a file.
    def _load_symbol_table(self,f):
        with open(f,'r') as symf:
            for line in symf:
                line = line[:-1] if line[-1] == '\n' else line
                #Assume the format is "addr type name" 
                tokens = line.split(' ')
                (addr,ty,name) = (int(tokens[0],16),tokens[1],self._trim_func_name(tokens[2]))
                break
            self.raw_syms += [(addr,ty,name)]
            for line in symf:
                line = line[:-1] if line[-1] == '\n' else line
                tokens = line.split(' ')
                (n_addr,n_ty,n_name) = (int(tokens[0],16),tokens[1],self._trim_func_name(tokens[2]))
                size = n_addr - addr
                self._sym_table[addr] = (ty,name,size)
                self._r_sym_table.setdefault(name,[]).append((ty,addr,size))
                (addr,ty,name) = (n_addr,n_ty,n_name)
                self.raw_syms += [(addr,ty,name)]
            #Actually we still have one entry remained here, but I think we can ignore this in the case of linux kernel symbol table.
            #Since this is usually in '.bss' section

    #Sometimes we can see compiler added suffix in the function names, such as 'func.isra.XX', trim them.
    def _trim_func_name(self,name):
        suffix_list = ['isra','constprop']
        tokens = name.split('.')
        if len(tokens) > 1 and tokens[1] in suffix_list:
            return tokens[0]
        return name

    #The 'k' can be either symbol name or addr, return the information tuple.
    def lookup(self,k):
        if isinstance(k,int) or isinstance(k,long):
            return self._sym_table[k] if k in self._sym_table else None
        elif isinstance(k,str):
            return self._r_sym_table[k] if k in self._r_sym_table else None
        return None
    
    #This is specifically designed to pick one tuple for a function name.
    def lookup_func_name(self,n):
        func_list = self.lookup(n)
        (addr,size) = (0,0)
        if not func_list:
            if self.dbg_out:
                print 'Cannot find function name in symbol table: ' + n
            return None
        else:
            #print func_list
            #Pick the first entry which has type 'T/t/'
            for (ty,addr,size) in func_list:
                if ty in ('T','t'):
                    break
            if (addr,size) == (0,0):
                if self.dbg_out:
                    print 'No symbol entry picked.'
                return None
            else:
                if self.dbg_out:
                    print '[Func] %s: %x - %x' % (n,addr,addr + size)
                return (ty,addr,size)

    def probe_arm64_kernel_base(self):
        for (addr,ty,name) in self.raw_syms:
            if addr >= 0xffffff0000000000 and ty in ('T','t'):
                break
        return addr

    #Decide the code ('t'/'T') segments according to the symbol table file.
    #The base is the memory load base address of the image.
    def get_code_segments(self,base):
        prev_st = None
        segments = []
        for (addr,ty,name) in self.raw_syms:
            if addr < base:
                continue
            if ty in ('t','T'):
                if prev_st is None:
                    prev_st = addr
            else:
                if prev_st is not None:
                    segments.append((prev_st,addr))
                    prev_st = None
        if prev_st is not None:
            #This should be in general impossible, but what if the symbol table has a tailing 't' section?
            segments.append((prev_st,addr))
        #(file_offset,mem_addr,size)
        return map(lambda (st,ed):(st-base,st-base,ed-st),segments)
