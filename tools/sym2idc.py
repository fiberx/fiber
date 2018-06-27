#!/usr/bin/python
#Convert a System.map file (argv[1]) to idc (stdout).

import sys

def convert(f):
    with open(f) as syms:
        print '#include <idc.idc>'
        print ''
        print 'static main()'
        print '{'
        for sym in syms:
            sym = sym[:-1] if sym[-1] == '\n' else sym
            tokens = sym.split(' ')
            #addr type name
            print 'MakeName(0x%x, \"%s\");' % (int(tokens[0],16),tokens[2])
        print '}'

if __name__ == '__main__':
    convert(sys.argv[1])
