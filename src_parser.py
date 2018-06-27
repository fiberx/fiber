#!/usr/bin/python

import sys
import re
from pygments.lexers import get_lexer_by_name
from pygments.token import Token
#from pycparser import c_parser

dbg_out = False

#The array's base index is 0, but base line number used by addr2line is 1, so we need adjustments when necessary.
LINE_BASE = 1

#It seems that the line number is based on 1 instead of 0 for DWARF, so we need to +1 for each line number.
def adj_lno_tuple(t):
    return tuple(map(lambda x:x+LINE_BASE,t))

def _adj_lno_patch(inf):
    for k in inf:
        if 'add' in inf[k]:
            for t in list(inf[k]['add']):
                inf[k]['add'][(t[0]+LINE_BASE,t[1]+LINE_BASE)] = inf[k]['add'][t]
                inf[k]['add'].pop(t)
        if 'del' in inf[k]:
            for t in list(inf[k]['del']):
                inf[k]['del'][(t[0]+LINE_BASE,t[1]+LINE_BASE)] = inf[k]['del'][t]
                inf[k]['del'].pop(t)

def _trim_lines(buf):
    for i in range(len(buf)):
        if buf[i][-1] == '\n':
            buf[i] = buf[i][:-1]

def parse_patch(patch,kernel):
    inf = {}
    with open(patch,'r') as p:
        p_buf = p.readlines()
    _trim_lines(p_buf)
    diff_index = [i for i in range(len(p_buf)) if p_buf[i].startswith('diff')] + [len(p_buf)]
    for i in range(len(diff_index)-1):
        inf.update(_parse_patch_diff(p_buf,diff_index[i],diff_index[i+1],kernel))
    #_adj_line_number(inf)
    return inf

src_map = {}
def _parse_patch_diff(p_buf,st,ed,kernel):
    #Get the file name at first
    fp = None
    fn = None
    for i in range(st,ed):
        if fp is not None and fn is not None:
            break
        if p_buf[i].startswith('---'):
            fn = p_buf[i][6:]
        elif p_buf[i].startswith('+++'):
            fp = p_buf[i][6:]
    inf = {}
    if fp is None or fn is None:
        print 'No file name found for diff section: ' + p_buf[st]
        return inf
    if fp <> fn:
        print 'This diff involves file creation/deletion/rename: ' + p_buf[st]
        return inf
    #Got the file name now, split the '@@' sections.
    at_index = [i for i in range(st,ed) if p_buf[i].startswith('@@')] + [ed]
    s_buf = None
    try:
        with open(kernel+'/'+fp,'r') as f:
            s_buf = f.readlines()
            build_func_map(s_buf)
    except:
        return inf
    if not s_buf:
        print 'The file does not exist in target kernel: ' + fp
        return inf
    global src_map
    src_map[fp] = s_buf
    for i in range(len(at_index)-1):
        at_inf = _parse_patch_at(p_buf,at_index[i],at_index[i+1],s_buf)
        for (func,func_loc,p_inf) in at_inf:
            #Let's do a hacking here: ignore all 'bfr' type @@ sections.
            #TODO: Better solutions later.
            if p_inf and p_inf['type'] <> 'aft':
                continue
            if func and p_inf:
                #NOTE: multiple @@ sections can be about the same function.
                k = (fp,func,func_loc)
                if k in inf:
                    if 'add' in p_inf:
                        inf[k].setdefault('add',{}).update(p_inf['add'])
                    if 'del' in p_inf:
                        inf[k].setdefault('del',{}).update(p_inf['del'])
                else:
                    inf[k] = p_inf
    for k in inf:
        inf[k]['func_range'] = cur_func_inf_r[k[1:3]][0]
        inf[k]['arg_cnt'] = cur_func_inf_r[k[1:3]][1]
    return inf

def _parse_patch_at(p_buf,st,ed,s_buf):
    #Skip the @@ line.
    for i in range(st,ed):
        if p_buf[i].startswith('@@'):
            head = p_buf[i].split('@@')[-1][1:]
            break
    else:
        return (None,None)
    p_st = i + 1
    #First get the interleaving change-sites and context lines.
    c_index = []
    i = p_st
    while i < ed:
        if p_buf[i][0] in ('+','-'):
            j = i + 1
            while j < len(p_buf) and p_buf[j][0] in ('+','-'):
                j += 1
            c_index.append((i,j-1))
            i = j
        else:
            i += 1
    c_index = [(p_st-1,p_st-1)] + c_index + [(ed,ed)]
    inf = []
    prev_line = 0
    for i in range(1,len(c_index)-1):
        t1 = c_index[i][0]
        t2 = c_index[i][1]
        t0 = c_index[i-1][1] + 1
        t3 = c_index[i+1][0] - 1
        #Get the line number of the change-sites in kernel source.
        (c_inf,prev_line) = _locate_change_site(head,p_buf[t1:t2+1],p_buf[t0:t1],p_buf[t2+1:t3+1],s_buf,st_line=prev_line) 
        if c_inf is None:
            if dbg_out:
                print '>>>>No matches found for this @@'
            continue
        if dbg_out:
            print c_inf
        lno = None
        if c_inf['type'] == 'aft':
            lno = c_inf['add'].keys()[0][0] if 'add' in c_inf else c_inf['del'].keys()[0][0] - 1
        else:
            lno = c_inf['del'].keys()[0][0] if 'del' in c_inf else c_inf['add'].keys()[0][0] - 1
        func_name = get_func_name(lno)
        if not func_name:
            if dbg_out:
                print 'Line %d does not belong to any function.' % (lno + LINE_BASE)
        else:
            #(name,head_line)
            inf.append((func_name[0],func_name[1],c_inf))
    return inf

#clines: changed lines
#blines: context lines before
#alines: context lines after
def _locate_change_site(head,clines,blines,alines,s_buf,st_line=0):
    if dbg_out:
        print '----------------@@--------------------'
        print head
        for l in blines:
            print l
        for l in clines:
            print l
        for l in alines:
            print l
        print '----------------@@--------------------'
    #locate head
    if head.strip():
        for i in range(len(s_buf)):
            if head.strip() == s_buf[i].strip():
                break
        else:
            #No head found
            return (None,st_line)
        if i < st_line:
            i = st_line
    else:
        i = st_line
    #Search for context.
    def _cmp(lines,i):
        if not lines:
            return True
        for j in range(len(lines)):
            if i + j > len(s_buf) - 1:
                #We have reached the end of the source file.
                return False
            re_space = '[\t ]*'
            if re.sub(re_space,' ',lines[j]).strip() <> re.sub(re_space,' ',s_buf[i+j]).strip():
                return False
        return True
    plines = filter(lambda x:x.startswith('+'),clines)
    plines = map(lambda x:x[1:],plines)
    nlines = filter(lambda x:x.startswith('-'),clines)
    nlines = map(lambda x:x[1:],nlines)
    inf = {}
    while i < len(s_buf):
        j = i
        if _cmp(blines,i):
            i += len(blines)
            ty = None
            if plines and nlines:
                if _cmp(plines,i):
                    ty = 'aft'
                    i += len(plines) 
                elif _cmp(nlines,i):
                    ty = 'bfr'
                    i += len(nlines)
                else:
                    i = j + 1
                    continue
                if _cmp(alines,i):
                    #Call it a day.
                    if ty == 'aft':
                        inf['add'] = {(i-len(plines),i-1):plines}
                        inf['del'] = {(j+len(blines),j+len(blines)+len(nlines)-1):nlines}
                    else:
                        inf['del'] = {(i-len(nlines),i-1):nlines}
                        inf['add'] = {(j+len(blines),j+len(blines)+len(plines)-1):plines}
                    inf['type'] = ty
                    return (inf,i)
                else:
                    i = j + 1
                    continue
            elif plines:
                #Pure addition
                if _cmp(plines,i):
                    ty = 'aft'
                    i += len(plines)
                else:
                    ty = 'bfr'
                if _cmp(alines,i):
                    #Got it.
                    if ty == 'aft':
                        inf['add'] = {(i-len(plines),i-1):plines}
                    else:
                        inf['add'] = {(j+len(blines),j+len(blines)+len(plines)-1):plines}
                    inf['type'] = ty
                    return (inf,i)
                else:
                    i = j + 1
                    continue
            elif nlines:
                #Pure deletion
                if _cmp(nlines,i):
                    ty = 'bfr'
                    i += len(nlines)
                else:
                    ty = 'aft'
                if _cmp(alines,i):
                    if ty == 'aft':
                        inf['del'] = {(j+len(blines),j+len(blines)+len(nlines)-1):nlines}
                    else:
                        inf['del'] = {(i-len(nlines),i-1):nlines}
                    inf['type'] = ty
                    return (inf,i)
                else:
                    i = j + 1
                    continue
        else:
            i += 1
    return (None,st_line)

def print_patch_inf(inf):
    for k in inf:
        print '-----------------------------------------'
        print k[1]
        print k[0] + ' ' + str(inf[k]['func_range'])
        print 'Type: ' + inf[k]['type']
        if 'add' in inf[k]:
            print '++++line++++'
            for (st,ed) in inf[k]['add']:
                print '%d - %d' % adj_lno_tuple((st,ed))
        if 'del' in inf[k]:
            print '----line----'
            for (st,ed) in inf[k]['del']:
                print '%d - %d' % adj_lno_tuple((st,ed))

def get_func_name(lno):
    for k in cur_func_inf:
        if lno >= k[0] and lno <= k[1]:
            return (cur_func_inf[k][0],k[0])
    return None

cur_func_inf = {}
cur_func_inf_r = {}
#This function parse a C source file, extract all the function definitions in it.
def build_func_map(s_buf):
    global cur_func_inf
    global cur_func_inf_r
    cur_func_inf.clear()
    cur_func_inf_r.clear()
    cnt = 0
    prev_pos = (0,0)
    in_str = False
    in_comment = 0
    #TODO: Maybe we should utilize lexer to avoid all the mess below.
    for i in range(len(s_buf)):
        for j in range(len(s_buf[i])):
            if s_buf[i][j] == '{':
                if in_str or in_comment > 0:
                    continue
                if cnt == 0:
                    prev_pos = (i,j)
                cnt += 1
            elif s_buf[i][j] == '}':
                if in_str or in_comment > 0:
                    continue
                cnt -= 1
                if cnt == 0:
                    #We have found a out-most {} pair, it *may* be a function. 
                    func_head = _detect_func_head(s_buf,prev_pos)
                    if func_head:
                        (func,arg_cnt) = func_head
                        cur_func_inf[(prev_pos[0],i)] = func_head
                        #NOTE: Sometimes one file can have multiple functions with same name, due to #if...#else.
                        #So to mark a function we need both name and its location.
                        cur_func_inf_r[(func,prev_pos[0])] = ((prev_pos[0],i),arg_cnt)
                elif cnt < 0:
                    print '!!! Syntax error: ' + s_buf[i]
                    print 'prev_pos: %d:%d' % adj_lno_tuple(prev_pos)
                    print '------------Context Dump--------------'
                    l1 = max(i-5,0)
                    l2 = min(i+5,len(s_buf)-1)
                    print ''.join([s_buf[i] for i in range(l1,l2+1)])
                    return
            elif s_buf[i][j] == '"' and in_comment == 0:
                in_str = not in_str
            elif s_buf[i][j] == '/' and j + 1 < len(s_buf[i]) and s_buf[i][j+1] == '/' and not in_str:
                #Line comment, skip this line
                break
            elif s_buf[i][j] == '/' and j + 1 < len(s_buf[i]) and s_buf[i][j+1] == '*' and not in_str:
                #Block comment start
                in_comment += 1
            elif s_buf[i][j] == '*' and j + 1 < len(s_buf[i]) and s_buf[i][j+1] == '/' and not in_str:
                #Block comment end
                in_comment -= 1

#pos is the position of leading '{' of a potential function.
def _detect_func_head(s_buf,pos):
    def _back(pos):
        i = pos[0]
        j = pos[1]
        return (i,j-1) if j > 0 else (i-1,len(s_buf[i-1])-1) if i > 0 else None
    #First ensure that there is nothing between the '{' and a ')'
    p = pos
    while True:
        p = _back(p)
        if not p:
            break
        if s_buf[p[0]][p[1]] in ('\n',' ','\t'):
            continue
        elif s_buf[p[0]][p[1]] == ')':
            cnt = 1
            comma_cnt = 0
            any_arg = False
            while True:
                p = _back(p)
                if not p:
                    break
                if s_buf[p[0]][p[1]] == ')':
                    cnt += 1
                elif s_buf[p[0]][p[1]] == '(':
                    cnt -= 1
                elif s_buf[p[0]][p[1]] == ',':
                    comma_cnt += 1
                elif not s_buf[p[0]][p[1]] in ('\n',' ','\t'):
                    any_arg = True
                if cnt == 0:
                    break
            arg_cnt = comma_cnt + 1 if comma_cnt > 0 else 1 if any_arg else 0
            if cnt == 0:
                #It should be a function, extract the func name.
                #First skip the tailing spaces
                while True:
                    p = _back(p)
                    if not p:
                        break
                    if not s_buf[p[0]][p[1]] in ('\n',' ','\t'):
                        break
                if not p:
                    return None
                #Record the function name
                func = [s_buf[p[0]][p[1]]]
                while True:
                    p = _back(p)
                    if not p:
                        break
                    if s_buf[p[0]][p[1]] in ('\n',' ','\t','*'):
                        break
                    func.append(s_buf[p[0]][p[1]])
                func.reverse()
                return (''.join(func),arg_cnt)
            else:
                return None
        else:
            return None
    return None

def parse_funcs_in_patch(p_inf):
    func_inf = {}
    for k in p_inf:
        if k in func_inf:
            continue
        (st,ed) = p_inf[k]['func_range']
        src = src_map[k[0]][st:ed+1]
        l_ind = build_line_index(src)
        text = ''.join(src)
        tokens = lex(text,lan='C',process=False)
        t_inf = parse_raw_tokens(tokens,l_ind,st)
        func_inf[k] = t_inf
    if dbg_out:
        print '----------Func Inf-----------'
        for k in func_inf:
            print '>>>> ' + str(k) + ' <<<<'
            for t in func_inf[k]:
                print t
                print func_inf[k][t]
    return func_inf

#Record the offset range of syntax structure of interest (e.g. if,for,function call...)
def parse_raw_tokens(tks,index,base_lno):
    i = 0
    tks = strip_tokens(tks)
    inf = {}
    def _nothing(ind,di):
        i = ind
        if di == 'u':
            while i > 0:
                i -= 1
                if tks[i][2][-1] == '\n':
                    return True
                if tks[i][2].strip():
                    return False
        else:
            if tks[i][2][-1] == '\n':
                return True
            while i < len(tks) - 1:
                i += 1
                if tks[i][2].strip():
                    return False
                if tks[i][2][-1] == '\n':
                    return True
        return True
    while i < len(tks) - 1:
        if tks[i][2] in ('if','for','while'):
            if tks[i+1][2] <> '(':
                #Should be impossible
                print '!!! No ( after keyword'
                print_surround_tokens(tks,i)
                continue
            st = tks[i][0]
            ed_i = find_close(tks,i+1)
            if ed_i is None:
                print '!!! No close found'
                print_surround_tokens(tks,i)
                i += 1
                continue
            #Generate the stripped cond string.
            cond_str_strip = ''.join([tks[x][2] for x in range(i+2,ed_i)])
            #Find the block range covered by this cond statement.
            if tks[ed_i+1][2] == '{':
                ed_block_i = find_close(tks,ed_i+1)
            else:
                #The cond statement doesn't use '{}' to contain its block, so it must only have one statement in the block.
                ed_block_i = ed_i + 1
                while ed_block_i < len(tks) and tks[ed_block_i][2] <> ';':
                    ed_block_i += 1
            if ed_block_i + 1 < len(tks):
                ed_block_i += 1
            ed_block = lookup_line_no(tks[ed_block_i][0],index) + base_lno
            ed = tks[ed_i][0]
            st = lookup_line_no(st,index) + base_lno
            ed = lookup_line_no(ed,index) + base_lno
            inf.setdefault(tks[i][2],[]).append((st,ed,cond_str_strip,ed_block))
            #i = ed_i + 1
            i += 1
        elif tks[i][1] in Token.Name and tks[i+1][2] == '(':
            #Should be a function call
            st = tks[i][0]
            ed_i = find_close(tks,i+1)
            if ed_i is None:
                print '!!! No close found'
                print_surround_tokens(tks,i)
                i += 1
                continue
            args = _parse_func_args(tks[i+2:ed_i])
            ed = tks[ed_i][0]
            st = lookup_line_no(st,index) + base_lno
            ed = lookup_line_no(ed,index) + base_lno
            inf.setdefault('func',[]).append((st,ed,tks[i][2],args))
            i = ed_i + 1
        elif tks[i][2] == 'return':
            #Parse a return statement.
            st = tks[i][0]
            j = i
            while j < len(tks) and tks[j][2] <> ';':
                j += 1
            if j >= len(tks):
                print '!!! No ; found for return'
                print_surround_tokens(tks,i)
            ed = tks[j][0]
            st = lookup_line_no(st,index) + base_lno
            ed = lookup_line_no(ed,index) + base_lno
            inf.setdefault('ret',[]).append((st,ed))
            i += 1
        elif tks[i][2] == 'else':
            st = lookup_line_no(tks[i][0],index) + base_lno
            ed = st
            inf.setdefault('else',[]).append((st,ed))
            i += 1
        elif tks[i][2] == 'goto':
            #TODO: We may need to parse the target of the 'goto'.
            st = lookup_line_no(tks[i][0],index) + base_lno
            ed = st
            inf.setdefault('goto',[]).append((st,ed))
            i += 1
        elif tks[i][2] in ('static','unsigned','int','long','u8','u16','u32','u64','struct') and _nothing(i,'u'):
            #A declaration line.
            st = lookup_line_no(tks[i][0],index) + base_lno
            ed = st
            inf.setdefault('decl',[]).append((st,ed))
            i += 1
        elif tks[i][1] in Token.Comment:
            st = lookup_line_no(tks[i][0],index) + base_lno
            #For a 'comment' type token, all comment contents (multi-line or single-line) will be in one token.
            ed = lookup_line_no(tks[i+1][0]-1,index) + base_lno
            #We want to only mark the pure comment lines as 'comm', that's to say, 'a=b //asd' should be excluded.
            if st == ed:
                if _nothing(i,'u') and _nothing(i,'d'):
                    inf.setdefault('comm',[]).append((st,ed))
            elif ed > st:
                if not _nothing(i,'u'):
                    st += 1
                if not _nothing(i,'d'):
                    ed -= 1
                if ed >= st:
                    inf.setdefault('comm',[]).append((st,ed))
            i += 1
        else:
            i += 1
    return inf

#The parameter is the token list of the function arg list.
#Assume the token list is already stripped.
def _parse_func_args(tks):
    if not tks:
        return []
    v = len(tks[0]) - 1
    args = []
    ind = [i for i in range(len(tks)) if tks[i][v] == ',']
    ind = [-1] + ind + [len(tks)]
    for i in range(len(ind)-1):
        arg = ''.join([x[v] for x in tks[ind[i]+1:ind[i+1]]])
        args += [arg]
    return args

#Parse function information (function name and args) from a string.
def parse_func_from_str(text):
    tks = lex(text,lan='C',process=True)
    tks = strip_tokens(tks)
    i = 0
    while i < len(tks) - 1:
        if tks[i][0] in Token.Name and tks[i+1][1] == '(':
            name = tks[i][1]
            e_i = find_close(tks,i+1)
            if e_i is None:
                i += 1
                continue
            args = _parse_func_args(tks[i+2:e_i])
            return (name,args)
        i += 1
    return None

def print_surround_tokens(tks,i,cnt=5):
    if not tks:
        return
    v = len(tks[0]) - 1
    t1 = max(0,i-cnt)
    t2 = min(len(tks)-1,i+cnt)
    print ''.join([x[v] for x in tks[t1:t2+1]])

#find ')' for '(', '}' for '{', etc.
def find_close(tks,i):
    if not tks:
        return None
    v = len(tks[0]) - 1
    if tks[i][v] == '(':
        p = '('
        n = ')'
    elif tks[i][v] == '{':
        p = '{'
        n = '}'
    else:
        print 'Unsupported open: ' + tks[i][v]
        return None
    cnt = 1
    i += 1
    while i < len(tks):
        if tks[i][v] == p:
            cnt += 1
        elif tks[i][v] == n:
            cnt -= 1
            if cnt == 0:
                return i
        i += 1
    return None

def lex(text,lan='C',process=True):
    lexer = get_lexer_by_name(lan)
    tokens = []
    if process:
        it = lexer.get_tokens(text)
    else:
        it = lexer.get_tokens_unprocessed(text)
    for tok in it:
        tokens += [tok]
    return tokens

def strip_tokens(tks):
    if not tks:
        return tks
    v = len(tks[0]) - 1
    return filter(lambda x:x[v].strip()<>'',tks)

def _l_cls_decl(line,tks):
    if not tks or len(tks) < 4:
        return False
    tys = ('unsigned','int','long','u8','u16','u32','u64','struct')
    for ty in tys:
        if line.startswith(ty):
            break
    else:
        return False
    return True

def _l_cls_call(line,tks):
    tks = strip_tokens(tks)
    if not tks or len(tks) < 3:
        return False
    for i in range(len(tks)):
        if tks[i][1] == '(':
            if i >= 1 and tks[i-1][0] in Token.Name:
                return True
    return False

line_classifiers = {
    _l_cls_decl:'decl',
    _l_cls_call:'call',
}
def classify_line(line):
    tags = []
    tokens = lex(line.strip(),lan='C',process=True)
    for cls in line_classifiers:
        if cls(line.strip(),tokens):
            tags += [line_classifiers[cls]]
    return tags

def build_line_index(lines):
    index = []
    i = 0
    for l in lines:
        index += [i]
        i += len(l)
    index += [i]
    return index

def lookup_line_no(off,index):
    for i in range(len(index)):
        if off <= index[i]:
            return i - 1

