#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

/*
 * Arg 0: a Linux kernel image (should have been uncompressed)
 * Output: A kernel symbol-address mapping similar to "System.map" file, to stdout.
 * Sections from "kallsyms.S":
 * (1) kallsyms_token_table: an array storing most commonly used prefix/suffix strings for kernel symbols.
 * In the kernel image, the strings are stored one by one in a segment, each is terminated by 0.
 * (2) kallsyms_token_index: each entry in this array is the offset of the correlated string in
 * kallsyms_token_table. This array itself is stored in a segment just after the token_table segment
 * in the kernel image, each entry is a 2-bytes "short integer" (at least for 64-bits image)
 * (3) kallsyms_names: stores all the symbol name strings, but this "string" has a special format:
 * Byte 0: [Len]
 * Byte 1-Len: the string content, each byte is an index for kallsyms_token_index, this byte V stands
 * not for a single byte, but for such a string: kallsyms_token_table + kallsyms_token_index[V].
 * Note that the 1st byte in the final symbol name denotes "type" of the symbol.
 * Such a symbol string encoding can save space.
 * (4) kallsyms_num_syms: total number of symbols
 * (5) kallsyms_addresses: this array provides address for every symbol in kallsyms_num_syms.
 */

void *st;
int sz;
void *addr_token_table,*addr_token_index;
void *addr_syms_names,*addr_syms_addrs,*addr_syms_num;
unsigned num_syms;
char *addr_rel_base_addr = 0;
unsigned addr_entry_size = 8;

//used as return values of verify_addr_section() to indicate the properties of the kallsyms_addr section.
#define ADDR_OK 0x0
#define ADDR_NEEDS_RELOCATION (1<<0)
#define ADDR_NEEDS_REL_BASE (1<<1)
#define ADDR_ERR (1<<31)

int in_alphabet(char a){
    if(a>='a' && a<='z')
        return 1;
    if(a>='A' && a<='Z')
        return 1;
    if(a>='0' && a<='9')
        return 1;
    if(a=='_')
        return 1;
    return 0;
}

//We assume little endian here, as it's the usual case for Android kernel image.
int locate_token_table(){
    char *p,*s;

    for(p=(char*)st;p+24<=(char*)(st+sz);++p){
        if(*(int*)p==0x00310030 && *(int*)(p+4)==0x00330032 && *(int*)(p+16)==0x00390038 && (in_alphabet(*(char*)(p+20)) || in_alphabet(*(char*)(p+21)))){
            break;
        }
    }
    //It may fail.
    if(p+24>(char*)(st+sz))
        return 0;
    //locate the start of the token_table
    for(s=(char*)p;s>(char*)st;--s){
        if(*s==0 && *(s-1)==0){
            break;
        }
    }
    if(s>(char*)st){
        //find it
        addr_token_table=(void*)(s+1);
        return 1;
    }
    return 0;
}

//In this function we assume that the pointer currently points to the start of one section,
//we will move the pointer to the start of previous section. 
char* prev_section(char *p, unsigned align){
    while(!*(--p)); //skip the "zero" gap between two sections.
    p-=((unsigned long int)p % 4);
    //We assume the "zero" gap is at least 8 bytes long.
    while(*(int*)(p-4) || *(int*)(p-8)){
        p-=4;
    }
    p-=((unsigned long int)p % align);
    //We assume the section start is 0x100 aligned.
    //p =(char*)((long unsigned int)p & 0xffffffffffffff00);
    //We assume all sections (addr,name,num,token) have the same lowest 1 byte.
    //*(char*)&p = *(char*)&addr_token_table;
    return p;
}

int is_addr_section_zero = 0;
//Based on token_table address, this function will decide addresses for other sections.
int locate_other_sections(){
    char *p;
    const unsigned gap_num_rel = 0x1000;
    const unsigned gap_num_addr = 0x1000;
    //We don't need the token_index section because we can re-construct it according to token_table.
    //(1) Skip kallsyms_markers, we don't need it as well.
    p=prev_section((char*)addr_token_table,4);
    //Now we are at the beginning of the kallsyms_markers section.
    //(2) Locate the start of the syms_names section
    addr_syms_names=prev_section(p,4);
    //(3) Locate num_syms section and record the symbol amount.
    p=prev_section((char*)addr_syms_names,4);
    addr_syms_num = p;
    num_syms=*(unsigned*)p;
    //(4) Here we have multiple different cases:
    //* There may or may not be a "kernel_relative_base_address" section between the "num" and "addr" sections but its content may be 0 since the relocation.
    //* The "addr" section can have 8-byte or 4-byte entry size...
    p=prev_section(p,4);
    char *addr_end = p;
    if((unsigned long int)addr_syms_num - (unsigned long int)p < gap_num_rel){
        //This means there exists a "kernel_relative_base_address" section whose content is not 0.
        //The kernel rel base address should have its high 4 bytes non-zero.
        if(!*(int*)(p+4) && (*(int*)p & 0xff000000 == 0xff000000)){
            addr_rel_base_addr = p - 4;
        }else{
            addr_rel_base_addr = p;
        }
        //Record the position of the end of the non-zero section above rel_base.
        while(*(int*)(addr_end-=4));
        while(!*(int*)(addr_end-=4));
        addr_end += 4;
        //Record the position of the start of the non-zero section above rel_base.
        p=prev_section(p,4);
    }else{
        //Record the position of the end of the non-zero section above syms_num..
        //"p" is already the start of the non-zero section above syms_num.
        addr_end = addr_syms_num;
        while(*(int*)(addr_end-=4));
        while(!*(int*)(addr_end-=4));
        addr_end += 4;
    }
    //(5) Locate the syms_addrs section.
    fprintf(stderr,"addr_end before addr_sym_num/rel_base: %p\n",(void*)((void*)addr_end-st));
    if((unsigned long int)addr_syms_num - (unsigned long int)addr_end > gap_num_addr){
        is_addr_section_zero = 1;
        //We don't know where the addr section begins in this case (it will be further decided by the relocation information probing)
        //so now we set it to the start of a zero segment so that the verify_addr_section can make the right decision.
        addr_syms_addrs = addr_end;
        //NOTE: It will be unreliable to decide the addr entry size if we have the zero addr section, in this case we rely on the
        //relocation information probing to decide the entry size.
    }else{
        is_addr_section_zero = 0;
        //If the addr section is non-zero, we can try to decide the addr entry size.
        if((unsigned long int)addr_syms_num - (unsigned long int)p >= num_syms * 8){
            //This measn the addr section has 8-byte per entry.
            addr_entry_size = 8;
        }else{
            //4-byte entry
            addr_entry_size = 4;
        }
        addr_syms_addrs = addr_end - addr_entry_size * num_syms;
    }
    return 1;
}

int verify_addr_section(char *p, unsigned entry_size){
    int i;
    int ret = ADDR_OK;
    if(entry_size == 4){
        //Since we are dealing w/ the ARM64 kernel, the address should be 64 bits, so if the addr entry is 4-byte,
        //there has to be a relative base address, what we need to figure out is whether we still need to relocate the addr section.
        ret |= ADDR_NEEDS_REL_BASE; 
        for(i=32;i<64;++i){
            if(!*(int*)(p+i*4)){
                ret |= ADDR_NEEDS_RELOCATION;
                break;
            }
        }
    }else if(entry_size == 8){
        for(i=32;i<64;++i){
            //The addr section should be relocated.
            if(!*(long int*)(p+i*8)){
                ret |= ADDR_NEEDS_RELOCATION;
                break;
            }
            //fprintf(stderr,"%p %p\n",(void*)*(p+i),(void*)(*(p+i) & 0xffff000000000000));
            //The addr section is actually a 'delta' section, each entry is a 4-byte 'delta' and we should figure out the base address to add. (i.e. relative base address symbol table)
            //The heuristic here is that the highest few bytes should be 'f' for a normal symbol address in an AArch64 kernel.
            if((*(long int*)(p+i*8) & 0xffff000000000000) != 0xffff000000000000){
                ret |= ADDR_NEEDS_REL_BASE;
                break;
            }
        }
    }else{
        return ADDR_ERR;
    }
    return ret;
}

typedef struct relo_entry{
    unsigned long int off;
    unsigned long int inf;
    unsigned long int add;
}relo_entry;
typedef struct relo_section{
    relo_entry *st;
    relo_entry *ed;
}relo_section;

//TODO: This heuristic may or may not be sufficient.
int is_relo_entry(relo_entry *p){
    //if(p->off>>40==0xffffff && p->add>>40==0xffffff)
    if(p->off>>40==0xffffff)
        return 1;
    return 0;
}

relo_entry *relo_st=0;
relo_entry *relo_ed=0;
char *kallsyms_addr=0;
relo_section relo_secs[16];
int num_secs=0;
relo_entry *relo_sec=0;
unsigned long int guessed_kernel_base_from_relo=0;

//This function tries to identify the relocation entries for the kallsyms_addr section, BTW it can probe
//the "addr_entry_size" and the start address of kallsyms_addr section.
int try_locate_relo_symaddr(relo_entry *p,relo_entry *e){
    //Now we need to locate the relo entries for kallsym_addr section, heuristics again...
    int i;
    const int g1_min=2048;
    const int g1_max=4096;
    const int g2=4096;
    fprintf(stderr,"m0 p:%p e:%p\n",p,e);
    for(addr_entry_size=8;addr_entry_size>=4;addr_entry_size-=4){
        int g1 = g1_max;
        while(!relo_st && g1>=g1_min){
            while(p+g2+g1<e){
                /*
                //Heuristic 0: the first symbol address in the symbol table should be the kernel base address,
                //so in the corresponding relo_entry, the .add field should be either the base address or 0 (if it's the relative relo).
                if(p->add != 0 && p->add != guessed_kernel_base_from_relo){
                    ++p;
                    continue;
                }
                */
                //Heuristic 1: We should see many consecutive "off" fields representing the consecutive sym addr entries, with interval 8 or 4 depending on the addr section entry size.
                for(i=0;i<g1-1;++i){
                    if((p+i)->off+addr_entry_size*g2!=(p+i+g2)->off)
                        break;
                    if((p+i)->off+addr_entry_size!=(p+i+1)->off)
                        break;
                }
                if(i>=g1-1){
                    //find it
                    relo_st = p;
                    goto exit;
                }
                p+=(i+1);
            }
            g1>>=1;
        }
    }
exit:
    if(!relo_st){
        return 0;
    }
    fprintf(stderr,"try_locate_relo_symaddr(): probed addr_entry_size: %d\n",addr_entry_size);
    //locate relo_end for kallsyms_addr section
    //for(p=relo_st;p<e;++p){
    //    if(p->off+addr_entry_size!=(p+1)->off)
    //        break;
    //}
    //relo_ed=p;
    kallsyms_addr=(char*)(relo_st->off);
    //fprintf(stderr,"try_locate_relo_symaddr st:%p ed:%p\n",relo_st,relo_ed);
    return 1;
}

//Method 1
int relo_ent_cmp(const void *a,const void *b){
    relo_entry *a1=(relo_entry*)a;
    relo_entry *b1=(relo_entry*)b;
    if(a1->off==b1->off)
        return 0;
    return a1->off>b1->off?1:-1;
}
//Provide a starting entry pointer, get the ending entry pointer of this relo section.
relo_entry *get_relo_sec_ed(relo_entry *p,relo_entry *e){
    for(;p<e&&is_relo_entry(p);++p);
    return p-1;
}

void print_relo_secs(){
    relo_entry *p = relo_sec;
    while(p<relo_ed){
        fprintf(stderr,"%016lx %016lx %016lx\n",p->off,p->inf,p->add);
        ++p;
    }
    return;
}

//Use some heuristics to locate the start and end of each relocation section
int get_relo_sections(){
    relo_entry *p = (relo_entry*)st;
    relo_entry *e = (relo_entry*)((char*)st+sz);
    int i;
    const int g=128;
    while(p+g<e){
        for(i=0;i<g;++i){
            if(!is_relo_entry(p+i))
                break;
        }
        if(i>=g){
            //'relo_st' found
            relo_secs[num_secs].st=p;
            relo_secs[num_secs].ed=get_relo_sec_ed(p,e);
            p=relo_secs[num_secs].ed+1;
            ++num_secs;
            continue;
        }
        //continue to find
        //NOTE: some kernel images may be aligned to 4 bytes instead of 8, so we'd better make the step of 4.
        p=(relo_entry*)((char*)p+4);
    }
    if(!num_secs){
        fprintf(stderr,"Cannot locate any relo_sec..");
        return 0;
    }
    for(i=0;i<num_secs;++i){
        fprintf(stderr,"RELO_SEC %d: +%p for off: +%p - +%p for off: +%p\n",i,(void*)((void*)relo_secs[i].st-st),(void*)relo_secs[i].st->off,(void*)((void*)relo_secs[i].ed-st),(void*)relo_secs[i].ed->off);
    }
    //Organize all relo entries together and sort them.
    int len=0,j=0,t;
    for(i=0;i<num_secs;++i){
        len += (relo_secs[i].ed-relo_secs[i].st+1);
    }
    relo_sec=(relo_entry*)malloc(sizeof(relo_entry)*len);
    for(i=0;i<num_secs;++i){
        t=relo_secs[i].ed-relo_secs[i].st+1;
        memcpy(relo_sec+j,relo_secs[i].st,sizeof(relo_entry)*t);
        j+=t;
    }
    qsort(relo_sec,len,sizeof(relo_entry),relo_ent_cmp);
    relo_ed=relo_sec+len;
    //print_relo_secs();
    //The "offset" of each relo entry is an actual address within a loaded kernel image (i.e. kernel_base+XXX),
    //since we already sorted all relo entries, the first relo entry should have an offset that is nearest to the "kernel_base",
    //so here we guess the "kernel_base" by masking out lowest bits of first relo entry's "offset".
    guessed_kernel_base_from_relo = relo_sec->off & 0xfffffffffffff000;
    fprintf(stderr,"guessed_kernel_base_from_relo: %016lx\n",guessed_kernel_base_from_relo);
    return 1;
}

//arg: the addr of the rel_base section
//return the kernel rel base addr.
unsigned long int relocate_kernel_rel_base(unsigned long int* addr_syms_relb){
    unsigned long int min_base = 0xffffffffffffffff; 
    if((unsigned long int)addr_syms_relb <= (unsigned long int)st){
        return min_base;
    }
    unsigned long int delta_syms_relb=(unsigned long int)addr_syms_relb-(unsigned long int)st;
    relo_entry *rp = relo_sec;
    for(;rp<relo_ed;++rp){
        //Is this heuristic reliable?
        //unsigned long int t = rp->add + (rp->inf>>32);
        unsigned long int t = rp->add;
        if(rp->off==t + delta_syms_relb){
            if(t<min_base)
                min_base=t;
        }
    }
    return min_base + *addr_syms_relb;
}

#define NUM_TOKEN 256
char* tokens[NUM_TOKEN];

int main(int argc, char **argv){
    int fd,err,i,len,j,ind;
    struct stat sta;
    char *p,buf[256];
    int gen_idc;

    if(argc<2){
        perror("Usage: <prog> <uncompressed kernel image> <gen_idc(opt)>\n");
        goto exit;
    }else{
        gen_idc=(argc<3?0:1);
    }
    fd=open(argv[1],O_RDONLY);
    if(fd<0){
        perror("Open kernel image failed\n");
        goto exit;
    }
    if(fstat(fd, &sta)){
        perror("Cannot obtain kernel image file length\n");
        goto exit;
    }
    sz=sta.st_size;
    fprintf(stderr,"Image size: %d\n",sz);
    st=mmap(NULL,sz,PROT_READ,MAP_SHARED,fd,0);
    if(st==MAP_FAILED){
        perror("Fail to map the image into memory.\n");
        goto exit_0;
    }
    fprintf(stderr,"Image base address in memory: %p\n",st);
    //Now we'll try to locate the kallsyms_token_table section, we choose this one among others because
    //we can get a signature string easily from it. That is "0 \0 1 \0 2 \0 ... 9 \0". We can find several
    //such strings in the kernel image, however, the one in the kallsyms_token_table section will not be
    //followed by ":" (the char after "9" in next table).
    //After locating this section, we can then locate other sections since they are adjacent.
    fprintf(stderr,"Locating the token_table address...\n");
    if(!locate_token_table()){
        perror("Cannot locate kallsyms_token_table in the kernel image.\n");
        goto exit_1;
    }
    fprintf(stderr,"token_table: +%p\n",(void*)(addr_token_table-st));
    fprintf(stderr,"Locating other sections...\n");
    if(!locate_other_sections()){
        perror("Cannot locate other sections in the kernel image.\n");
        goto exit_1;
    }
    fprintf(stderr,"syms_names: +%p\n",(void*)(addr_syms_names-st));
    fprintf(stderr,"syms_addrs: +%p\n",(void*)(addr_syms_addrs-st));
    fprintf(stderr,"syms_num: +%p(#%d)\n",(void*)(addr_syms_num-st),num_syms);
    fprintf(stderr,"rel_base_addr: +%p\n",addr_rel_base_addr ? (void*)((void*)addr_rel_base_addr-st) : (void*)addr_rel_base_addr);
    fprintf(stderr,"is_addr_section_zero: %d, addr_entry_size: %u\n",is_addr_section_zero,addr_entry_size);
    //Here we should verify that the kallsyms_addresses section is valid, some kernels need relocation to fill this section and some kernels use 'relative base address' symbol table,
    //some kernels have the 4-byte addr entry size and some have 8-byte one.
    int addr_code = ADDR_NEEDS_RELOCATION;
    if(!is_addr_section_zero){
        addr_code = verify_addr_section(addr_syms_addrs,addr_entry_size);
    }
    int addr_relocated = 0;
    if(addr_code & ADDR_NEEDS_RELOCATION){
        fprintf(stderr,"The kallsyms_addresses section needs a relocation...\n");
        if(!get_relo_sections()){
            fprintf(stderr,"Fail to get relo section, exit..\n");
            return 0;
        }
        if(!try_locate_relo_symaddr(relo_sec,relo_ed)){
            fprintf(stderr,"Cannot locate relo inf for kallsym_addr..\n");
            return 0;
        }
        fprintf(stderr,"Below relo info is for kallsyms_addresses...\n");
        fprintf(stderr,"relo_st:%p for off:%p and add:%p, relo_ed:%p for off:%p and add:%p\n",relo_st,(void*)(relo_st->off),(void*)(relo_st->add),relo_ed,(void*)(relo_ed->off),(void*)(relo_ed->add));
        //prepare for the relocated kallsyms_addr section.
        addr_syms_addrs = (void*)malloc(num_syms*8);
        unsigned long int *t1 = (unsigned long int*)addr_syms_addrs;
        relo_entry *t2 = relo_st;
        char *t3;
        for(i=0;i<num_syms && t2<relo_ed;++i){
            //t3 is the kallsyms_addr section entry address for current symbol.
            t3=kallsyms_addr+i*addr_entry_size;
            while(t2->off<(unsigned long int)t3 && t2<relo_ed)
                ++t2;
            if (t2 >= relo_ed)
                break;
            if(t2->off==(unsigned long int)t3){
                if(addr_entry_size == 4){
                    //*(t1+i)= t2->add + (t2->inf>>32);
                    *(t1+i) = t2->add;
                }else{
                    //*(t1+i)= t2->add + (t2->inf>>32);
                    *(t1+i) = t2->add;
                }
                ++t2;
            }else if(t2->off>(unsigned long int)t3){
                //this means we don't have this symbol's address even with relocation information.
                *(t1+i) = 0;
            }
        }
        fprintf(stderr,"Addr entries relocated: %d/%d\n",i,num_syms);
        //After relocating the addr section, we may still need to rebase each entry.
        addr_code = verify_addr_section(addr_syms_addrs,8);
        addr_relocated = 1;
    }
    if(addr_code & ADDR_NEEDS_REL_BASE){
        fprintf(stderr,"This kernel should use relative-base-address format symbol table.\n");
        fprintf(stderr,"Try to figure out the relative base address...\n");
        if(!relo_sec && !get_relo_sections()){
            fprintf(stderr,"Fail to get relo section, exit..\n");
            return 0;
        }
        unsigned long int base_addr = 0xffffffffffffffff;
        if(addr_rel_base_addr){
            //Ok, we have the kernel_rel_base_addr section w/ non-zero content.
            base_addr = *(unsigned long int*)addr_rel_base_addr;
            fprintf(stderr,"We have a non-zero rel_base section whose value is: %p\n",(void*)base_addr);
            if((base_addr & 0xff00000000000000) != 0xff00000000000000){
                //This rel_base itself needs to be relocated.
                base_addr = relocate_kernel_rel_base((unsigned long int*)addr_rel_base_addr);
                fprintf(stderr,"Still need to relocate the non-zero rel_base section, after that: %p\n",(void*)base_addr);
            }
        }else{
            //Needs to probe the correct kernel_rel_base_addr section address and do the relocation at the same while.
            fprintf(stderr,"We don't know the exact rel_base section address, try and probe...\n");
            char *pr = (char*)addr_syms_num - 8;
            int max_cnt = 0x100;
            while(!*(long int*)pr && max_cnt--){
                unsigned long int t_base = relocate_kernel_rel_base((unsigned long int*)pr);
                if (t_base < base_addr) {
                    base_addr = t_base;
                }
                pr -= 4;
            }
            fprintf(stderr,"Probed kernel base address: %p\n",(void*)base_addr);
        }
        if (base_addr != guessed_kernel_base_from_relo){
            fprintf(stderr,"Probed base address is not equal to guessed_kernel_base_from_relo, if something bad happens later, consider to use guessed_kernel_base_from_relo\n");
            if (base_addr == 0xffffffffffffffff) {
                base_addr = guessed_kernel_base_from_relo;
            }
        }
        //First create a new addr table to unify the 4-byte and 8-byte entry.
        if(!addr_relocated){
            void *new_addr_table = (void*)malloc(num_syms*8);
            if(addr_entry_size == 4){
                for(i=0;i<num_syms;++i){
                    *((int*)new_addr_table+i*2) = *((int*)addr_syms_addrs+i);
                    *((int*)new_addr_table+i*2+1) = 0;
                }
            }else{
                memcpy((char*)new_addr_table,(char*)addr_syms_addrs,num_syms*8);
            }
            addr_syms_addrs = new_addr_table;
        }
        //Ok, rebase the addr section now.
        for(i=0;i<num_syms;++i){
            *((unsigned long int*)addr_syms_addrs+i) += base_addr;
        }
    }
    //Set up the token array.
    p=(char*)addr_token_table;
    for(i=0;i<NUM_TOKEN;++i){
        tokens[i]=p;
        p+=(strlen(p)+1);
    }
    //Generate the IDA Pro script to introduce the symbols, based on the token array.
    if(gen_idc){
        printf("#include <idc.idc>\n");
        printf("\n");
        printf("static main()\n");
        printf("{\n");
    }

    p=(char*)addr_syms_names;
    for(i=0;i<num_syms;++i){
        void *pt = (void*)*((long int*)addr_syms_addrs+i);
        buf[0]=0;
        len=*(int*)p;
        len&=0xff;
        for(j=0;j<len;++j){
            ++p;
            ind=*(int*)p;
            ind&=0xff;
            strcat(buf,tokens[ind]);
        }
        ++p;
        if(!pt){
            fprintf(stderr,"Null addr_inf for the symbol: %c %s\n",buf[0],buf+1);
            continue;
        }
        if(gen_idc){
            printf("MakeName(%p, \"%s\");\n",pt,buf+1);
        }else{
            printf("%p %c %s\n",pt,buf[0],buf+1);
        }
    }
    if(gen_idc){
        printf("}\n");
    }
exit_1:
    munmap(st,sz);
exit_0:
    close(fd);
exit:
    return 0;
}
