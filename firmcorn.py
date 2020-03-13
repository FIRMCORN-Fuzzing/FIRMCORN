import sys
import logging 
import os
import json
import binascii
from pwn import * 
import random


# Unicorn imports
# require unicorn moudle
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *

# custom module import 
from hook.hook_loader import *

from fuzz.fuzz_loader import *
from crash.crash_loader import *

# Name of the index file
CONTEXT_JSON = "_index.json"

UNICORN_PAGE_SIZE = 0x1000

MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024
    
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP   = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1)
LITTLE2BIG      = lambda num : int( num.decode('hex')[::-1].encode('hex') , 16)

COMPILE_GCC = 1
COMPILE_MSVC = 2
BASE = 0x0400000



class Firmcorn( Uc ): # Firmcorn object inherit from Uc object  
    '''
    Firmcorn-object is main object of our Firmcorn Framework
    '''
    def __init__(self   ,compiler = COMPILE_GCC , enable_debug = True):
        self.enable_debug = enable_debug
        self.trace_start_addr = 0
        self.trace_end_addr = 0
        self.dbg_addr_list = []
        self.skip_func_list = None
        self.unresolved_funcs = None
        self.fuzztarget = None
        self.compiler = compiler
        self.instrs = []

    def load_context(self , context_dir , binary , libc):
        self.context_dir = context_dir
        self.elf = ELF(binary)
        self.libc = ELF(libc)
        self.got = self.elf.got
        self.get_arch_info()
        Uc.__init__(self, self.uc_arch, self.uc_mode + self.uc_endian)

    def rand_seed(self , seed_len):
        sa = []
        for i in range(seed_len):
            sa.append( chr(random.randint(0,255)))
        return ''.join(sa)

    def _load_context(self):
        """
        load context and binary actual
        """
        self.get_arch_info()
        context_json = os.path.join( self.context_dir, CONTEXT_JSON)
        if not os.path.isfile(context_json):
            raise Exception("Contex json not found")
        context_json_file  = open(context_json , "r")
        context = json.load(context_json_file) # load _index.json
        context_json_file.close()
        regs_map = self.get_regs_by_arch(self.arch)
        regs = context['regs']

        self.init_class()

        self.get_common_regs()
        
        # endian to uc_endian
        if self.endian == "big":
            self.uc_endian =  UC_MODE_BIG_ENDIAN
        else:
            self.uc_endian =  UC_MODE_LITTLE_ENDIAN

        # init uc object
        Uc.__init__(self, self.uc_arch, self.uc_mode + self.uc_endian)

        # setup registers
        if not self.set_reg(regs , regs_map):
            raise Exception("Error in setup registers")

        # setup segment
        segments_list = context['segments'] # 
        if not self.set_memory(segments_list):
            raise Exception("Error in setup memory")
        
        # init got
        self.init_got()
        self.rebased_got()

    def get_arch_info(self):
        """
        get uc_arch , uc_mode , endian
        """
        context_json = os.path.join( self.context_dir, CONTEXT_JSON)
        if not os.path.isfile(context_json):
            raise Exception("Contex json not found")
        
        # load context from json
        context_json_file  = open(context_json , "r")
        context = json.load(context_json_file) # load _index.json
        context_json_file.close()
        self.arch = context['arch']['arch']
        self.endian = context['arch']['endian']

        # arch to uc_arch
        if self.arch == "x64":
            self.uc_arch =  UC_ARCH_X86
            self.uc_mode = UC_MODE_64
        elif self.arch == "x86":
            self.uc_arch = UC_ARCH_X86
            self.uc_mode = UC_MODE_32
        elif self.arch == "mips":
            self.uc_arch = UC_ARCH_MIPS
            self.uc_mode = UC_MODE_32
        elif self.arch == "arm":
            self.uc_arch = UC_ARCH_ARM
            self.uc_mode = UC_MODE_32
        else:
            raise Exception("Error arch")

        # endian to uc_endian
        if self.endian == "big":
            self.uc_endian =  UC_MODE_BIG_ENDIAN
        else:
            self.uc_endian =  UC_MODE_LITTLE_ENDIAN

    def load_library(self , libc):
        self.libc = ELF(libc)

    def init_got(self , enable_debug = True):
        """
        read GOT table entries in memory 
        """
        print "=====================Init GOT Table Start========================"
        print self.got.items()
        self.mem_got = dict()
        for name , addr in self.got.items():
            _addr = str(self.mem_read(addr , self.size)).encode("hex") 
            if self.endian == "little":
                _addr = LITTLE2BIG(_addr)
            else:
                _addr = int(_addr , 16)
            self.mem_got.update({ _addr : name})
            print "Name : {:<40} Addr : {:<10} Value: {:<10}".format( name, hex(addr) , hex(_addr))
        print "======================Init GOT Table End========================="
        
    def rebased_got(self):
        """
        reload GOT table entries
        """
        self.rebase_got = dict()
        print "====================Rebase GOT Table Start=======================" 
        for addr , name in self.mem_got.items():
            if int(addr) & 0xff000000 != 0:
                dl_resolve_addr = addr 
                dl_resolve_name = name 
                break
        print self.libc
        libc_base = dl_resolve_addr - self.libc.symbols[dl_resolve_name] 
        print "libc_base : {}".format(hex(libc_base))
        for addr , name  in self.mem_got.items():
            if self.libc.symbols.has_key(name):
                self.rebase_got.update( { name :  libc_base + self.libc.symbols[name]   })
                print "Name : {:<40} Rebase addr : {}".format(name , hex(libc_base + self.libc.symbols[name]) )
                
        #raw_input()
        print "=====================Rebase GOT Table End========================" 

    def dbg_hook_code(mu, address, size, user_data):  
        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    def debug_moudle(self , start_addr , end_addr):
        """
        debug 
        """
        dbg_mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
        dbg_mu.hook_add(UC_HOOK_CODE, self.dbg_hook_code)
        dbg_mu.emu_start(start_addr )

    def set_reg(self , regs, regs_map , debug_func = True ):
        self.enable_debug = debug_func
        # setup register
        for register , value in regs.iteritems():
            if self.enable_debug and value is not None:
                print "Reg {0} start_address = {1}".format(register, hex(value)) 
                pass
            if not regs_map.has_key(register.lower()):
                if self.enable_debug:
                    print "Skip Reg:{0}".format(register)
            else:
                # ====copy from unicorn loader.py=====
                # 
                reg_write_retry = True
                try:
                    self.reg_write(regs_map[register.lower()], value)
                    reg_write_retry = False
                except Exception as e:
                    if self.enable_debug:
                        print "ERROR writing register: {}, value: {} -- {}".format(register, value, repr(e)) 
                if reg_write_retry:
                    if self.enable_debug:
                        print "Trying to parse value ({}) as hex string".format(value)
                    try:
                        self.reg_write(regs_map[register.lower()], int(value, 16))
                    except Exception as e:
                        if self.enable_debug:
                            print "ERROR writing hex string register: {}, value: {} -- {}".format(register, value, repr(e))
        
        return True

    def set_memory(self , segments_list , debug_func = True  ):
        """
        setup memory need 2 steps
        1. mu.mem_map
        2. mu.mem_write
        before mem_map, must check it's not already mapped
        copy from __map_segments
        """
        self.enable_debug = debug_func
        for segment in segments_list:
            seg_name = segment['name']
            seg_start = segment['start']
            seg_end = segment['end']
            perms = \
                (UC_PROT_READ  if segment['permissions']['r'] == True else 0) | \
                (UC_PROT_WRITE if segment['permissions']['w'] == True else 0) | \
                (UC_PROT_EXEC  if segment['permissions']['x'] == True else 0)        

            if self.enable_debug:
                print "Handling segment {}".format(seg_name) 
            """
            before map memory , do some check
            there are 3 cases:
            ======= 1 =======
            +----------------------------+ <-----+ mem_start
            |                            |
            |  +----------------------+<----+  seg_start
            |  |                      |  |
            |  |                      |  |
            |  +----------------------+<----+  seg_end
            |                            |
            +----------------------------+ <-----+  mem_end
            for this case, shoud't map memory 

            ======= 2 =======
            +-----------------------------+<-----+ mem_start
            |                             |
            |                             |
            +------------------------------<----+  seg_start
            |                             |
            |                             |
            |                             |
            +------------------------------<-----+  mem_end=tmp
            |-----------------------------|
            |--------------------------------------------->map area
            |-----------------------------|
            +------------------------------<----+  seg_end
            
            ======= 3 =======
            +------------------------------<----+  seg_start
            |-----------------------------|
            |--------------------------------------------->map area
            |-----------------------------|
            +------------------------------<-----+ mem_start=tmp
            |                             |
            |                             |
            |                             |
            +------------------------------<----+  seg_end
            |                             |
            |                             |
            |                             |
            +-----------------------------+<-----+  mem_end
            """
            found = False
            overlap_start = False
            overlap_end = False
            tmp = 0
            for (mem_start, mem_end, mem_perm) in self.mem_regions():
                mem_end = mem_end + 1
                if seg_start >= mem_start and seg_end < mem_end:
                    found = True
                    break
                if seg_start >= mem_start and seg_start < mem_end:
                    overlap_start = True
                    tmp = mem_end
                    break
                if seg_end >= mem_start and seg_end < mem_end:
                    overlap_end = True
                    tmp = mem_start
                    break

            # Map memory into the address space if it is of an acceptable size.
            if (seg_end - seg_start) > MAX_ALLOWABLE_SEG_SIZE:
                if self.enable_debug:
                    print "Skipping segment (LARGER THAN {0}) from {1:016x} - {2:016x} with perm={3}: {4}".format(MAX_ALLOWABLE_SEG_SIZE, seg_start, seg_end, perms, name)
                continue
            elif not found:           # Make sure it's not already mapped
                if overlap_start:     # Partial overlap (start) case 3
                    self.map_segment(seg_name, tmp, seg_end - tmp, perms)
                elif overlap_end:       # Patrial overlap (end) case 2
                    self.map_segment(seg_name, seg_start, tmp - seg_start, perms)
                else:                   # Not found
                    self.map_segment(seg_name, seg_start, seg_end - seg_start, perms)
            else:
                if self.enable_debug:
                    print "Segment {} already mapped. Moving on.".format(seg_name) 

            # Load the content (*.bin)
            # directly copy from unicorn_loader.py
            if 'content_file' in segment and len(segment['content_file']) > 0:
                content_file_path = os.path.join(self.context_dir, segment['content_file'])
                if not os.path.isfile(content_file_path):
                    raise Exception("Unable to find segment content file. Expected it to be at {}".format(content_file_path))
                if self.enable_debug:
                    print "Loading content for segment {} from {}".format(seg_name, segment['content_file'])
                content_file = open(content_file_path, 'rb')
                compressed_content = content_file.read()
                content_file.close()
                self.mem_write(seg_start, zlib.decompress(compressed_content)) 

            else:
                if self.enable_debug:
                    print("No content found for segment {0} @ {1:016x}".format(seg_name, seg_start))
                self.mem_write(seg_start, '\x00' * (seg_end - seg_start))


        return True

    def map_segment(self , name, address, size, perms , debug_func = True ):
        self.enable_debug = debug_func
        map_start = address 
        map_end = address + size
        # page alingn
        map_start_align = ALIGN_PAGE_DOWN(map_start)
        map_end_align = ALIGN_PAGE_UP(map_end)
        if self.enable_debug:
            print " segment name: {}".format(name)
            print " segment start: {0:016x} -> {1:016x}".format(map_start, map_start_align)
            print " segment end:   {0:016x} -> {1:016x}".format(map_end, map_end_align)
        if map_start_align < map_end_align: 
            self.mem_map(map_start_align , map_end_align - map_start_align , perms) # map memory

        # pass

    def func_skip(self , skip_list = None):
        self.skip_func_list = skip_list

    def set_trace(self , trace_start_addr , trace_end_addr  , debug_func=True):
        self.trace_start_addr = trace_start_addr
        self.trace_end_addr = trace_end_addr

    def _set_trace(self , uc , address , size , user_data):
        if address >= self.trace_start_addr and address <=self.trace_end_addr:
            # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
            print "{} ".format(hex(address)) , 
            instr = self.mem_read(address, size)
            # context.arch      = 'i386'
            context.endian    = str(self.endian)
            # context.os        = 'linux'
            # context.word_size = 32
            # print ("0x%x %s" % (address - BASE ,   disasm(instr)) )
            if  self.arch == "x86":
                print "{}".format( disasm(instr , arch="{}".format("i386")))
            elif self.arch == "x64":
                print "{}".format( disasm(instr , arch="{}".format("amd64")))
            elif self.arch == "mips":
                print "{}".format( disasm(instr , arch="{}".format("mips")))
            elif self.arch == "arm":
                print "{}".format( disasm(instr , arch="{}".format("arm")))
            else:
                raise Exception("arch not found")

    def show_debug_info(self , dbg_addr_list):
        self.dbg_addr_list = dbg_addr_list

    def _show_debug_info(self, uc , address , size , user_data ):
        """
        show registers and memory info when debug
        """
        if address in self.dbg_addr_list:
            self.show_reg_value()
            self.show_memory_layout()

    def show_reg_value(self):
        context_json = os.path.join( self.context_dir, CONTEXT_JSON)
        if not os.path.isfile(context_json):
            raise Exception("Contex json not found")
        
        # load context from json
        context_json_file  = open(context_json , "r")
        context = json.load(context_json_file) # load _index.json
        context_json_file.close()
        regs_map = self.get_regs_by_arch(self.arch)
        regs = context['regs']
        
        # show registers value
        print("=========================Registers Value=========================")
        for register , value in regs.iteritems():
            try:
                print("Reg {} --> {:<51} {}".format(register.lower() ,hex(self.reg_read(regs_map[register.lower()])), "||"))
            except Exception as e:
                # print "ERROR writing register: {}, value: {} -- {}".format(register, value, repr(e))
                pass
        print("=================================================================")

    def show_memory_layout(self):
        print("=========================Memory Layout===========================")
        # show stack memory
        for i in range(6):
            # reg_sp = self.reg_read(self.REG_SP , size)
            #stack_addr = reg_sp + 0x14 + 4*i
            # print self.size
            stack_addr = 0x7fffffffd870  - 8*i
            mem_cont = self.mem_read(stack_addr, self.size)
            print("{} --> {:<41} {}".format(  hex(stack_addr) ,str(mem_cont).encode("hex") , "||"))
        print("=================================================================")

    def show_instrs(self):
        """
        print crash location instruction
        """
        print "=========================Instructions=========================="
        for instr in self.instrs[:-50:-1]:
            print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(instr, self.size))
        print "==============================================================="

    def log_instrs(self , uc , address , size , user_data):
        self.instrs.append(address)

    def add_func(self , func_list = None):
        self.unresolved_funcs = func_list

    def add_fuzz(self, fuzzTarget):
        """
        add a fuzz targrt object
        """
        self.fuzztarget = fuzzTarget

    def start_find(self , start_address , end_address):
        print "  ______ _____ _____  __  __  _____ ____  _____  _   _  "
        print " |  ____|_   _|  __ \|  \/  |/ ____/ __ \|  __ \| \ | | "
        print " | |__    | | | |__) | \  / | |   | |  | | |__) |  \| | "
        print " |  __|   | | |  _  /| |\/| | |   | |  | |  _  /| . ` | "
        print " | |     _| |_| | \ \| |  | | |___| |__| | | \ \| |\  | "
        print " |_|    |_____|_|  \_\_|  |_|\_____\____/|_|  \_\_| \_| "
        print "                                                        "
        # uc_result = self.emu_start(start_address , end_address)
        self.unresolved_funcs = []
        rounds = 0
        while True:
            self._load_context()
            #raw_input()
            """
            some hook function
            """
            #raw_input()
            last_round_list_len = len(self.unresolved_funcs)
            if self.skip_func_list is not None:
                self.hook_add(UC_HOOK_CODE , self.hookcode._func_skip)
            if self.dbg_addr_list is not None:
                self.hook_add(UC_HOOK_CODE, self._show_debug_info)
            if self.trace_start_addr!=0 and self.trace_end_addr!=0:
                self.hook_add(UC_HOOK_CODE , self._set_trace)
            if self.unresolved_funcs is not None:
                self.hook_add(UC_HOOK_CODE , self.hookcode.hook_unresolved_func)
            self.hook_add(UC_HOOK_CODE , self.log_instrs)
            self.hook_add(UC_HOOK_CODE , self.hookcode.hookauto.record_last_func)
            self.hook_add( UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED  , self.hookcode.hookauto.find_unresolved_func)
            try:
                uc_result = self.emu_start(start_address , end_address)
            except UcError as e:
                print "next round"
                print "Round : {}".format(rounds)
                rounds += 1
                print  "find all unresolved funcs : {}".format(self.unresolved_funcs)
                # raw_input()
            # raw_input()
            if len(self.unresolved_funcs) == last_round_list_len:
                print self.unresolved_funcs
                print "End Find!"
                break

    def start_run(self , start_address , end_address):
        self.start_find(start_address , end_address)
        print "=================End Find================="
        print "start run!"
        # raw_input()
        rounds = 0
        while True:
            self._load_context()
            if  self.fuzztarget is not None:
                self.fuzztarget.init(self)
                self.hook_add(UC_HOOK_CODE , self.fuzztarget.find_magic_num)
            if self.skip_func_list is not None:
                self.hook_add(UC_HOOK_CODE , self.hookcode._func_skip)
            if self.dbg_addr_list is not None:
                self.hook_add(UC_HOOK_CODE, self._show_debug_info)
            if self.trace_start_addr!=0 and self.trace_end_addr!=0:
                self.hook_add(UC_HOOK_CODE , self._set_trace)
            if self.got is not None:
                # self.hook_add(UC_HOOK_CODE , self.hookcode.func_alt_auto_libc)
                pass
            if self.unresolved_funcs is not None:
                self.hook_add(UC_HOOK_CODE , self.hookcode.hook_unresolved_func)
            # self.hook_add( UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED  , self.crash.mem_crash_check)
            # self.hook_add(UC_ERR_FETCH_UNMAPPED , self.crash.crash_check_dbg)
            self.hook_add(UC_HOOK_CODE , self.log_instrs)

            # try:  
            #     uc_result = self.emu_start(start_address , end_address)
            # except UcError as e:
            #     # if e.errno == UC_ERR_READ_UNMAPPED:
            #     print("   \033[1;31;40m !!! about to bail due to bad fetch... here's the data at PC: {} \033[0m   ".format(  binascii.hexlify(self.mem_read(self.reg_read(self.REG_PC), self.size)))  )
            #     # print(binascii.hexlify(self.mem_read(self.reg_read(self.REG_PC), self.size)))
            #     self.show_instrs()
            import datetime
            oldtime=datetime.datetime.now()
            try:
                uc_result = self.emu_start(start_address , end_address)
            except UcError as e:
                print e.errno
                if e.errno == UC_ERR_FETCH_UNMAPPED:
                    print "   \033[1;31;40m !!! Find Crash !!! \033[0m   "
                    self.crash.crash_log()
                    break

            newtime=datetime.datetime.now()
            print "time : {}".format( (newtime-oldtime).microseconds )
            print "Round : {}".format(rounds)
            rounds += 1
            # raw_input()

    def init_class(self): 
        """
        import other classes
        """
        self.hookcode = HookLoader(self)
        self.crash    = CrashLoader(self)

    def get_regs_by_arch(self , arch):
        if arch == "arm64le" or arch == "arm64be":
            arch = "arm64"
        elif arch == "armle" or arch == "armbe" or "thumb" in arch:
            arch = "arm"
        elif arch == "mipsel":
            arch = "mips"
        registers = {

            "x64" : {
                "rax":    UC_X86_REG_RAX,
                "rbx":    UC_X86_REG_RBX,
                "rcx":    UC_X86_REG_RCX,
                "rdx":    UC_X86_REG_RDX,
                "rsi":    UC_X86_REG_RSI,
                "rdi":    UC_X86_REG_RDI,
                "rbp":    UC_X86_REG_RBP,
                "rsp":    UC_X86_REG_RSP,
                "r8":     UC_X86_REG_R8,
                "r9":     UC_X86_REG_R9,
                "r10":    UC_X86_REG_R10,
                "r11":    UC_X86_REG_R11,
                "r12":    UC_X86_REG_R12,
                "r13":    UC_X86_REG_R13,
                "r14":    UC_X86_REG_R14,
                "r15":    UC_X86_REG_R15,
                "rip":    UC_X86_REG_RIP,
                "rsp":    UC_X86_REG_RSP,
                "efl":    UC_X86_REG_EFLAGS,
                "cs":     UC_X86_REG_CS,
                "ds":     UC_X86_REG_DS,
                "es":     UC_X86_REG_ES,
                "fs":     UC_X86_REG_FS,
                "gs":     UC_X86_REG_GS,
                "ss":     UC_X86_REG_SS,
            },
            "x86" : {
                "dil":    UC_X86_REG_DIL,
                "ip":     UC_X86_REG_IP ,
                "fs":     UC_X86_REG_FS ,
                "eip":    UC_X86_REG_EIP,
                "bh":     UC_X86_REG_BH ,
                "edi":    UC_X86_REG_EDI,
                "ah":     UC_X86_REG_AH ,
                "al":     UC_X86_REG_AL ,
                "cs":     UC_X86_REG_CS ,
                "cx":     UC_X86_REG_CX ,
                "eax":    UC_X86_REG_EAX,
                "di":     UC_X86_REG_DI ,
                "ebp":    UC_X86_REG_EBP,
                "edx":    UC_X86_REG_EDX,
                "ebx":    UC_X86_REG_EBX,
                "cl":     UC_X86_REG_CL ,
                "ecx":    UC_X86_REG_ECX,
                "ch":     UC_X86_REG_CH ,
                "bp":     UC_X86_REG_BP ,
                "dl":     UC_X86_REG_DL ,
                "esp":    UC_X86_REG_ESP,
                "eiz":    UC_X86_REG_EIZ,
                "fpsw":   UC_X86_REG_FPSW,
                "bpl":    UC_X86_REG_BPL,
                "dh":     UC_X86_REG_DH ,
                "gs":     UC_X86_REG_GS ,
                "ax":     UC_X86_REG_AX ,
                "eflags": UC_X86_REG_EFLAGS,
                "ds":     UC_X86_REG_DS ,
                "es":     UC_X86_REG_ES ,
                "bx":     UC_X86_REG_BX ,
                "dx":     UC_X86_REG_DX ,
                "bl":     UC_X86_REG_BL ,
                "esi":    UC_X86_REG_ESI
            },        
            "arm" : {
                "r0":     UC_ARM_REG_R0,
                "r1":     UC_ARM_REG_R1,
                "r2":     UC_ARM_REG_R2,
                "r3":     UC_ARM_REG_R3,
                "r4":     UC_ARM_REG_R4,
                "r5":     UC_ARM_REG_R5,
                "r6":     UC_ARM_REG_R6,
                "r7":     UC_ARM_REG_R7,
                "r8":     UC_ARM_REG_R8,
                "r9":     UC_ARM_REG_R9,
                "r10":    UC_ARM_REG_R10,
                "r11":    UC_ARM_REG_R11,
                "r12":    UC_ARM_REG_R12,
                "pc":     UC_ARM_REG_PC,
                "sp":     UC_ARM_REG_SP,
                "lr":     UC_ARM_REG_LR,
                "cpsr":   UC_ARM_REG_CPSR
            },
            "arm64" : {
                "x0":     UC_ARM64_REG_X0,
                "x1":     UC_ARM64_REG_X1,
                "x2":     UC_ARM64_REG_X2,
                "x3":     UC_ARM64_REG_X3,
                "x4":     UC_ARM64_REG_X4,
                "x5":     UC_ARM64_REG_X5,
                "x6":     UC_ARM64_REG_X6,
                "x7":     UC_ARM64_REG_X7,
                "x8":     UC_ARM64_REG_X8,
                "x9":     UC_ARM64_REG_X9,
                "x10":    UC_ARM64_REG_X10,
                "x11":    UC_ARM64_REG_X11,
                "x12":    UC_ARM64_REG_X12,
                "x13":    UC_ARM64_REG_X13,
                "x14":    UC_ARM64_REG_X14,
                "x15":    UC_ARM64_REG_X15,
                "x16":    UC_ARM64_REG_X16,
                "x17":    UC_ARM64_REG_X17,
                "x18":    UC_ARM64_REG_X18,
                "x19":    UC_ARM64_REG_X19,
                "x20":    UC_ARM64_REG_X20,
                "x21":    UC_ARM64_REG_X21,
                "x22":    UC_ARM64_REG_X22,
                "x23":    UC_ARM64_REG_X23,
                "x24":    UC_ARM64_REG_X24,
                "x25":    UC_ARM64_REG_X25,
                "x26":    UC_ARM64_REG_X26,
                "x27":    UC_ARM64_REG_X27,
                "x28":    UC_ARM64_REG_X28,
                "pc":     UC_ARM64_REG_PC,
                "sp":     UC_ARM64_REG_SP,
                "fp":     UC_ARM64_REG_FP,
                "lr":     UC_ARM64_REG_LR,
                "nzcv":   UC_ARM64_REG_NZCV,
                "cpsr": UC_ARM_REG_CPSR, 
            },
            "mips" : {
                "0" :     UC_MIPS_REG_ZERO,
                "at":     UC_MIPS_REG_AT,
                "v0":     UC_MIPS_REG_V0,
                "v1":     UC_MIPS_REG_V1,
                "a0":     UC_MIPS_REG_A0,
                "a1":     UC_MIPS_REG_A1,
                "a2":     UC_MIPS_REG_A2,
                "a3":     UC_MIPS_REG_A3,
                "t0":     UC_MIPS_REG_T0,
                "t1":     UC_MIPS_REG_T1,
                "t2":     UC_MIPS_REG_T2,
                "t3":     UC_MIPS_REG_T3,
                "t4":     UC_MIPS_REG_T4,
                "t5":     UC_MIPS_REG_T5,
                "t6":     UC_MIPS_REG_T6,
                "t7":     UC_MIPS_REG_T7,
                "t8":     UC_MIPS_REG_T8,
                "t9":     UC_MIPS_REG_T9,
                "s0":     UC_MIPS_REG_S0,
                "s1":     UC_MIPS_REG_S1,
                "s2":     UC_MIPS_REG_S2,    
                "s3":     UC_MIPS_REG_S3,
                "s4":     UC_MIPS_REG_S4,
                "s5":     UC_MIPS_REG_S5,
                "s6":     UC_MIPS_REG_S6,              
                "s7":     UC_MIPS_REG_S7,
                "s8":     UC_MIPS_REG_S8,  
                "k0":     UC_MIPS_REG_K0,
                "k1":     UC_MIPS_REG_K1,
                "gp":     UC_MIPS_REG_GP,
                "pc":     UC_MIPS_REG_PC,
                "sp":     UC_MIPS_REG_SP,
                "fp":     UC_MIPS_REG_FP,
                "ra":     UC_MIPS_REG_RA,
                "hi":     UC_MIPS_REG_HI,
                "lo":     UC_MIPS_REG_LO
            }
        }
        return registers[arch]  

    def get_common_regs(self):
        """
        get some common register
        REG_PC: IP
        REG_SP: stack pointer 
        REG_RA: return address (just like arm $lr and mips $ra)
        REG_ARGS: args 
        REG_RES: return value
        arch to uc_arch
        """

        if self.uc_arch == UC_ARCH_X86:
            if self.uc_mode == UC_MODE_16:
                self.size = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_IP
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGS = []
            elif self.uc_mode == UC_MODE_32:
                self.size = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGS = []
            elif self.uc_mode == UC_MODE_64:
                self.size = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                                     UC_X86_REG_R8, UC_X86_REG_R9]
                    # print "test"
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        elif self.uc_arch == UC_ARCH_ARM:
            if self.uc_mode == UC_MODE_ARM:
                self.size = 4
                self.pack_fmt = '<I'
            elif self.uc_mode == UC_MODE_THUMB:
                self.size = 2
                self.pack_fmt = '<H'
            self.REG_PC = UC_ARM_REG_PC
            self.REG_SP = UC_ARM_REG_SP
            self.REG_RA = UC_ARM_REG_LR
            self.REG_RES = UC_ARM_REG_R0
            self.REG_ARGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        elif self.uc_arch == UC_ARCH_ARM64:
            self.size = 8
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        elif self.uc_arch == UC_ARCH_MIPS:
            self.size = 4
            self.pack_fmt = "<I"
            self.REG_PC = UC_MIPS_REG_PC
            self.REG_SP = UC_MIPS_REG_SP
            self.REG_RA = UC_MIPS_REG_RA
            self.REG_RES = [UC_MIPS_REG_V0, UC_MIPS_REG_V1,UC_MIPS_REG_V1]
            self.REG_ARGS = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3]