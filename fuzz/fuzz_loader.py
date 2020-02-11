import subprocess
import os 
import sys
import logging 
import os
import json
import ctypes
import ctypes.util
import zlib
from struct import unpack, pack, unpack_from, calcsize

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *

COMPILE_GCC = 1
COMPILE_MSVC = 2
INPUT_BASE = 0x300000

MAGIC = "^^^firm#"

class Fuzzer():
    def __init__(self  , seed ,datas , formats="not" , enable_debug = True):
        self.seed = seed
        self.datas =datas
        self.formats = formats
        self.fuzz_func_list = []
        self.enable_debug = enable_debug

    def init(self ,fc  , compiler=COMPILE_GCC):
        self.fc = fc 
        self.arch = self.fc.arch
        self.compiler = compiler
        self.get_common_regs() 

    def get_mutate_data(self):
        """ 
        mutation-based method
        """
        self.cmd = []
        self.cmd.append("radamsa")
        # self.cmd.append("--seed")
        # self.cmd.append(str(self.seed))
        self.cmd.append("-n")
        self.cmd.append("1")

        fuzz_data = subprocess.Popen(self.cmd , 
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
        fuzz_data_str = fuzz_data.communicate( self.datas )[0]

        if self.enable_debug == True:
            print fuzz_data_str
        return fuzz_data_str

    def get_generate_data(self):
        """
        generation-based method
        """
        pass

    def fuzz_func_alt_dbg(self , uc , address , size , user_data):
        """
        use for hijack function , like getenv , printf .etc
        """
        if address in self.fuzz_func_list:
            if self.enable_debug:
                print "function fuzz address : {}".format(hex(address))
                print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
            # 1 , get return address
            reg_sp = self.fc.reg_read(self.REG_SP)
            # we should get address value from stack
            if self.REG_RA == 0: 
                _value = str(self.fc.mem_read(reg_sp , self.size))
                ret_addr = unpack(self.pack_fmt , _value)[0]
            else:
                ret_addr = self.fc.reg_read(self.REG_RA)

            # 2. get malformed data 
            res = self.get_mutate_data() # get malformed data

            # 3. map a memory to store res_data
            res_addr = INPUT_BASE
            if self.enable_debug:
                print res_addr
                print type(res_addr)
            self.fc.mem_map(INPUT_BASE , 1024*1024)
            
            # 4. write res_data to res_addr
            self.fc.mem_write( INPUT_BASE , res)
            if self.enable_debug:
                print "get malformed data :{}".format(res)
                print "return addr : {}".format(hex(ret_addr))
            # 3. write malformed data to REG_RES and change REG_PC
            self.fc.reg_write(self.REG_RES , INPUT_BASE)
            self.fc.reg_write(self.REG_PC , ret_addr)
            if self.enable_debug:
                print "reg_res : {}".format( str(self.fc.mem_read(INPUT_BASE , self.size)))
                print "ret_addr : {}".format(str(self.fc.reg_read(self.REG_PC , self.size)))

    def find_magic_num(self, uc , address , size , user_data):
        if self.fc.mem_got.get(address) is not None or self.fc.rebase_got.get(address):
            #raw_input()
            for reg_arg in self.fc.REG_ARGS:
                reg_arg_value = self.fc.reg_read( reg_arg )
                try:
                    mem_value = self.fc.mem_read(reg_arg_value , 0x30)
                except:
                    continue
                if MAGIC in mem_value:
                    print "find magic : {}".format(mem_value)
                    print "magic function name : {}".format(self.fc.mem_got[address])
                    print "reg_arg_value : {}".format(hex(reg_arg_value))
                    malformed_data = self.get_mutate_data()
                    mem_value_new = mem_value.replace(MAGIC , malformed_data)
                    self.fc.malformed_data = mem_value_new
                    print "new data : {}".format(mem_value_new)
                    #raw_input()
                    self.fc.mem_write(reg_arg_value , str(mem_value_new))
                    print "write done"
                    break

    def get_common_regs(self):
        """
        get some common register
        REG_PC: IP
        REG_SP: stack pointer 
        REG_RA: return address (just like arm $lr and mips $ra)
        REG_ARGSS: args 
        REG_RES: return value
        arch to uc_arch
        """
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

        if self.uc_arch == UC_ARCH_X86:
            if self.uc_mode == UC_MODE_16:
                self.size = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_IP
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGSS = []
            elif self.uc_mode == UC_MODE_32:
                self.size = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGSS = []
            elif self.uc_mode == UC_MODE_64:
                self.size = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGSS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                                     UC_X86_REG_R8, UC_X86_REG_R9]
                    # print "test"
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGSS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
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
            self.REG_ARGSS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        elif self.uc_arch == UC_ARCH_ARM64:
            self.size = 8
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGSS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        elif self.uc_arch == UC_ARCH_MIPS:
            self.size = 8
            self.pack_fmt = "<I"
            self.REG_PC = UC_MIPS_REG_PC
            self.REG_SP = UC_MIPS_REG_SP
            self.REG_RA = UC_MIPS_REG_RA
            self.REG_RES = [UC_MIPS_REG_V0, UC_MIPS_REG_V1,UC_MIPS_REG_V1]
            self.REG_ARGSS = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3]

