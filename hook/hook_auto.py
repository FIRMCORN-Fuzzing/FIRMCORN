import sys
import logging 
import os
import json
from pwn import *

from func_emu import *
from hook_auto import *

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class HookAuto():
    """
    heuristic method
    """
    def __init__(self , fc , hc):
        self.fc = fc 
        self.hc = hc
        self.last_func = ""

    def record_last_func(self , uc , address , size , user_data):
        # if self.fc.mem_got
        if self.fc.mem_got.get(address) and self.fc.rebase_got.get(self.fc.mem_got[address]):
            self.last_func = self.fc.mem_got[address]

    def find_unresolved_func(self, uc, access, address, size, value, user_data):
        self.fc.unresolved_funcs.append(self.last_func)
        print "find unresolved func : {}".format(self.last_func)


    def func_alt_auto_libc(self , uc, address , size , user_data):
        if self.fc.mem_got.get(address) is not None and self.fc.rebase_got.get( self.fc.mem_got[address] ) is not None:
            print "find got table func : {} --> {}".format(hex(address) , self.fc.mem_got[address]) 
            # determaine if it has beed replaced 
            if self.fc.reg_read(self.fc.REG_PC) != self.fc.rebase_got[ self.fc.mem_got[address] ]: 
                if self.fc.rebase_got.get(self.fc.mem_got[address]):
                    print "find libc func : {} --> {}".format(hex(self.fc.rebase_got[ self.fc.mem_got[address] ]) , self.fc.mem_got[address] )
                    self.fc.reg_write(self.fc.REG_PC , self.fc.rebase_got[ self.fc.mem_got[address] ])
                    raw_input()

    def func_alt_auto(self, uc , address , size , user_data):
        instr = uc.mem_read(address , size)
        if self.fc.mem_got.has_key(address):
            print "find func : {} --> {}".format(hex(address) , self.fc.mem_got[address])
            if self.funcemu.func_list.has_key(self.fc.mem_got[address]):
                print "custom func {}##############################################".format(self.fc.mem_got[address])
                #fc.hookcode.func_alt(memset_addr2 , fc.funcemu.memset  , 2)
                self.func_alt( address , self.funcemu.func_list[self.fc.mem_got[address]]  , 2)
                if self.func_alt_addr is not None:
                    self.fc.hook_add(UC_HOOK_CODE , self._func_alt) 
                    # reg_sp = self.fc.reg_read(self.REG_SP)
                    # # we should get address value from stack
                    # if self.REG_RA == 0: 
                    #     ret_addr = unpack(self.pack_fmt , str(self.fc.mem_read(reg_sp , self.size)))[0]
                    # else:
                    #     ret_addr = self.fc.reg_read(self.REG_RA)