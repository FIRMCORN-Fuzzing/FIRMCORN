import subprocess
import os 
import sys
import logging 
import json
from datetime import datetime

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *

CONTEXT_JSON = "_index.json"
class CrashLoader():
    def __init__(self  , fc ):
        self.fc = fc 

    def check_stack(self , uc , address , size , user_data):
        instr = mu.mem_read(address , size)

    def mem_crash_check(self, uc, access, address, size, value, user_data):
        print "   \033[1;31;40m >>>Crash!!!<<< Missing memory is being WRITE at {} \033[0m   ".format(hex(address))
        current_pc = uc.reg_read(self.fc.REG_PC , self.fc.size)
        print ">> pc: {}".format(hex(current_pc))
        self.fc.show_reg_value()
        self.fc.show_instrs()

    def crash_check_dbg(self, uc ,address , size , user_data):
        print "Memory fetech error : {}".format(hex(address)) 

    def crash_log(self):
        if not os.path.exists("outputs"):
            os.mkdir("outputs")
        tm = datetime.now().strftime("%Y%m%d_%H%M%S") + ".crash"
        fp = open("./outputs/" + tm , "w+")
        fp.write(self.fc.malformed_data)
        fp.close()

    def get_common_ret(self):
        if self.arch == "x64":
            self.RET_INTR = "\xC3"
        elif self.arch == "x86":
            self.RET_INTR = "\xC3"
        elif self.arch == "mips":
            self.RET_INTR = "\x03\xE0\x00\x08"
        elif self.arch == "arm":
            self.uc_arch = UC_ARCH_ARM
            self.uc_mode = UC_MODE_32
        else:
            raise Exception("Error arch")