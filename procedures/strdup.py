
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class strdup():
    def __init__(self , fc ,hc , call_num ,  enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug
        self.call_num = call_num
    def run(self ):
        print "strdup"
        src_addr  = self.fc.reg_read(self.hc.REG_ARGS[0])
        if self.enable_debug:
            print "src_addr : {}".format(hex(src_addr))
        src_str = self.fc.mem_read(src_addr , 0x400)
        print "src_str : {}".format(src_str)
        dest_str = 0x6000 + 1024 * 1024 * self.call_num
        print "call num : {}".format(self.call_num)
        self.fc.mem_map(dest_str , 1024 * 1024)
        self.fc.mem_write(dest_str , str(src_str))
        return dest_str