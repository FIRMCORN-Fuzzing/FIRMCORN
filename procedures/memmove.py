
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class memmove():
    def __init__(self , fc ,hc , enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug

    def run(self ):
        print "memmove"
        src_addr = self.fc.reg_read(self.hc.REG_ARGS[0])
        dest_addr = self.fc.reg_read(self.hc.REG_ARGS[1])
        n =  self.fc.reg_read(self.hc.REG_ARGS[2])
        src_str = self.fc.mem_read(src_addr , n)
        if self.enable_debug:
            print "src_addr : {} dest_addr : {} n : {}".format(hex(src_addr) , hex(dest_addr), n )
            print "src_str : {}".format(str(src_str))
        self.fc.mem_write(dest_addr ,str(src_str)) 
