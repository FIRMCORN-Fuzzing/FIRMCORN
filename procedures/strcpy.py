
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class strcpy():
    def __init__(self , fc ,hc , enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object

    def run(self ):
        print "strcpy"
        src_addr  = self.fc.reg_read(self.hc.REG_ARGS[0])
        src_str = self.fc.mem_read(src_addr , 0x10)
        dest_addr = self.fc.mem_map(0x60000  , 0x100)
        self.fc.mem_write(dest_addr ,str(src_str) )
        if self.enable_debug:
            print "src: {} ; dest: {}".format(hex(src_addr) , hex(dest_addr))
        if self.enable_debug:
            print "scanf buf: {}".format(self.fc.mem_read(0x7fffffffdb30,0x10) )
        self.fc.mem_write(dest_addr - len(str(src_str)) , str(src_str)) # stack isfrom high to low
        if self.enable_debug:
            print "check the stack: {}".format(self.fc.mem_read(self.fc.reg_read(self.hc.REG_SP) , self.hc.size) )
