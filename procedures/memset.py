
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class memset():
    """
    memset(void *s,int ch,size_t n)
    """
    def __init__(self , fc, hc, enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug

    def run(self ):
        if self.fc.arch == "x32":
            # read args from stack
            return  1
        addr = self.fc.reg_read(self.hc.REG_ARGS[0])
        ch = self.fc.reg_read(self.hc.REG_ARGS[1])
        n =  self.fc.reg_read(self.hc.REG_ARGS[2])
        if ch is None:
            ch = ""
        if self.enable_debug:
            print "addr:{} ch:{} n:{}".format(hex(addr) , hex(ch) , hex(n))
        self.fc.mem_write( addr, chr(ch)*n )
        self.fc.reg_write( self.hc.REG_RES[0] , addr)
        if self.enable_debug:
            print "addr -->:{}".format(self.fc.mem_read(addr ,n))