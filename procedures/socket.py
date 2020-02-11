
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class socket():
    """
    socket 
    """
    def __init__(self ,fc, hc, enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug

    def run(self ):
        # not implement 
        print "socket"
        arg1 = self.fc.reg_read(self.hc.REG_ARGS[0])
        arg2 = self.fc.reg_read(self.hc.REG_ARGS[1])
        arg3 = self.fc.reg_read(self.hc.REG_ARGS[2])
        if self.enable_debug:
            print "arg1: {} arg2:{} arg3:{}".format(hex(arg1), hex(arg2), hex(arg3))