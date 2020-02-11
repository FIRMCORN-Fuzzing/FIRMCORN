
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class snprintf():
    """
    sprintf(char *string, char *format [,argument,...])
    """
    def __init__(self ,fc, hc, enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug

    def run(self ):
        print "snprintf"
        if self.fc.arch == "x32":
            return 1
        strings = self.fc.reg_read(self.hc.REG_ARGS[0])
        formats = self.fc.reg_read(self.hc.REG_ARGS[1])
        arg1 = self.fc.reg_read(self.hc.REG_ARGS[2])
        arg2 = self.fc.reg_read(self.hc.REG_ARGS[3])
        if self.enable_debug:
            print "strings: {} formats:{} arg1:{} arg2:{}".format(hex(strings), hex(formats), hex(arg1) , hex(arg2))    