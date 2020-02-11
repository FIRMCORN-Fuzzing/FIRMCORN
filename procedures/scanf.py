
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *


class scanf():
    def __init__(self, fc ,hc , enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug

    def run(self ):
        # maybe we have to think about all instruction
        # # need to be changed
        inputs_dir = "/home/b1ngo/Firmcorn/inputs/" 
        inputs_bin = "1.bin"
        inputs_file = open(inputs_dir + inputs_bin, "rb")
        inputs = inputs_file.read()
        inputs_file.close()
        fmt = self.fc.reg_read(self.hc.REG_ARGS[0])
        buf = self.fc.reg_read(self.hc.REG_ARGS[1])
        if self.enable_debug:
            print "fmt: {} ; buf : {:#x}".format(fmt , buf)
        self.fc.mem_write(buf , inputs)
        if self.enable_debug:
            print "scanf buf: {}".format(self.fc.mem_read(0x7fffffffdb30,0x10) )
        print "scanf compelte"