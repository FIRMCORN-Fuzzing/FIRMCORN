
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *
import random


class rand_():
    def __init__(self, fc ,hc , enable_debug=True):
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object
        self.enable_debug = enable_debug

    def run(self ):
        """
        rand
        """
        return random.randint(0,100000)