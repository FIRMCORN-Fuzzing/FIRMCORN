import sys
import logging 
import os
import json
import ctypes
import ctypes.util
import zlib

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *
from unicorn.mips_const import *

sys.path.append('../')
from procedures import *


INPUT_BASE = 0x300000

class FuncEmu(object):
    """
    simulation of common function
    """ 
    def __init__(self , fc ,  hc , enable_debug=True):
        # pass
        self.fc = fc # firmcorn class, inherited from uc class
        self.hc = hc # hookcode class, inherited from object(this is not a good implementation...)
        self.debug_func = enable_debug
        self.func_list = {}
        self.func_list.update({ 'strcpy': self.strcpy })
        self.func_list.update({ 'scanf' : self.scanf })
        self.func_list.update({ 'memset': self.memset})
        self.func_list.update({ 'sprintf': self.sprintf})
        self.func_list.update({ 'strdup': self.strdup})
        self.func_list.update({ 'memmove': self.memmove})
        self.func_list.update({ 'memcpy': self.memcpy})
        self.func_list.update({ 'free': self.free})
        self.func_list.update({ 'snprintf': self.snprintf})
        self.func_list.update({ 'socket': self.socket})
        self.func_list.update({ 'fcntl': self.fcntl})
        self.func_list.update({ 'connect': self.connect})
        self.func_list.update({ 'send': self.send})
        self.func_list.update({ 'close': self.close})
        self.func_list.update({ 'getpid': self.getpid})
        self.func_list.update({ 'open': self.open_})
        self.func_list.update({ 'rand': self.rand_})
        self.strdup_call_num = 0

    def strcpy(self):
        strcpyEmu = strcpy(self.fc, self.hc)
        strcpyEmu.run()
    
    def scanf(self):
        scanfEmu = scanf(self.fc, self.hc)
        scanfEmu.run()
    
    def memset(self):
        memsetEmu = memset(self.fc, self.hc)
        memsetEmu.run()
    
    def sprintf(self):
        sprintfEmu = sprintf(self.fc, self.hc)
        sprintfEmu.run()

    def strdup(self):
        strdupEmu = strdup(self.fc, self.hc , self.strdup_call_num)
        self.strdup_call_num += 1
        return strdupEmu.run()

    def memmove(self):
        memmoveEmu = memmove(self.fc, self.hc)
        memmoveEmu.run()

    def memcpy(self):
        memcpyEmu = memcpy(self.fc, self.hc)
        memcpyEmu.run()

    def free(self):
        freeEmu = free(self.fc, self.hc)
        freeEmu.run()

    def snprintf(self):
        snprintfEmu = snprintf(self.fc, self.hc)
        snprintfEmu.run()

    def socket(self):
        socketEmu = socket(self.fc, self.hc)
        socketEmu.run()

    def fcntl(self):
        fcntlEmu = fcntl(self.fc, self.hc)
        fcntlEmu.run()

    def connect(self):
        connectEmu = connect(self.fc, self.hc)
        connectEmu.run()

    def send(self):
        connectEmu = send(self.fc, self.hc)
        connectEmu.run()

    def close(self):
        connectEmu = close(self.fc, self.hc)
        connectEmu.run()

    def getpid(self):
        getpidEmu = getpid(self.fc, self.hc)
        getpidEmu.run()

    def open_(self):
        open_Emu = open_(self.fc, self.hc)
        open_Emu.run()

    def rand_(self):
        rand_Emu = rand_(self.fc, self.hc)
        return rand_Emu.run()
