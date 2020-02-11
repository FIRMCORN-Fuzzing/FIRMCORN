from pwn import *

archs = ['amd64','i386', 'arm',  'mips']


x64_ret = "ret"
x32_ret = "ret"
arm_ret = "BX LR"
mips_ret = "jr $ra"

print "x64_ret : {}".format(asm(x64_ret , arch="amd64").encode("hex"))

print "x32_ret : {}".format(asm(x32_ret , arch="i386").encode("hex"))

print "arm_ret : {}".format(asm(arm_ret , arch="arm").encode("hex"))

print "mips_ret : {}".format(asm(mips_ret , arch="mips").encode("hex"))