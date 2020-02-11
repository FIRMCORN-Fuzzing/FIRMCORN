import os
import subprocess
import pygdbmi.gdbcontroller
import pdb
import logging


logging.basicConfig(level=logging.INFO)

GDB_PORT = 1236

gdb_executable = "gdb"
gdb_args = []
gdbserver =subprocess.Popen(['gdbserver' , '127.0.0.1:1239' , './t1'],
                            stdout = subprocess.PIPE, 
                            stdin = subprocess.PIPE, 
                            stderr=subprocess.STDOUT)


response = gdbserver.stdout.readline().strip()
print "sub process output: ", response
proc_pid = response[response.find("pid = ")+6:]
gdbmi_ = pygdbmi.gdbcontroller.GdbController()
response = gdbmi_.write('target remote localhost:1239')
response = gdbmi_.write('b *main') # B *addr
response = gdbmi_.write('c') 

def get_all_regs(arch):
    all_arch_registers = {
        "x64" : [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rip",
            "rsp",
            "efl",
            "cs",
            "ds",
            "es",
            "fs",
            "gs",
            "ss",
        ],
        "x86" : [
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "eip",
            "esp",
            "efl"  
        ],        
        "arm" : [
            "r0",
            "r1",
            "r2",
            "r3",
            "r4",
            "r5",
            "r6",
            "r7",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "pc",
            "sp",
            "lr",
            "cpsr"
        ],
        "arm64" : [
            "x0",
            "x1",
            "x2",
            "x3",
            "x4",
            "x5",
            "x6",
            "x7",
            "x8",
            "x9",
            "x10",
            "x11",
            "x12",
            "x13",
            "x14",
            "x15",
            "x16",
            "x17",
            "x18",
            "x19",
            "x20",
            "x21",
            "x22",
            "x23",
            "x24",
            "x25",
            "x26",
            "x27",
            "x28",
            "pc",
            "sp",
            "fp",
            "lr",
            "nzcv",
            "cpsr"
        ],
        "mips" : [
            "0" ,
            "at",
            "v0",
            "v1",
            "a0",
            "a1",
            "a2",
            "a3",
            "t0",
            "t1",
            "t2",
            "t3",
            "t4",
            "t5",
            "t6",
            "t7",
            "t8",
            "t9",
            "s0",
            "s1",
            "s2",
            "s3",
            "s4",
            "s5",
            "s6",
            "s7",
            "s8",
            "k0",
            "k1",
            "gp",
            "pc",
            "sp",
            "fp",
            "ra",
            "hi",
            "lo"
        ]
    }
    logging.info(type(all_arch_registers))
    registers = all_arch_registers[arch]
    return registers


def dump_arch_info(gdbmi):
    response = gdbmi.write("show architecture")
    for dict_ in range(len(response)):
        print dict_
        arch = response[dict_]['payload']
        if 'x86_64' in arch or 'x86-64' in arch:
            return "x64"
        elif 'x86' in arch or 'i386' in arch:
            return "x86"
        elif 'aarch64' in arch or 'arm64' in arch:
            return "arm64le"
        elif 'aarch64_be' in arch:
            return "arm64be"
        elif 'arm' in arch:
            cpsr = pwndbg.regs['cpsr']
            if pwndbg.arch.endian == 'big':
                # check for THUMB mode
                if (cpsr & (1 << 5)):
                    return "armbethumb"
                else:
                    return "armbe"
                # check for THUMB mode
                if (cpsr & (1 << 5)):
                    return "armlethumb"
                else:
                    return "armle"
        elif 'mips' in arch:
            if pwndbg.arch.endian == 'little':
                return 'mipsel'
            else:
                return 'mips'
        else:
            continue
    return ""


def dump_regs(gdbmi , arch):
    reg_state = {}
    regs = get_all_regs(arch)
    print len(regs)
    for reg in regs:
        response = gdbmi.write("info register {}".format(reg))
        for dict_ in range(len(response)):
            payload = response[dict_]['payload']
            if payload is not None:
                if reg in payload and "Invalid register"  not in payload \
                    and "info register" not in payload :
                    reg_state[reg] = int(payload.replace(" ", "").replace(reg , ""), 16)
    logging.info(reg_state)
    return reg_state

def dump_process_memory(gdbmi ):
    final_segment_list = []
    response = gdbmi.write("info proc mappings")
    # print response
    proc_maps = subprocess.Popen(['cat' , '/proc/{}/maps'.format(proc_pid)],
                                stdout = subprocess.PIPE, 
                                stdin  = subprocess.PIPE, 
                                stderr = subprocess.STDOUT)

    while proc_maps.stdout.readline() != "":
        seg_info = proc_maps.stdout.readline().strip()





arch =  dump_arch_info(gdbmi_)
print arch
dump_regs(gdbmi_ , arch)
dump_process_memory(gdbmi_)
# response = gdbmi_.write("info registers") # hahhaha




