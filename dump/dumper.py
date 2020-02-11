
import datetime
import hashlib
import json
import os
import sys
import time
import zlib

# GDB Python SDK
import gdb

pwndbg_loaded = False

try:
    import pwndbg.arch
    import pwndbg.regs
    import pwndbg.vmmap
    import pwndbg.memory

    pwndbg_loaded = True

except ImportError:
    print('You need install pwndbg first')

MAX_SEG_SIZE = 128 * 1024 * 1024

# Name of the index file
INDEX_FILE_NAME = "_index.json"

class DumpPwndbgTarget():
    def __init__(self):
        self.arch_info = {}
        self.reg_state = {}

    def get_arch(self):
        """
        dump registers from pwndbg gdb api
        """
        arch = pwndbg.arch.current # from PWNDBG
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
            # check endianess 
            if pwndbg.arch.endian == 'big':
                # check for THUMB mode
                if (cpsr & (1 << 5)):
                    return "armbethumb"
                else:
                    return "armbe"
            else:
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
            return ""

    def get_endian(self):
        """
        get endian 
        """
        return pwndbg.arch.endian

    def get_all_regs(self):
        """
        Sometimes pwndbg can not dump all registers , this is a bug in pwndbg
        if arch is mips, you can not get register `gp` from pwndbg.regs.all
        """ 
        if self.arch_info['arch'] == 'mips':
            reg_gp = gdb.execute("info register gp" , to_string=True).strip("\n").split(":")
            print("ssss" , reg_gp)
            self.reg_state[reg_gp[0]] = int(reg_gp[1] , 16)

    def dump_regs(self):
        # reg_state = {}
        for reg in pwndbg.regs.all:
            reg_val = pwndbg.regs[reg]
            self.reg_state[reg.strip().strip('$')] = reg_val
        # return reg_state
        self.get_all_regs()


    def dump_arch_info(self):
        # arch_info = {}
        self.arch_info["arch"] = self.get_arch()
        self.arch_info['endian'] = self.get_endian()
        # return arch_info


    def dump_process_memory(self , output_dir):
        # Segment information dictionary
        final_segment_list = []
        
        # PWNDBG:
        vmmap = pwndbg.vmmap.get()
        
        # Pointer to end of last dumped memory segment
        segment_last_addr = 0x0;

        start = None
        end   = None

        if not vmmap:
            print("No address mapping information found")
            return  
        # print(vmmap)
        # Assume segment entries are sorted by start address
        for entry in vmmap:
            if entry.start == entry.end:
                continue

            start = entry.start
            end   = entry.end

            if (segment_last_addr > entry.start): # indicates overlap
                if (segment_last_addr > entry.end): # indicates complete overlap, so we skip the segment entirely
                    continue
                else:            
                    start = segment_last_addr
                
            
            seg_info = {'start': start, 'end': end, 'name': entry.objfile, 'permissions': {
                "r": entry.read,
                "w": entry.write,
                "x": entry.execute
            }, 'content_file': ''}

            # "(deleted)" may or may not be valid, but don't push it.
            if entry.read and not '(deleted)' in entry.objfile:
                try:
                    # Compress and dump the content to a file
                    seg_content = pwndbg.memory.read(start, end - start)
                    if(seg_content == None):
                        print("Segment empty: @0x{0:016x} (size:UNKNOWN) {1}".format(entry.start, entry.objfile))
                    else:
                        print("Dumping segment @0x{0:016x} (size:0x{1:x}): {2} [{3}]".format(entry.start, len(seg_content), entry.objfile, repr(seg_info['permissions'])))
                        compressed_seg_content = zlib.compress(seg_content)
                        md5_sum = hashlib.md5(compressed_seg_content).hexdigest() + ".bin"
                        seg_info["content_file"] = md5_sum
                        
                        # Write the compressed contents to disk
                        out_file = open(os.path.join(output_dir, md5_sum), 'wb')
                        out_file.write(compressed_seg_content)
                        out_file.close()

                except:
                    print("Exception reading segment ({}): {}".format(entry.objfile, sys.exc_info()[0]))
            else:
                print("Skipping segment {0}@0x{1:016x}".format(entry.objfile, entry.start))
            
            segment_last_addr = end

            # Add the segment to the list
            final_segment_list.append(seg_info)

        print(final_segment_list)
        return final_segment_list

    def start_dump(self):
        print("==============start dump==============")
        try:
            timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
            output_path = "UnicornContext_" + timestamp
            if not os.path.exists(output_path):
                os.makedirs(output_path)
            print("Process context will be output to {}".format(output_path))
            # Get the context
            self.dump_arch_info()
            self.dump_regs()
            context = {
                "arch": self.arch_info,
                "regs": self.reg_state, 
                "segments": self.dump_process_memory(output_path),
            }

            # Write the index file
            index_file = open(os.path.join(output_path, INDEX_FILE_NAME), 'w')
            index_file.write(json.dumps(context, indent=4))
            index_file.close()    
            print("Done.")
            
        except Exception as e:
            print("!!! ERROR:\n\t{}".format(repr(e)))
        

dumpTarget = DumpPwndbgTarget()
dumpTarget.start_dump()