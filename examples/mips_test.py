import sys
sys.path.append('../') 

from firmcorn import *

fc = Firmcorn()
fc.load_context("./dir859/" , "cgibin" , "libc.so.0" )
run_start_addr = 0x0040F7DC
run_end_addr = 0x0040FE04  

seed = fc.rand_seed(0x100)
fuzz_target = Fuzzer(5 ,seed )
fc.add_fuzz(fuzz_target)

show_info_list = [0x040F918]
fc.show_debug_info(show_info_list)

trace_start_addr = 0x0040F7DC 
trace_end_addr = 0x0040FE04  
fc.set_trace(trace_start_addr, trace_end_addr )
fc.start_run(run_start_addr , run_end_addr )
