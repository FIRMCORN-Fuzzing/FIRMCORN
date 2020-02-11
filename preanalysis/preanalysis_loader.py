import idaapi
import idautils
import idc
from sets import Set
import logging
import os
import math


SENSITIVE_FUNC_LIST = ['strcpy','strcat','read','scanf','gets','read','gets','system','execve','getenv' , 'sprintf' , 'tcapi_set'] 

class PreanalysisTarget():
    def __init__(self , enable_debug=False):
        self.complex_sort_dict = dict()
        self.vuln_sort_dict = dict()
        self.enable_debug = enable_debug
        # fileName = idc.AskFile(1, "*.*", "Search Vulnerability Code")
        # baseName = idc.GetInputFile()
        self.funcs  = idautils.Functions()
        self.arch = self.get_arch()

    def search_vuln_code(self):
        pass

    def complex_sort(self  ):
        # stage 1 sorting
        stage1_dict = dict()
        for func in  self.funcs:
            stage1_list = []
            # get  cyclomatic complexity & xref_num
            xref_num = self.get_xref_num(func)
            cyc_complex_num = self.get_cyclomatic_complexity(func)
            # if xref_num==0:
            #     if self.enable_debug:
            #         print "ignore this function : {} --> {}".format(hex(func) , GetFunctionName(func))
            #     continue
            stage1_list.append(cyc_complex_num)
            stage1_list.append(xref_num)   
            complex_rate = int(cyc_complex_num * math.log(cyc_complex_num)) + xref_num
            if complex_rate == 0:
                print "Complex Rate 0 function : {} --> {}".format(hex(func) , GetFunctionName(func))
                # continue
            stage1_dict.update( {func:complex_rate})
        list_tmp = []
        for k,v in stage1_dict.items():
            if v in self.complex_sort_dict:
                self.complex_sort_dict[v].append(k)
            else:
                self.complex_sort_dict[v] = [k]
        print self.complex_sort_dict # test 

    def get_cyclomatic_complexity(self , func_ea):
        f_start = func_ea
        f_end = FindFuncEnd(func_ea)
        edges = Set()
        boundaries = Set((f_start,))

        for head in Heads(f_start, f_end):
            # If the element is an instruction
            if isCode(GetFlags(head)):
                refs = CodeRefsFrom(head, 0)
                refs = Set(filter(lambda x: x>=f_start and x<=f_end, refs))
                if refs:
                    next_head = NextHead(head, f_end)
                    if isFlow(GetFlags(next_head)):
                        refs.add(next_head)
                    # Update the boundaries found so far.
                    boundaries.union_update(refs)
                    for r in refs:
                        if isFlow(GetFlags(r)):
                            edges.add((PrevHead(r, f_start), r))
                        edges.add((head, r))
        return len(edges) - len(boundaries) + 2


    def get_xref_num(self , func_ea):
        xref_num = 0
        for xref_ea  in CodeRefsTo(func_ea , 0):
            # print analysis result 
            caller_name = GetFunctionName(xref_ea)
            xref_num += 1
        return xref_num

    def vuln_sort(self):
        """
        stage 2 sorting
        stage1 dict format: {rate1 : [ea1 , ea2 , ...] , rate2 : [ea1 ,ea2 ..] ...}
        stage2 dict format: {rate1 : [{ea1_rate1 : ea1 } , {ea1_rate2 : ea2 } ..] , rate2: [ {ea1_rate1: ea1 }, {ea1_rate2: ea2 } ]}  
        """
        for k,v in self.complex_sort_dict.items():
            each_rate_list = []
            for i in range(len(v)):
                tmp = []
                sensitive_index = self.get_sensitive_index(v[i]) # each v[i] is func_ea 
                memop_num = self.get_memop_num(v[i])
                vuln_rate = sensitive_index + memop_num
                if vuln_rate == 0:
                    print "Vuln Rate 0 function : {} --> {}".format(hex(v[i]) , GetFunctionName(v[i]))
                    # continue
                tmp.append(sensitive_index)
                tmp.append(memop_num)
                tmp.append(v[i])
                each_rate_list.append({vuln_rate:tmp})
            self.vuln_sort_dict.update({k:each_rate_list})
        for k in self.vuln_sort_dict:
            self.vuln_sort_dict[k].sort(reverse=True)
        self.vuln_sort_dict = [ (k , self.vuln_sort_dict[k]) for k in sorted(self.vuln_sort_dict.keys())]
        # for k in self.vuln_sort_dict:
        #     print k
        print self.vuln_sort_dict
        return self.vuln_sort_dict 

    def vuln_sort_show(self):
        """
        stage 2 sorting
        stage1 dict format: {rate1 : [ea1 , ea2 , ...] , rate2 : [ea1 ,ea2 ..] ...}
        stage2 dict format: {rate1 : [{ea1_rate1 : ea1 } , {ea1_rate2 : ea2 } ..] , rate2: [ {ea1_rate1: ea1 }, {ea1_rate2: ea2 } ]}  
        """
        for k,v in self.complex_sort_dict.items():
            each_rate_list = []
            for i in range(len(v)):
                tmp = []
                sensitive_index = self.get_sensitive_index(v[i]) # each v[i] is func_ea 
                memop_num = self.get_memop_num(v[i])
                vuln_rate = sensitive_index + memop_num
                if vuln_rate == 0:
                    continue
                each_rate_list.append( vuln_rate )
            self.vuln_sort_dict.update({k:each_rate_list})
        for k in self.vuln_sort_dict:
            self.vuln_sort_dict[k].sort(reverse=True)
        # self.vuln_sort_dict = [ (k , self.vuln_sort_dict[k]) for k in sorted(self.vuln_sort_dict.keys())]
        # for k in self.vuln_sort_dict:
        #     print k
        print self.vuln_sort_dict
        return self.vuln_sort_dict 

    def get_sensitive_index(self , func_ea):
        indexs = 0
        func_name = GetFunctionName(func_ea)
        func_apis = self.get_apis(func_ea)
        if func_apis is not None and self.enable_debug:
            print "func {} apis : {}".format(func_name , func_apis)
        for sub_func in func_apis:
            for func in SENSITIVE_FUNC_LIST:
                if func == sub_func:
                    if self.enable_debug:
                        print "find sensitive func: {}".format(sub_func)
                    indexs += 10    
                else:
                    continue
        return indexs

    def get_apis(self , func_ea):
        calls = 0
        apis = []
        flags = GetFunctionFlags(func_ea)
        dism_addr = list(FuncItems(func_ea))
        for instr in dism_addr:
            tmp_api_address = ""
            if idaapi.is_call_insn(instr):
                for xref in XrefsFrom(instr, idaapi.XREF_FAR):
                    if xref.to == None:
                        calls += 1
                        continue
                    tmp_api_address = xref.to
                    break
                if tmp_api_address == "":
                    calls += 1
                    continue
                api_flags = GetFunctionFlags(tmp_api_address)
                # print GetFunctionName(tmp_api_address)
                tmp_api_name = GetFunctionName(tmp_api_address)
                apis.append(tmp_api_name)
        return apis


    def get_memop_num(self ,func_ea):
        """
        memop_num / allop_num
        """
        memop_num = 0.0
        allop_num = 0 
        dism_addr = list(FuncItems(func_ea))
        for instr in dism_addr:
            allop_num  += 1
            op = GetOpType(instr, 0) 
            # print op
            dism_instr = GetDisasm(instr)
            # need to distinguish arch
            # print self.arch[0]
            # raw_input()
            # print dism_addr
            if self.arch[0] == "metapc":
                # x86 arch 
                if op == 4 and "mov"  in dism_instr:
                    memop_num += 1
                    # print "0x{} {}".format(hex(instr), dism_instr)
            elif self.arch[0] == "mips" or  self.arch[0] == "mipsb"  or  self.arch[0] == "mipsl" :
                if op == 1 and ("sw"  in dism_instr or "lw"  in dism_instr or  "sb"  in dism_instr or "lb"  in dism_instr ):
                    memop_num += 1
                    # print "0x{} {}".format(hex(instr), dism_instr)
            elif self.arch[0] == "ARM" :
                # print dism_addr
                if op == 1 and ("STR" in dism_instr or "STRH" in dism_instr or "STRB" in dism_instr):
                    # pass
                    memop_num += 1
                    # print dism_instr
            else:
                print "unknow arch"
        # print "memop_num: {}   all_op_num{} , rate: {} ".format(memop_num , allop_num,  int((float(memop_num) / float(allop_num)) * 100))
        return int(( memop_num / len(dism_addr) )* 10.0)

    def get_arch(self):
        arch_list = []
        info = idaapi.get_inf_structure()
        arch_list.append(info.procName)
        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16
        try:
            is_be = info.is_be()
        except:
            is_be = info.mf
        endian = "big" if is_be else "little"
        arch_list.append(bits)
        arch_list.append(endian)
        return arch_list
        # print arch_list


target = PreanalysisTarget()
print "==============================Complex Sort=============================="
target.complex_sort()
print "==========================Vulnerability Sort============================"
# target.vuln_sort()
target.vuln_sort_show()