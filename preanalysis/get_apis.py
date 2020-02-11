import idaapi
import idautils
import idc
from sets import Set
import logging


def get_apis(func_addr):
        calls = 0
        apis = []
        flags = GetFunctionFlags(func_addr)
        # ignore library functions
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            logging.debug("get_apis: Library code or thunk")
            return None
        # list of addresses
        dism_addr = list(FuncItems(func_addr))
        for instr in dism_addr:
            tmp_api_address = ""
            if idaapi.is_call_insn(instr):
                # In theory an API address should only have one xrefs
                # The xrefs approach was used because I could not find how to
                # get the API name by address.
                for xref in XrefsFrom(instr, idaapi.XREF_FAR):
                    if xref.to == None:
                        calls += 1
                        continue
                    tmp_api_address = xref.to
                    break
                # get next instr since api address could not be found
                if tmp_api_address == "":
                    calls += 1
                    continue
                api_flags = GetFunctionFlags(tmp_api_address)
                print GetFunctionName(tmp_api_address)
                tmp_api_name = GetFunctionName(tmp_api_address)
                apis.append(tmp_api_name)
                # check for lib code (api)
        return (calls, apis)