from const import general_purpose_regs, dit_instrs, dit_simd_instrs
from util import find_line_for_addr
import re

#checks if an instruction is considered a "dit" instruction by arm
def is_dit(instruction, _):
    mnemonic = instruction.mnemonic
    if(mnemonic.upper() not in dit_instrs):
        return False

    return True

LD_ST_MNEMONICS = ["ldp", "ldr", "stp", "str", "strb", "ldrb"]

#returns a filter that passes loads and stores to/from a specific register
def gen_is_ld_st_from_reg(reg):
    def res(instruction, _):
        mnemonic = instruction.mnemonic
        if(mnemonic not in LD_ST_MNEMONICS):
            return False
        
        if(re.search(r"\["+reg+r", #-?(0x)?[0-9a-f]+\]!?$", instruction.op_str)):
            return True

        if(re.search(r"\["+reg+r"\], #-?(0x)?[0-9a-f]+$", instruction.op_str)):
            return True
        
        if(re.search(r"\["+reg+r"\]$", instruction.op_str)):
            return True
        
        return False
    return res

#checks if an instruction is a load/store from a static offset from the stack pointer
#these are never secret-dependent since the stack pointer is never moved to a secret-dependent location
is_ld_st_from_sp = gen_is_ld_st_from_reg("sp")
is_ld_st_from_x0 = gen_is_ld_st_from_reg("x0")

def is_ld_st_from_x0_in_fix_sprint(instruction, instructions):
    return instruction.function == "fix_sprint" and is_ld_st_from_x0(instruction, instructions)

FILTERS = [is_dit, is_ld_st_from_sp, is_ld_st_from_x0_in_fix_sprint]
def any_filter(instruction, instructions):
    for filter in FILTERS:
        if(filter(instruction, instructions)):
            return True
    return False