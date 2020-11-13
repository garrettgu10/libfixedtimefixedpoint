from const import general_purpose_regs, dit_instrs, dit_simd_instrs
from util import find_line_for_addr
import re

#checks if an instruction is considered a "dit" instruction by arm
def is_dit(instruction, _):
    op_str = instruction.op_str
    mnemonic = instruction.mnemonic
    if(op_str == '' or op_str.split(",")[0].upper() in general_purpose_regs):
        if(mnemonic.upper() not in dit_instrs):
            return False
    elif(mnemonic.upper() not in dit_simd_instrs):
        return False
    
    return True

#checks if an instruction is a load/store from a static offset from the stack pointer
#these are never secret-dependent since the stack pointer is never moved to a secret-dependent location
def is_ld_st_from_sp(instruction, _):
    mnemonic = instruction.mnemonic
    if(mnemonic not in ["ldp", "ldr", "stp", "str", "strb", "ldrb"]):
        return False
    
    if(re.search(r"\[sp, #-?(0x)?[0-9a-f]+\]!?$", instruction.op_str)):
        return True

    if(re.search(r"\[sp\], #-?(0x)?[0-9a-f]+$", instruction.op_str)):
        return True
    
    if(re.search(r"\[sp\]$", instruction.op_str)):
        return True
    
    return False

#checks if an instruction is an ADRP
#since this is essentially a load immediate for an address, this is not secret-dependent
def is_adrp(instruction, _):
    return instruction.mnemonic == "adrp"

#checks if an instruction is a global load or store
#this is defined by a load or store to/from a location relative to a register immediately following an adrp
#we know this is a load at a fixed offset because we have eliminated function calls
def is_global_ld_st(instruction, instructions):
    if(instruction.mnemonic not in ["ldp", "ldr", "stp", "str", "strb", "ldrb"]):
        return False
    
    match = re.search(r"\[(x\d+)", instruction.op_str)
    if(not match):
        raise Exception("Unexpected instruction format: " + str(instruction))
    
    addr_reg = match.group(1)
    
    prev_addr = instruction.addr - 4
    prev_instr = [i for i in instructions if i.addr == prev_addr][0]
    if(prev_instr.mnemonic == "adrp" and prev_instr.op_str.find(addr_reg) != -1):
        return True
    return False

FILTERS = [is_dit, is_ld_st_from_sp, is_adrp, is_global_ld_st]
def any_filter(instruction, instructions):
    for filter in FILTERS:
        if(filter(instruction, instructions)):
            return True
    return False

def judge_instr(instruction, instructions, lines):
    reason = None
    for filter in FILTERS:
        if(filter(instruction, instructions)):
            reason = filter.__name__
            break
    
    if reason == None:
        print(str(instruction))
        print([str(l) for l in find_line_for_addr(lines, instruction.addr)])
        inp = None
        while(inp != "y" and inp != "n"):
            inp = input("Is the timing of this instruction secret-independent? (y/n) ")
        if(inp == "y"):
            reason = "manual: " + input("Why? ")

    return {
        "instruction": str(instruction),
        "location": str(find_line_for_addr(lines, instruction.addr)[0]),
        "valid": reason != None,
        "reason": reason
    }