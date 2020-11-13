#!/usr/bin/python3
import sys
import json
from filters import *
from util import Instr, Line, get_function_code, get_lines_from_dwarf, find_line_for_addr 
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *

EXCLUDED_FUNCS = [
    'fix_sprint', #timing is not independent from inputs since "buffer" is an input
    'fix_print', #calls libc function, info leakage is inevitable
    'fix_println' #ditto
]

if __name__ == "__main__":
    filename = sys.argv[1]
    file = open(filename, "rb")
    elf = ELFFile(file)
    sections = list(elf.iter_sections())
    text_section = [s for s in sections if s.name == ".text"][0]
    symbol_tables = [s for s in sections if isinstance(s, SymbolTableSection)]
    dynsym = [s for s in symbol_tables if s.name == ".dynsym"][0]
    functions = [sym for _, sym in enumerate(dynsym.iter_symbols()) if sym['st_info']['type'] == "STT_FUNC" and sym.name[:4] == "fix_" and sym.name not in EXCLUDED_FUNCS]

    instructions = []

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for function in functions:
        code = get_function_code(text_section, function)
        
        instrs = [i for i in md.disasm_lite(code, function['st_value'])]
        
        if(len(instrs) != len(code) / 4): 
            print("invalid disassembly for " + function.name)
            continue
        
        for (addr, size, mnemonic, op_str) in instrs:
            instructions += [Instr(function.name, addr, mnemonic, op_str)]
    
    dwarf = elf.get_dwarf_info()
    lines = get_lines_from_dwarf(dwarf)

    print("checked functions", [f.name for f in functions])

    bad_instrs = [str(i) for i in instructions if not any_filter(i, instructions)]

    if(len(bad_instrs) != 0):
        print(bad_instrs)
        exit(1)

    print("check was successful, these functions are DIT")