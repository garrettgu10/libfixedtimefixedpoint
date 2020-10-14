#!/usr/bin/python3
import sys
import json
from filters import *
from util import Instr, Line, get_function_code, get_lines_from_dwarf, find_line_for_addr 
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *

if __name__ == "__main__":
    filename = sys.argv[1]
    file = open(filename, "rb")
    elf = ELFFile(file)
    sections = list(elf.iter_sections())
    text_section = [s for s in sections if s.name == ".text"][0]
    symbol_tables = [s for s in sections if isinstance(s, SymbolTableSection)]
    dynsym = [s for s in symbol_tables if s.name == ".dynsym"][0]
    functions = [sym for _, sym in enumerate(dynsym.iter_symbols()) if sym['st_info']['type'] == "STT_FUNC" and sym.name[:4] == "fix_"]

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

    print([str(i) for i in instructions if not any_filter(i, instructions)])
    
    output = open("output.txt", "w")
    output.write(json.dumps([judge_instr(instruction, instructions, lines) for instruction in instructions], indent=4))
    output.close()
    
