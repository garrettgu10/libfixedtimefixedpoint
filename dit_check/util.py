from bisect import bisect_left

class Instr(object):
    def __init__(self, function, addr, mnemonic, op_str):
        self.function = function
        self.addr = addr
        self.mnemonic = mnemonic
        self.op_str = op_str
    def __str__(self):
        return f'{self.function}@{hex(self.addr)}: {self.mnemonic} {self.op_str}'

class Line(object):
    def __init__(self, filename, lineno, addr):
        self.filename = filename
        self.lineno = lineno
        self.addr = addr
    def __str__(self):
        return f'{self.filename}:{self.lineno}({hex(self.addr)})'

def get_function_code(text_section, function):
    begin_idx = function['st_value'] - text_section['sh_offset']
    end_idx = begin_idx + function['st_size']
    return text_section.data()[begin_idx:end_idx]

def get_lines_from_cu(dwarf, cu):
    res = []
    lineprogram = dwarf.line_program_for_CU(cu)
    for entry in lineprogram.get_entries():
        state = entry.state
        if state is not None:
            res += [Line(lineprogram['file_entry'][state.file-1].name.decode('utf-8'), state.line, state.address)]
    return res

def get_lines_from_dwarf(dwarf):
    res = []
    for cu in dwarf.iter_CUs():
        res += get_lines_from_cu(dwarf, cu)
    return sorted(res, key=lambda l: l.addr)

def find_line_for_addr(lines, addr):
    exact_matches = [l for l in filter(lambda line: line.addr == addr, lines)]
    if(len(exact_matches) != 0):
        return exact_matches
    addrs = [l.addr for l in lines]
    return [lines[bisect_left(addrs, addr) - 1]]