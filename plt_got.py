import sys
import json
import r2pipe

unique_addr = 8
pc_name = ""

def find_pc_register(r):
    global pc_name
    pc_name = [reg for reg in r.cmdj('arrj') if "role" in reg and reg["role"] == "PC"][0]["reg"]

def start_esil_at_addr(r, addr):
    r.cmd(f's {addr}')
    r.cmd('aeip; aeim')

def section_info(r, section_name):
    sections = r.cmdj('iSj')
    res = [section for section in sections if section['name'] == section_name]

    if len(res) < 0:
        print(f"Can't found {section_name}")
        sys.exit(2)

    return res[0]

def is_inside_section(section, addr):
    section_addr = section["vaddr"]
    section_size = section["size"]

    return addr >= section_addr and addr < section_addr + section_size

def select_got_relocs(relocs, got):
    return [reloc for reloc in relocs if is_inside_section(got, reloc["vaddr"])]

# We need a real function to get unique addr
def get_unique_addr():
    global unique_addr
    res = unique_addr
    unique_addr += 8

    return res

def patch_got_for_analysis(r, got_relocs):
    res = {}

    for reloc in got_relocs:
        addr = reloc["vaddr"]
        value = get_unique_addr()
        r.cmd(f'wv {value} @ {addr}')
        res[value] = addr

    return res

def get_pc_esil(r):
    return r.cmdj('aerj')[pc_name]

def resolve_plt_entrie(r, plt, info):
    start_addr = info['offset']
    start_esil_at_addr(r, start_addr)

    pc = start_addr

    while True:
        curr_instr = r.cmdj('pdj1')[0]
        next_pc_value = pc + curr_instr["size"]
        r.cmd('aes')
        tmp = get_pc_esil(r)

        # detect jump out of the plt
        if not is_inside_section(plt, tmp):
            break
        pc = tmp

    return get_pc_esil(r)

def plt_analysis(r, value_to_got):
    r.cmd('s section..plt') 

    plt = section_info(r, '.plt')
    plt_start = plt['vaddr']
    plt_end = plt_start + plt['vsize']

    pc = plt_start

    # plt_addr -> got_addr
    res = {}

    while pc < plt_end:
        r.cmd("af")
        info = r.cmdj("afij")

        if len(info) < 1:
            pc += r.cmdj('pdj1')[0]['size']
            r.cmd(f"s {pc}") 
            continue

        info = info[0]

        jmp_pc = resolve_plt_entrie(r, plt, info)

        if jmp_pc in value_to_got:
            res[pc] = value_to_got[jmp_pc]

        pc += info["realsz"]
        r.cmd(f"s {pc}") 

    return res

def fix_got_plt(r):
    relocs = r.cmdj('irj')
    # doesn't work if the .got section doesn't exist, we need to fix how we get the got addr
    got = section_info(r, '.got')
    got_relocs = select_got_relocs(relocs, got)

    value_to_got = patch_got_for_analysis(r, got_relocs)
    return plt_analysis(r, value_to_got)

def print_res(res):
    for key in res:
        print(f"{hex(key)} -> {hex(res[key])}")

def main():
    if len(sys.argv) < 2:
        print("Not enough arguments")
        sys.exit(1)

    filename = sys.argv[1]
    r = r2pipe.open(filename)

    # find the pc register
    find_pc_register(r)

    r.cmd('e io.pcache=true')
    res = fix_got_plt(r)
    print_res(res)

if __name__ == "__main__":
    main()
