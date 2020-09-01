import os
import sys
import r2pipe

unique_addr = 8
pc_name = ""


def find_pc_register_name(r):
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

    return section_addr <= addr < section_addr + section_size


def is_inside_section_without_start(section, addr):
    section_addr = section["vaddr"]
    section_size = section["size"]

    return section_addr < addr < section_addr + section_size


def get_pc_esil(r):
    return r.cmdj('aerj')[pc_name]


def resolve_plt_entrie(r, plt, start_addr):
    start_esil_at_addr(r, start_addr)

    while True:
        r.cmd('aes')
        tmp = get_pc_esil(r)

        # detect jump out of the plt
        if not is_inside_section_without_start(plt, tmp):
            break

    return get_pc_esil(r)


# source https://github.com/haystack-ia/radare-funhouse/blob/master/plt_fixup.py
def get_plt_stubs(r, plt):
    r.cmd('aaf')
    clear_screen()
    all_functions = r.cmdj('aflj')

    return [func for func in all_functions if is_inside_section_without_start(plt, func['offset'])]


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


def get_patched_got_relocs(r):
    # doesn't work if the .got section doesn't exist, we need to fix how we get the got addr
    got = section_info(r, '.got')

    all_relocs = r.cmdj('irj')
    got_relocs = select_got_relocs(all_relocs, got)
    return patch_got_for_analysis(r, got_relocs)


def plt_analyis(r):
    # get a hash table that associate an unique id to a got addr
    id_to_got_addr = get_patched_got_relocs(r)

    plt = section_info(r, '.plt')
    plt_stubs = get_plt_stubs(r, plt)

    # plt_addr -> got_addr
    res = {}

    for stub in plt_stubs:
        stub_addr = stub['offset']

        stub_jump_addr = resolve_plt_entrie(r, plt, stub_addr)
        if stub_jump_addr in id_to_got_addr:
            res[stub_addr] = id_to_got_addr[stub_jump_addr]
        else:
            print(f"WARNING: {hex(stub_addr)}")

    return res


def parse_args():
    if len(sys.argv) < 2:
        print("Not enough arguments")
        sys.exit(1)

    filename = sys.argv[1]
    return r2pipe.open(filename)


def init(r):
    r.cmd('e io.pcache=true')
    find_pc_register_name(r)


def clear_screen():
    os.system('clear')


def print_res(res):
    for key in res:
        print(f"{hex(key)} -> {hex(res[key])}")


def dump_result(result):
    clear_screen()
    print_res(result)


def main():
    r = parse_args()
    init(r)

    res = plt_analyis(r)
    dump_result(res)


if __name__ == "__main__":
    main()
