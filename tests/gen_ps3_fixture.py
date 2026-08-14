# Generates a synthetic big-endian ELF64 fixture shaped like a PS3
# executable: a .text-like PT_LOAD segment and a separate .opd-like
# PT_LOAD segment holding the entry function's descriptor, with e_entry
# pointing at the descriptor (not at code) -- the PPC64 ELFv1 convention.
# Purely synthetic, for testing toc.hpp; not a real game file.
import struct

def make_ps3_fixture():
    e_ident = bytes([0x7F, ord('E'), ord('L'), ord('F'), 2, 2, 1, 0]) + b'\x00' * 8
    ehsize, phentsize, shentsize = 64, 56, 64
    phnum, shnum = 2, 1

    phoff = ehsize
    phdr_table_size = phentsize * phnum
    text_data_off = phoff + phdr_table_size
    text_data = b"\x60\x00\x00\x00" * 8  # 8 nops, 32 bytes -- stand-in for real code

    TEXT_VADDR = 0x10000
    CODE_ENTRY_OFFSET_IN_TEXT = 8  # "real" code entry is 8 bytes into the segment
    CODE_ENTRY_VADDR = TEXT_VADDR + CODE_ENTRY_OFFSET_IN_TEXT

    opd_data_off = text_data_off + len(text_data)
    OPD_VADDR = 0x20000
    TOC_VALUE = 0x30000
    opd_descriptor = struct.pack(">QQQ", CODE_ENTRY_VADDR, TOC_VALUE, 0)  # code, toc, env

    shoff = opd_data_off + len(opd_descriptor)

    e_type, e_machine, e_version = 2, 21, 1  # ET_EXEC, EM_PPC64
    e_entry = OPD_VADDR  # <-- points at the descriptor, NOT at code
    e_flags = 0
    e_shstrndx = 0

    ehdr = e_ident + struct.pack(">HHIQQQIHHHHHH",
        e_type, e_machine, e_version, e_entry, phoff, shoff,
        e_flags, ehsize, phentsize, phnum, shentsize, shnum, e_shstrndx)
    assert len(ehdr) == 64

    def phdr(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align=0x10):
        return struct.pack(">IIQQQQQQ", p_type, p_flags, p_offset, p_vaddr, p_vaddr, p_filesz, p_memsz, p_align)

    phdr_text = phdr(1, 5, text_data_off, TEXT_VADDR, len(text_data), len(text_data))       # PT_LOAD, R|X
    phdr_opd  = phdr(1, 6, opd_data_off,  OPD_VADDR,  len(opd_descriptor), len(opd_descriptor))  # PT_LOAD, R|W

    def shdr(name, stype, flags, addr, offset, size, link=0, info=0, align=0, entsize=0):
        return struct.pack(">IIQQQQIIQQ", name, stype, flags, addr, offset, size, link, info, align, entsize)
    sh_null = shdr(0, 0, 0, 0, 0, 0)

    blob = ehdr + phdr_text + phdr_opd + text_data + opd_descriptor + sh_null
    return blob, {"CODE_ENTRY_VADDR": CODE_ENTRY_VADDR, "TOC_VALUE": TOC_VALUE, "OPD_VADDR": OPD_VADDR}

blob, info = make_ps3_fixture()
with open("/home/claude/sprx-patcher/tests/fixtures/synthetic_ps3_opd.elf", "wb") as f:
    f.write(blob)
print("wrote", len(blob), "bytes;", info)
