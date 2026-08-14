# Generates a small synthetic big-endian ELF64 fixture that mimics the shape
# of a PS3 executable (header + 1 PT_LOAD segment + section headers), purely
# for testing libelf. Not a real game file.
import struct

def make_be_elf64():
    e_ident = bytes([0x7F, ord('E'), ord('L'), ord('F'), 2, 2, 1, 0]) + b'\x00' * 8  # class=64,data=MSB,version=1
    assert len(e_ident) == 16

    ehsize = 64
    phentsize = 56
    shentsize = 64
    phnum = 1
    shnum = 2

    phoff = ehsize
    phdr_table_size = phentsize * phnum
    data_off = phoff + phdr_table_size
    segment_data = b"HELLO_PS3_SEGMENT_DATA_PADDING_"  # 32 bytes
    shoff = data_off + len(segment_data)

    e_type, e_machine, e_version = 2, 21, 1  # ET_EXEC, EM_PPC64
    e_entry = 0x10000
    e_flags = 0
    e_shstrndx = 0

    ehdr = e_ident + struct.pack(">HHIQQQIHHHHHH",
        e_type, e_machine, e_version, e_entry, phoff, shoff,
        e_flags, ehsize, phentsize, phnum, shentsize, shnum, e_shstrndx)
    assert len(ehdr) == 64, len(ehdr)

    p_type, p_flags = 1, 5  # PT_LOAD, PF_R|PF_X
    p_offset, p_vaddr, p_paddr = data_off, e_entry, e_entry
    p_filesz = p_memsz = len(segment_data)
    p_align = 0x10
    phdr = struct.pack(">IIQQQQQQ", p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
    assert len(phdr) == 56

    def shdr(name, stype, flags, addr, offset, size, link, info, align, entsize):
        return struct.pack(">IIQQQQIIQQ", name, stype, flags, addr, offset, size, link, info, align, entsize)

    sh_null = shdr(0,0,0,0,0,0,0,0,0,0)
    sh_one = shdr(0, 1, 2, e_entry, data_off, len(segment_data), 0, 0, 1, 0)  # SHT_PROGBITS

    blob = ehdr + phdr + segment_data + sh_null + sh_one
    return blob

with open("/home/claude/sprx-patcher/tests/fixtures/synthetic_be64.elf", "wb") as f:
    f.write(make_be_elf64())

print("wrote", len("".join(chr(b) for b in make_be_elf64())), "bytes")
