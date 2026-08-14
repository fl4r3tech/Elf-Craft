// libelf/include/elf/types.hpp
//
// On-disk ELF32 and ELF64 struct layouts, per the System V ABI / ELF spec.
// Every struct is templated on Endian so the *file's* declared byte order
// (read from e_ident) picks the instantiation — see file.hpp for dispatch.
//
// These structs are meant to be read/written via memcpy from/to the raw
// file bytes, so:
//   - No virtual functions, no non-POD members.
//   - Field order and sizes must exactly match the spec (static_assert
//     the overall struct size at the bottom of this file).
//   - Padding is avoided by construction (fields are naturally aligned in
//     spec order), but we still static_assert to catch compiler surprises.

#pragma once

#include <cstdint>
#include "elf/endian.hpp"

namespace elf {

// ---- e_ident indices (not endian-dependent; raw bytes) --------------------

enum EIdentIndex : int {
    EI_MAG0 = 0, EI_MAG1 = 1, EI_MAG2 = 2, EI_MAG3 = 3,
    EI_CLASS = 4,
    EI_DATA = 5,
    EI_VERSION = 6,
    EI_OSABI = 7,
    EI_ABIVERSION = 8,
    EI_PAD = 9,
    EI_NIDENT = 16,
};

constexpr unsigned char ELFMAG0 = 0x7F;
constexpr unsigned char ELFMAG1 = 'E';
constexpr unsigned char ELFMAG2 = 'L';
constexpr unsigned char ELFMAG3 = 'F';

enum ElfClass : unsigned char {
    ELFCLASSNONE = 0,
    ELFCLASS32 = 1,
    ELFCLASS64 = 2,
};

enum ElfData : unsigned char {
    ELFDATANONE = 0,
    ELFDATA2LSB = 1, // little-endian
    ELFDATA2MSB = 2, // big-endian (PS3 / PowerPC)
};

// ---- e_type / e_machine values we care about -------------------------------

enum ElfType : uint16_t {
    ET_NONE = 0,
    ET_REL = 1,
    ET_EXEC = 2,
    ET_DYN = 3,
    ET_CORE = 4,
};

enum ElfMachine : uint16_t {
    EM_PPC64 = 21, // PS3 executables report as PPC64
};

// ---- Program header types / flags -----------------------------------------

enum PType : uint32_t {
    PT_NULL = 0,
    PT_LOAD = 1,
    PT_DYNAMIC = 2,
    PT_INTERP = 3,
    PT_NOTE = 4,
};

enum PFlags : uint32_t {
    PF_X = 0x1,
    PF_W = 0x2,
    PF_R = 0x4,
};

// ---- Section header types ---------------------------------------------------

enum SType : uint32_t {
    SHT_NULL = 0,
    SHT_PROGBITS = 1,
    SHT_SYMTAB = 2,
    SHT_STRTAB = 3,
    SHT_NOBITS = 8,
};

// ============================================================================
// ELF32
// ============================================================================

template <Endian E>
struct Elf32_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Endianed<uint16_t, E> e_type;
    Endianed<uint16_t, E> e_machine;
    Endianed<uint32_t, E> e_version;
    Endianed<uint32_t, E> e_entry;
    Endianed<uint32_t, E> e_phoff;
    Endianed<uint32_t, E> e_shoff;
    Endianed<uint32_t, E> e_flags;
    Endianed<uint16_t, E> e_ehsize;
    Endianed<uint16_t, E> e_phentsize;
    Endianed<uint16_t, E> e_phnum;
    Endianed<uint16_t, E> e_shentsize;
    Endianed<uint16_t, E> e_shnum;
    Endianed<uint16_t, E> e_shstrndx;
};

template <Endian E>
struct Elf32_Phdr {
    Endianed<uint32_t, E> p_type;
    Endianed<uint32_t, E> p_offset;
    Endianed<uint32_t, E> p_vaddr;
    Endianed<uint32_t, E> p_paddr;
    Endianed<uint32_t, E> p_filesz;
    Endianed<uint32_t, E> p_memsz;
    Endianed<uint32_t, E> p_flags;
    Endianed<uint32_t, E> p_align;
};

template <Endian E>
struct Elf32_Shdr {
    Endianed<uint32_t, E> sh_name;
    Endianed<uint32_t, E> sh_type;
    Endianed<uint32_t, E> sh_flags;
    Endianed<uint32_t, E> sh_addr;
    Endianed<uint32_t, E> sh_offset;
    Endianed<uint32_t, E> sh_size;
    Endianed<uint32_t, E> sh_link;
    Endianed<uint32_t, E> sh_info;
    Endianed<uint32_t, E> sh_addralign;
    Endianed<uint32_t, E> sh_entsize;
};

// ============================================================================
// ELF64
// ============================================================================

template <Endian E>
struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Endianed<uint16_t, E> e_type;
    Endianed<uint16_t, E> e_machine;
    Endianed<uint32_t, E> e_version;
    Endianed<uint64_t, E> e_entry;
    Endianed<uint64_t, E> e_phoff;
    Endianed<uint64_t, E> e_shoff;
    Endianed<uint32_t, E> e_flags;
    Endianed<uint16_t, E> e_ehsize;
    Endianed<uint16_t, E> e_phentsize;
    Endianed<uint16_t, E> e_phnum;
    Endianed<uint16_t, E> e_shentsize;
    Endianed<uint16_t, E> e_shnum;
    Endianed<uint16_t, E> e_shstrndx;
};

template <Endian E>
struct Elf64_Phdr {
    Endianed<uint32_t, E> p_type;
    Endianed<uint32_t, E> p_flags;   // note: flags before offset in ELF64
    Endianed<uint64_t, E> p_offset;
    Endianed<uint64_t, E> p_vaddr;
    Endianed<uint64_t, E> p_paddr;
    Endianed<uint64_t, E> p_filesz;
    Endianed<uint64_t, E> p_memsz;
    Endianed<uint64_t, E> p_align;
};

template <Endian E>
struct Elf64_Shdr {
    Endianed<uint32_t, E> sh_name;
    Endianed<uint32_t, E> sh_type;
    Endianed<uint64_t, E> sh_flags;
    Endianed<uint64_t, E> sh_addr;
    Endianed<uint64_t, E> sh_offset;
    Endianed<uint64_t, E> sh_size;
    Endianed<uint32_t, E> sh_link;
    Endianed<uint32_t, E> sh_info;
    Endianed<uint64_t, E> sh_addralign;
    Endianed<uint64_t, E> sh_entsize;
};

// ---- Layout sanity checks ---------------------------------------------------
// If these ever fail, the struct no longer matches the on-disk spec size,
// which would silently corrupt every parse/serialize. Checked for one
// instantiation (Little) since Endianed<T,E> is sizeof(T) regardless of E.

static_assert(sizeof(Elf32_Ehdr<Endian::Little>) == 52, "Elf32_Ehdr must be 52 bytes");
static_assert(sizeof(Elf32_Phdr<Endian::Little>) == 32, "Elf32_Phdr must be 32 bytes");
static_assert(sizeof(Elf32_Shdr<Endian::Little>) == 40, "Elf32_Shdr must be 40 bytes");

static_assert(sizeof(Elf64_Ehdr<Endian::Little>) == 64, "Elf64_Ehdr must be 64 bytes");
static_assert(sizeof(Elf64_Phdr<Endian::Little>) == 56, "Elf64_Phdr must be 56 bytes");
static_assert(sizeof(Elf64_Shdr<Endian::Little>) == 64, "Elf64_Shdr must be 64 bytes");

} // namespace elf
