// ps3patch/include/ps3patch/info.hpp
//
// Formats a human-readable inspection report for a PS3 EBOOT.elf: TOC
// value, entry OPD descriptor, segment table, and whether ps3patch has
// already patched this file. Kept separate from main.cpp (as a pure
// string-formatting function over already-parsed data) so it's directly
// testable without spawning the CLI.

#pragma once

#include <cstdio>
#include <string>

#include "elf/file.hpp"
#include "ps3patch/syscalls.hpp"
#include "ps3patch/toc.hpp"
#include "ps3patch/trampoline.hpp"

namespace ps3patch {

namespace detail {

inline std::string segmentFlagsToString(uint32_t flags) {
    std::string s;
    s += (flags & elf::PF_R) ? 'R' : '-';
    s += (flags & elf::PF_W) ? 'W' : '-';
    s += (flags & elf::PF_X) ? 'X' : '-';
    return s;
}

inline std::string segmentTypeToString(uint32_t type) {
    switch (type) {
        case elf::PT_NULL: return "NULL";
        case elf::PT_LOAD: return "LOAD";
        case elf::PT_DYNAMIC: return "DYNAMIC";
        case elf::PT_INTERP: return "INTERP";
        case elf::PT_NOTE: return "NOTE";
        default: {
            char b[16];
            std::snprintf(b, sizeof(b), "0x%x", type);
            return std::string(b);
        }
    }
}

inline std::string hex(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

} // namespace detail

// Builds the full --info report for an already-parsed PS3 ELF file.
// Read-only: never touches the file, only describes it.
inline elf::Result<std::string, elf::Error> formatInfo(const Ps3ElfFile& file) {
    auto entryResult = resolveEntryDescriptor(file);
    if (!entryResult.ok()) return entryResult.error();
    const auto& entry = entryResult.value();

    std::string out;
    out += "=== ELF Header ===\n";
    out += "  Class:        ELF64\n";
    out += "  Data:         big-endian\n";
    out += "  Machine:      EM_PPC64 (" + std::to_string(static_cast<uint16_t>(file.header().e_machine)) + ")\n";
    out += "  Type:         " + std::to_string(static_cast<uint16_t>(file.header().e_type)) + "\n";
    out += "  Flags:        " + detail::hex(static_cast<uint32_t>(file.header().e_flags)) + "\n";
    out += "  Entry (raw):  " + detail::hex(file.entry()) + "  (OPD descriptor address, not code)\n";
    out += "\n";

    out += "=== Entry Function Descriptor (OPD) ===\n";
    out += "  Code address: " + detail::hex(entry.codeAddress) + "\n";
    out += "  TOC value:    " + detail::hex(entry.tocValue) + "\n";
    out += "  Env pointer:  " + detail::hex(entry.envPointer) + "\n";
    out += "\n";

    bool patched = isAlreadyPatched(file);
    out += "=== ps3patch status ===\n";
    out += std::string("  Already patched by ps3patch: ") + (patched ? "YES" : "no") + "\n";
    out += "\n";

    out += "=== Program Headers (" + std::to_string(file.segments().size()) + ") ===\n";
    out += "  #   Type      Flags  VirtAddr            Offset              FileSz      MemSz\n";
    size_t idx = 0;
    for (const auto& ph : file.segments()) {
        char line[256];
        std::snprintf(line, sizeof(line), "  %-3zu %-9s %-6s %-18s %-18s %-11s %s\n", idx,
                       detail::segmentTypeToString(static_cast<uint32_t>(ph.p_type)).c_str(),
                       detail::segmentFlagsToString(static_cast<uint32_t>(ph.p_flags)).c_str(),
                       detail::hex(ph.p_vaddr).c_str(), detail::hex(ph.p_offset).c_str(),
                       detail::hex(ph.p_filesz).c_str(), detail::hex(ph.p_memsz).c_str());
        out += line;
        ++idx;
    }
    out += "\n";

    out += "=== Syscalls ps3patch's trampoline uses ===\n";
    out += "  " + std::to_string(SYS_PRX_LOAD_MODULE) + "  sys_prx_load_module\n";
    out += "  " + std::to_string(SYS_PRX_START_MODULE) + "  sys_prx_start_module\n";
    out += "  (syscall number passed in r11, per LV2 convention, confirmed on real hardware)\n";

    return out;
}

} // namespace ps3patch
