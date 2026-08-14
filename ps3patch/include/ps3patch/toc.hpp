// ps3patch/include/ps3patch/toc.hpp
//
// PS3 executables use the PPC64 ELFv1 ABI, where a "function pointer" isn't
// a raw code address — it's the address of a function descriptor (an OPD
// entry): three consecutive big-endian 64-bit words holding
//   [0] the actual code entry address
//   [1] the TOC base value (what r2 must be set to before calling)
//   [2] an environment pointer (nested-function support; PS3 code paths we
//       care about always leave this 0)
//
// Critically, e_entry in the ELF header points at *this descriptor*, not at
// the first executable instruction. Patch the raw bytes at e_entry and
// you've corrupted a data structure, not redirected execution — this is
// the PS3-specific quirk on top of standard PPC64 ELFv1 that a patcher has
// to handle before it can safely touch the entrypoint at all.
//
// This module is intentionally PS3-specific (unlike libelf/ppc): it knows
// about EM_PPC64 and the OPD convention, not just generic ELF/PowerPC.

#pragma once

#include <cstdint>

#include "elf/errors.hpp"
#include "elf/file.hpp"
#include "elf/types.hpp"

namespace ps3patch {

struct EntryDescriptor {
    uint64_t codeAddress; // where real execution actually starts
    uint64_t tocValue;    // r2 must hold this before jumping to codeAddress
    uint64_t envPointer;  // nested-function environment; expect 0 in practice
};

namespace detail {

inline uint64_t readBigEndian64(const std::vector<uint8_t>& bytes, size_t offset) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | bytes[offset + static_cast<size_t>(i)];
    }
    return v;
}

} // namespace detail

using Ps3ElfFile = elf::ElfFile<true, elf::Endian::Big>; // PS3 is always ELF64 + big-endian

// Confirms this actually looks like a PS3/PPU executable before we trust
// anything PS3-specific about it (OPD layout, TOC conventions). Being
// strict here means a malformed or non-PS3 ELF fails with a clear error
// instead of us silently misinterpreting unrelated bytes as a descriptor.
inline elf::VoidResult validatePs3Executable(const Ps3ElfFile& file) {
    if (static_cast<uint16_t>(file.header().e_machine) != elf::EM_PPC64) {
        return elf::Error::make(elf::ErrorCode::Unsupported,
                                 "e_machine is not EM_PPC64 -- this does not look like a PS3/PPU executable");
    }
    return elf::ok();
}

// Resolves e_entry to the underlying (codeAddress, tocValue, envPointer)
// triple by translating the descriptor's virtual address to a file offset
// and reading the three big-endian 64-bit words there.
inline elf::Result<EntryDescriptor, elf::Error> resolveEntryDescriptor(const Ps3ElfFile& file) {
    auto validated = validatePs3Executable(file);
    if (!validated.ok()) return validated.error();

    uint64_t descriptorVaddr = file.entry();

    auto offsetResult = file.vaddrToFileOffset(descriptorVaddr);
    if (!offsetResult.ok()) {
        return elf::Error::make(elf::ErrorCode::OffsetOutOfBounds,
                                 "e_entry (0x" + std::to_string(descriptorVaddr) +
                                     ") does not resolve to any file-backed segment -- cannot locate the "
                                     "entry function descriptor: " +
                                     offsetResult.error().message);
    }
    uint64_t descriptorOffset = offsetResult.value();

    auto bytesResult = file.readAt(descriptorOffset, 24); // 3 x 8 bytes
    if (!bytesResult.ok()) {
        return elf::Error::make(elf::ErrorCode::TruncatedFile,
                                 "entry function descriptor at file offset 0x" + std::to_string(descriptorOffset) +
                                     " is truncated: " + bytesResult.error().message);
    }
    const auto& bytes = bytesResult.value();

    EntryDescriptor descriptor;
    descriptor.codeAddress = detail::readBigEndian64(bytes, 0);
    descriptor.tocValue = detail::readBigEndian64(bytes, 8);
    descriptor.envPointer = detail::readBigEndian64(bytes, 16);
    return descriptor;
}

} // namespace ps3patch
