// ps3patch/include/ps3patch/toc.hpp
//
// PS3 executables use a PPC64 ELFv1-style ABI where a "function pointer"
// isn't a raw code address -- it's the address of a function descriptor.
// The generic PPC64 ELFv1 spec describes this as three consecutive 8-byte
// big-endian fields (code address, TOC base, environment pointer -- 24
// bytes total). SCE's own PS3 SDK toolchain diverges from that: empirical
// analysis of a real, retail-disc-decrypted EBOOT.elf (decrypted via
// TrueAncestor) showed its entry descriptor is only 8 bytes total -- a
// 4-byte code address immediately followed by a 4-byte TOC pointer, with
// no third field at all.
//
// The evidence: reading the descriptor and the words immediately
// surrounding it as 8-byte fields produced values where every single
// 8-byte-aligned word -- across multiple unrelated fields and multiple
// different functions -- shared an identical trailing 4 bytes. Splitting
// each word into two 4-byte halves instead resolved this cleanly: the
// "constant" half is the module's TOC pointer (correctly constant across
// functions in the same module -- TOC is per-module, not per-function),
// and subtracting the ABI's well-known +0x8000 TOC offset from it lands
// exactly inside the file's actual .toc-bearing segment, which is strong
// independent corroboration this reading is correct.
//
// This is the same kind of SCE-toolchain divergence from stock PowerPC
// convention as the LV2 syscall-number register (r11, not r0) documented
// in syscalls.hpp -- Sony's PS3 SDK differs from generic PPC64/ELFv1 ABI
// documentation in more than one place, and this codebase now reflects
// what a real retail EBOOT actually contains rather than only the
// textbook spec.
//
// Critically, e_entry in the ELF header points at *this descriptor*, not
// at the first executable instruction. Patch the raw bytes at e_entry and
// you've corrupted a data structure, not redirected execution -- this is
// the PS3-specific quirk on top of the PowerPC ABI that a patcher has to
// handle before it can safely touch the entrypoint at all.
//
// This module is intentionally PS3-specific (unlike libelf/ppc): it knows
// about EM_PPC64 and this descriptor convention, not just generic
// ELF/PowerPC.

#pragma once

#include <cstdint>

#include "elf/errors.hpp"
#include "elf/file.hpp"
#include "elf/types.hpp"

namespace ps3patch {

struct EntryDescriptor {
    uint64_t codeAddress; // where real execution actually starts
    uint64_t tocValue;    // r2 must hold this before jumping to codeAddress
    uint64_t envPointer;  // not present in this PS3 SDK's descriptor format; always 0
};

namespace detail {

inline uint32_t readBigEndian32(const std::vector<uint8_t>& bytes, size_t offset) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        v = (v << 8) | bytes[offset + static_cast<size_t>(i)];
    }
    return v;
}

} // namespace detail

using Ps3ElfFile = elf::ElfFile<true, elf::Endian::Big>; // PS3 is always ELF64 + big-endian

// Confirms this actually looks like a PS3/PPU executable before we trust
// anything PS3-specific about it (descriptor layout, TOC conventions).
// Being strict here means a malformed or non-PS3 ELF fails with a clear
// error instead of us silently misinterpreting unrelated bytes.
inline elf::VoidResult validatePs3Executable(const Ps3ElfFile& file) {
    if (static_cast<uint16_t>(file.header().e_machine) != elf::EM_PPC64) {
        return elf::Error::make(elf::ErrorCode::Unsupported,
                                 "e_machine is not EM_PPC64 -- this does not look like a PS3/PPU executable");
    }
    return elf::ok();
}

// Whether e_flags matches the value consistently observed in real,
// hardware-decrypted PS3 EBOOTs (0x0). This is deliberately advisory, not
// a hard gate: unlike e_machine (defined by the ELF spec) or the OPD/
// syscall-register conventions elsewhere in this project (each backed by
// either a primary specification or independently corroborating sources),
// there is no publicly documented PS3-specific bit-level meaning for
// e_flags. Treating a nonzero value as an outright error would mean
// inventing a rule we can't actually back up -- exactly the mistake that
// produced the original (wrong) 24-byte OPD assumption this file used to
// make. So this is surfaced as "unusual" information (in --info and as a
// non-fatal warning before patching), not enforced.
inline bool hasTypicalEFlags(const Ps3ElfFile& file) {
    return static_cast<uint32_t>(file.header().e_flags) == 0;
}

// Resolves e_entry to the underlying (codeAddress, tocValue) pair by
// translating the descriptor's virtual address to a file offset and
// reading two big-endian 32-bit words there. envPointer is always 0 --
// this descriptor format has no third field (see the header comment for
// why this differs from the generic PPC64 ELFv1 ABI's 3x8-byte OPD entry).
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

    auto bytesResult = file.readAt(descriptorOffset, 8); // 2 x 4 bytes: codeAddress, tocValue
    if (!bytesResult.ok()) {
        return elf::Error::make(elf::ErrorCode::TruncatedFile,
                                 "entry function descriptor at file offset 0x" + std::to_string(descriptorOffset) +
                                     " is truncated: " + bytesResult.error().message);
    }
    const auto& bytes = bytesResult.value();

    EntryDescriptor descriptor;
    descriptor.codeAddress = detail::readBigEndian32(bytes, 0);
    descriptor.tocValue = detail::readBigEndian32(bytes, 4);
    descriptor.envPointer = 0;
    return descriptor;
}

} // namespace ps3patch
