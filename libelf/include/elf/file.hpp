// libelf/include/elf/file.hpp
//
// ElfFile<Is64, E>: parses and serializes an ELF32 or ELF64 file of a known
// endianness E. Every read is bounds-checked against the buffer size before
// touching it — malformed/truncated input returns a typed Error, it never
// reads out of bounds or crashes.
//
// Because the file's own class (32/64) and data encoding (LE/BE) aren't
// known until we've read e_ident, top-level callers should use parseAny(),
// which reads those 2 bytes first and dispatches into the right
// ElfFile<Is64, E> instantiation, wrapped in AnyElfFile (a std::variant).

#pragma once

#include <algorithm>
#include <cstring>
#include <type_traits>
#include <variant>
#include <vector>

#include "elf/endian.hpp"
#include "elf/errors.hpp"
#include "elf/types.hpp"

namespace elf {

namespace detail {

// Bounds-checked "read a T out of bytes at offset" — the building block
// every parse step uses instead of raw memcpy.
template <typename T>
Result<T, Error> readStruct(const std::vector<uint8_t>& bytes, size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx", offset);
        return Error::make(
            ErrorCode::TruncatedFile,
            "need " + std::to_string(sizeof(T)) + " bytes at offset 0x" + std::string(buf) +
                ", but file is only " + std::to_string(bytes.size()) + " bytes");
    }
    T value;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

// Bounds-checked "does [offset, offset+count*elemSize) fit in the buffer".
inline bool regionFits(size_t bufferSize, uint64_t offset, uint64_t count, size_t elemSize) {
    // Guard against overflow in offset + count*elemSize before comparing.
    if (count != 0 && elemSize > (UINT64_MAX / count)) return false;
    uint64_t span = count * static_cast<uint64_t>(elemSize);
    if (offset > bufferSize) return false;
    if (span > bufferSize - offset) return false;
    return true;
}

} // namespace detail

template <bool Is64, Endian E>
class ElfFile {
public:
    using Ehdr = std::conditional_t<Is64, Elf64_Ehdr<E>, Elf32_Ehdr<E>>;
    using Phdr = std::conditional_t<Is64, Elf64_Phdr<E>, Elf32_Phdr<E>>;
    using Shdr = std::conditional_t<Is64, Elf64_Shdr<E>, Elf32_Shdr<E>>;

    static Result<ElfFile, Error> parse(std::vector<uint8_t> bytes) {
        auto headerResult = detail::readStruct<Ehdr>(bytes, 0);
        if (!headerResult.ok()) return headerResult.error();
        Ehdr header = headerResult.value();

        if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 ||
            header.e_ident[EI_MAG2] != ELFMAG2 || header.e_ident[EI_MAG3] != ELFMAG3) {
            return Error::make(ErrorCode::BadMagic, "missing 0x7F 'E' 'L' 'F' magic");
        }

        constexpr unsigned char expectedClass = Is64 ? ELFCLASS64 : ELFCLASS32;
        if (header.e_ident[EI_CLASS] != expectedClass) {
            return Error::make(ErrorCode::UnsupportedClass,
                                "EI_CLASS byte does not match the requested ElfFile<Is64> instantiation");
        }
        constexpr unsigned char expectedData = (E == Endian::Big) ? ELFDATA2MSB : ELFDATA2LSB;
        if (header.e_ident[EI_DATA] != expectedData) {
            return Error::make(ErrorCode::UnsupportedDataEncoding,
                                "EI_DATA byte does not match the requested ElfFile<E> instantiation");
        }

        if (static_cast<size_t>(header.e_ehsize) != sizeof(Ehdr)) {
            return Error::make(ErrorCode::InconsistentHeaderSize,
                                "e_ehsize (" + std::to_string((uint16_t)header.e_ehsize) +
                                    ") != sizeof(Ehdr) (" + std::to_string(sizeof(Ehdr)) + ")");
        }
        if (header.e_phnum > 0 && static_cast<size_t>(header.e_phentsize) != sizeof(Phdr)) {
            return Error::make(ErrorCode::InconsistentHeaderSize, "e_phentsize does not match sizeof(Phdr)");
        }
        if (header.e_shnum > 0 && static_cast<size_t>(header.e_shentsize) != sizeof(Shdr)) {
            return Error::make(ErrorCode::InconsistentHeaderSize, "e_shentsize does not match sizeof(Shdr)");
        }

        if (!detail::regionFits(bytes.size(), header.e_phoff, header.e_phnum, sizeof(Phdr))) {
            return Error::make(ErrorCode::OffsetOutOfBounds, "program header table falls outside the file");
        }
        if (!detail::regionFits(bytes.size(), header.e_shoff, header.e_shnum, sizeof(Shdr))) {
            return Error::make(ErrorCode::OffsetOutOfBounds, "section header table falls outside the file");
        }

        std::vector<Phdr> phdrs;
        phdrs.reserve(header.e_phnum);
        for (uint16_t i = 0; i < header.e_phnum; ++i) {
            auto r = detail::readStruct<Phdr>(bytes, static_cast<size_t>(header.e_phoff) + i * sizeof(Phdr));
            if (!r.ok()) return r.error();
            phdrs.push_back(r.value());
        }

        std::vector<Shdr> shdrs;
        shdrs.reserve(header.e_shnum);
        for (uint16_t i = 0; i < header.e_shnum; ++i) {
            auto r = detail::readStruct<Shdr>(bytes, static_cast<size_t>(header.e_shoff) + i * sizeof(Shdr));
            if (!r.ok()) return r.error();
            shdrs.push_back(r.value());
        }

        if (header.e_shnum > 0 && header.e_shstrndx >= header.e_shnum) {
            return Error::make(ErrorCode::IndexOutOfBounds, "e_shstrndx >= e_shnum");
        }

        ElfFile file;
        file.header_ = header;
        file.phdrs_ = std::move(phdrs);
        file.shdrs_ = std::move(shdrs);
        file.raw_ = std::move(bytes);
        return file;
    }

    const Ehdr& header() const { return header_; }
    const std::vector<Phdr>& segments() const { return phdrs_; }
    const std::vector<Shdr>& sections() const { return shdrs_; }

    uint64_t entry() const { return header_.e_entry; }
    void setEntry(uint64_t addr) { header_.e_entry = static_cast<decltype(header_.e_entry.get())>(addr); }

    // Overwrite existing bytes in place, starting at file offset `offset`.
    // Cannot grow the file -- use addLoadSegment for that. This is what
    // patching the entrypoint (redirecting it to a trampoline) uses: the
    // jump-in instructions replace bytes that already exist in the file.
    Result<Unit, Error> patchBytesAt(uint64_t offset, const std::vector<uint8_t>& newBytes) {
        if (!detail::regionFits(raw_.size(), offset, newBytes.size(), 1)) {
            return Error::make(ErrorCode::OffsetOutOfBounds, "patch region falls outside the current file");
        }
        std::copy(newBytes.begin(), newBytes.end(),
                   raw_.begin() + static_cast<typename std::vector<uint8_t>::difference_type>(offset));
        return ok();
    }

    // Appends `data` as a new file-backed PT_LOAD segment at the end of the
    // file, and relocates the program header table to the (new) end of the
    // file so the growing table never has to collide with or overwrite
    // existing data -- this is the same technique the original SPRXPatcher
    // uses (move the table rather than shifting everything after it).
    Result<Unit, Error> addLoadSegment(uint64_t vaddr, const std::vector<uint8_t>& data, uint32_t flags,
                                        uint64_t align) {
        uint64_t newOffset = raw_.size();
        raw_.insert(raw_.end(), data.begin(), data.end());

        Phdr ph{};
        ph.p_type = static_cast<uint32_t>(PT_LOAD);
        ph.p_flags = flags;
        ph.p_offset = newOffset;
        ph.p_vaddr = vaddr;
        ph.p_paddr = vaddr;
        ph.p_filesz = static_cast<uint64_t>(data.size());
        ph.p_memsz = static_cast<uint64_t>(data.size());
        ph.p_align = align;
        phdrs_.push_back(ph);

        header_.e_phnum = static_cast<uint16_t>(phdrs_.size());
        header_.e_phoff = raw_.size(); // relocate the table to the (new) end of file

        return ok();
    }

    // Read `length` raw bytes at an arbitrary file offset, bounds-checked.
    // General-purpose building block for anything that needs to read data
    // whose location was computed at runtime (e.g. resolving a virtual
    // address to file contents) rather than known at parse time.
    Result<std::vector<uint8_t>, Error> readAt(uint64_t offset, uint64_t length) const {
        if (!detail::regionFits(raw_.size(), offset, length, 1)) {
            return Error::make(ErrorCode::OffsetOutOfBounds,
                                "requested read of " + std::to_string(length) + " bytes at offset 0x" +
                                    [&] { char buf[32]; std::snprintf(buf, sizeof(buf), "%llx",
                                          static_cast<unsigned long long>(offset)); return std::string(buf); }() +
                                    " falls outside the file");
        }
        auto begin = raw_.begin() + static_cast<long>(offset);
        return std::vector<uint8_t>(begin, begin + static_cast<long>(length));
    }

    // Translate a virtual (runtime/loaded) address to the file offset that
    // backs it, by searching PT_LOAD segments. Only the file-backed portion
    // of each segment is considered ([p_vaddr, p_vaddr + p_filesz)) — an
    // address that falls in the BSS tail (p_filesz <= offset < p_memsz,
    // zero-initialized at load time, never present in the file) correctly
    // reports as not found rather than returning a bogus offset.
    Result<uint64_t, Error> vaddrToFileOffset(uint64_t vaddr) const {
        for (const auto& ph : phdrs_) {
            if (static_cast<uint32_t>(ph.p_type) != PT_LOAD) continue;
            uint64_t vstart = static_cast<uint64_t>(ph.p_vaddr);
            uint64_t vend = vstart + static_cast<uint64_t>(ph.p_filesz);
            if (vaddr >= vstart && vaddr < vend) {
                uint64_t delta = vaddr - vstart;
                uint64_t offset = static_cast<uint64_t>(ph.p_offset) + delta;
                if (offset > raw_.size()) {
                    return Error::make(ErrorCode::OffsetOutOfBounds,
                                        "computed file offset for vaddr exceeds file size");
                }
                return offset;
            }
        }
        return Error::make(ErrorCode::OffsetOutOfBounds,
                            "virtual address not found in any file-backed PT_LOAD segment");
    }

    // Read the raw bytes of a segment's file-backed contents. Bounds were
    // already validated at parse time, but we re-check defensively in case
    // the header was mutated after parsing (e.g. by relocation logic).
    Result<std::vector<uint8_t>, Error> segmentData(size_t index) const {
        if (index >= phdrs_.size()) return Error::make(ErrorCode::IndexOutOfBounds, "segment index out of range");
        const auto& ph = phdrs_[index];
        if (!detail::regionFits(raw_.size(), ph.p_offset, ph.p_filesz, 1)) {
            return Error::make(ErrorCode::OffsetOutOfBounds, "segment data falls outside the file");
        }
        auto begin = raw_.begin() + static_cast<long>(static_cast<uint64_t>(ph.p_offset));
        return std::vector<uint8_t>(begin, begin + static_cast<long>(static_cast<uint64_t>(ph.p_filesz)));
    }

    // Rebuild a byte buffer from the current header/phdrs/shdrs state,
    // leaving everything else copied verbatim from the originally-parsed
    // bytes. For a file that hasn't been mutated, serialize() is byte-
    // identical to the input to parse() — this is what the round-trip test
    // in tests/elf_roundtrip_test.cpp checks.
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out = raw_;

        writeStruct(out, 0, header_);
        writeTable(out, static_cast<uint64_t>(header_.e_phoff), phdrs_);
        writeTable(out, static_cast<uint64_t>(header_.e_shoff), shdrs_);

        return out;
    }

private:
    ElfFile() = default;

    template <typename T>
    static void writeStruct(std::vector<uint8_t>& buf, uint64_t offset, const T& value) {
        ensureCapacity(buf, offset + sizeof(T));
        std::memcpy(buf.data() + offset, &value, sizeof(T));
    }

    template <typename T>
    static void writeTable(std::vector<uint8_t>& buf, uint64_t offset, const std::vector<T>& items) {
        for (size_t i = 0; i < items.size(); ++i) {
            writeStruct(buf, offset + i * sizeof(T), items[i]);
        }
    }

    static void ensureCapacity(std::vector<uint8_t>& buf, uint64_t requiredSize) {
        if (requiredSize > buf.size()) {
            buf.resize(static_cast<size_t>(requiredSize), 0);
        }
    }

    Ehdr header_{};
    std::vector<Phdr> phdrs_;
    std::vector<Shdr> shdrs_;
    std::vector<uint8_t> raw_;
};

// A parsed ELF file of any class/endianness. Use std::visit to operate on
// whichever alternative parseAny() actually produced.
using AnyElfFile = std::variant<
    ElfFile<false, Endian::Little>,
    ElfFile<false, Endian::Big>,
    ElfFile<true, Endian::Little>,
    ElfFile<true, Endian::Big>>;

// Reads e_ident (only — no swapping needed, it's raw bytes) to determine
// class (32/64) and data encoding (LE/BE), then parses using the matching
// ElfFile<Is64, E> instantiation.
inline Result<AnyElfFile, Error> parseAny(std::vector<uint8_t> bytes) {
    if (bytes.size() < EI_NIDENT) {
        return Error::make(ErrorCode::TruncatedFile, "file smaller than e_ident (16 bytes)");
    }
    if (bytes[EI_MAG0] != ELFMAG0 || bytes[EI_MAG1] != ELFMAG1 ||
        bytes[EI_MAG2] != ELFMAG2 || bytes[EI_MAG3] != ELFMAG3) {
        return Error::make(ErrorCode::BadMagic, "missing 0x7F 'E' 'L' 'F' magic");
    }

    unsigned char elfClass = bytes[EI_CLASS];
    unsigned char elfData = bytes[EI_DATA];

    if (elfClass != ELFCLASS32 && elfClass != ELFCLASS64) {
        return Error::make(ErrorCode::UnsupportedClass, "EI_CLASS is neither ELFCLASS32 nor ELFCLASS64");
    }
    if (elfData != ELFDATA2LSB && elfData != ELFDATA2MSB) {
        return Error::make(ErrorCode::UnsupportedDataEncoding, "EI_DATA is neither ELFDATA2LSB nor ELFDATA2MSB");
    }

    if (elfClass == ELFCLASS32 && elfData == ELFDATA2LSB) {
        auto r = ElfFile<false, Endian::Little>::parse(std::move(bytes));
        if (!r.ok()) return r.error();
        return AnyElfFile(std::move(r.value()));
    }
    if (elfClass == ELFCLASS32 && elfData == ELFDATA2MSB) {
        auto r = ElfFile<false, Endian::Big>::parse(std::move(bytes));
        if (!r.ok()) return r.error();
        return AnyElfFile(std::move(r.value()));
    }
    if (elfClass == ELFCLASS64 && elfData == ELFDATA2LSB) {
        auto r = ElfFile<true, Endian::Little>::parse(std::move(bytes));
        if (!r.ok()) return r.error();
        return AnyElfFile(std::move(r.value()));
    }
    // elfClass == ELFCLASS64 && elfData == ELFDATA2MSB (this is the PS3 case)
    auto r = ElfFile<true, Endian::Big>::parse(std::move(bytes));
    if (!r.ok()) return r.error();
    return AnyElfFile(std::move(r.value()));
}

} // namespace elf
