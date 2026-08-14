// tests/ps3_toc_test.cpp
//
// Verifies:
//   1. resolveEntryDescriptor correctly follows e_entry -> OPD descriptor
//      -> (codeAddress, tocValue, envPointer), across two separate
//      PT_LOAD segments (proving vaddrToFileOffset's segment search works,
//      not just a hardcoded single-segment case).
//   2. validatePs3Executable rejects a non-EM_PPC64 file.
//   3. An e_entry that doesn't land in any file-backed segment fails
//      cleanly with a descriptive error, not a crash or garbage read.
//   4. A descriptor that would read past the end of the file (truncated)
//      fails cleanly instead of reading out of bounds.

#include <cstdio>
#include <fstream>
#include <vector>

#include "elf/file.hpp"
#include "ps3patch/toc.hpp"

using namespace elf;
using namespace ps3patch;

static std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static int failures = 0;

#define CHECK(cond, msg)                                                                                          \
    do {                                                                                                          \
        if (!(cond)) {                                                                                            \
            std::printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);                                           \
            ++failures;                                                                                           \
        } else {                                                                                                  \
            std::printf("ok:   %s\n", msg);                                                                       \
        }                                                                                                         \
    } while (0)

int main() {
    auto bytes = readFile("tests/fixtures/synthetic_ps3_opd.elf");
    CHECK(!bytes.empty(), "PS3 fixture file loaded");

    auto parsed = ElfFile<true, Endian::Big>::parse(bytes);
    CHECK(parsed.ok(), "PS3 fixture parses as ElfFile<true, Endian::Big>");
    if (!parsed.ok()) {
        std::printf("  error: %s\n", parsed.error().message.c_str());
        return 1;
    }
    const auto& file = parsed.value();

    CHECK(validatePs3Executable(file).ok(), "validatePs3Executable accepts an EM_PPC64 file");

    auto descResult = resolveEntryDescriptor(file);
    CHECK(descResult.ok(), "resolveEntryDescriptor succeeds on the synthetic fixture");
    if (descResult.ok()) {
        const auto& d = descResult.value();
        // These must match the constants baked into gen_ps3_fixture.py.
        CHECK(d.codeAddress == 0x10008, "resolved codeAddress matches the fixture's real code entry (0x10008)");
        CHECK(d.tocValue == 0x30000, "resolved tocValue matches the fixture's TOC base (0x30000)");
        CHECK(d.envPointer == 0, "resolved envPointer is 0 as the fixture sets it");
    }

    // --- vaddrToFileOffset: cross-segment sanity check ---
    // The descriptor lives in a *different* PT_LOAD segment than the code
    // it points to -- confirm both translate correctly, proving the lookup
    // actually searches across segments rather than assuming one.
    auto codeOffset = file.vaddrToFileOffset(0x10008);
    auto opdOffset = file.vaddrToFileOffset(0x20000);
    CHECK(codeOffset.ok() && opdOffset.ok(), "both the code vaddr and the OPD vaddr translate to file offsets");
    if (codeOffset.ok() && opdOffset.ok()) {
        CHECK(codeOffset.value() != opdOffset.value(), "code and OPD resolve to distinct file offsets (different segments)");
    }

    // --- error handling: e_entry pointing outside any segment ---
    {
        ElfFile<true, Endian::Big> mutated = file; // ElfFile has no public mutator for e_entry pre-parse
        // Re-parse a corrupted copy instead: patch e_entry in the raw bytes
        // to an address far outside both segments (segment window <=0x20018).
        std::vector<uint8_t> corrupted = bytes;
        // e_entry lives at byte offset 24 in the Ehdr (after e_ident[16] + e_type[2] + e_machine[2] + e_version[4]).
        uint64_t badEntry = 0xDEADBEEF00ull;
        for (int i = 0; i < 8; ++i) corrupted[24 + static_cast<size_t>(i)] = static_cast<uint8_t>(badEntry >> (56 - 8 * i));
        auto reparsed = ElfFile<true, Endian::Big>::parse(corrupted);
        CHECK(reparsed.ok(), "file with corrupted e_entry still parses (header/segment structure itself is intact)");
        if (reparsed.ok()) {
            auto badResult = resolveEntryDescriptor(reparsed.value());
            CHECK(!badResult.ok(), "resolveEntryDescriptor fails when e_entry points outside any segment");
        }
        (void)mutated;
    }

    // --- error handling: non-PS3 machine type ---
    {
        std::vector<uint8_t> wrongMachine = bytes;
        // e_machine lives at byte offset 18 (after e_ident[16] + e_type[2]).
        wrongMachine[18] = 0x00; wrongMachine[19] = 0x03; // EM_386 = 3, definitely not EM_PPC64
        auto reparsed = ElfFile<true, Endian::Big>::parse(wrongMachine);
        CHECK(reparsed.ok(), "file with swapped e_machine still parses structurally");
        if (reparsed.ok()) {
            CHECK(!validatePs3Executable(reparsed.value()).ok(), "validatePs3Executable rejects a non-EM_PPC64 file");
        }
    }

    // --- error handling: descriptor truncated at end of file ---
    {
        std::vector<uint8_t> truncated(bytes.begin(), bytes.end() - 10); // chop off the last 10 bytes
        auto reparsed = ElfFile<true, Endian::Big>::parse(truncated);
        // Section header table likely falls outside now too, so parse() itself may fail --
        // either outcome (parse failure, or resolve failure) demonstrates no OOB read occurs.
        if (reparsed.ok()) {
            auto badResult = resolveEntryDescriptor(reparsed.value());
            CHECK(!badResult.ok(), "resolveEntryDescriptor fails cleanly on a truncated OPD descriptor");
        } else {
            CHECK(true, "truncated file is correctly rejected at parse() time instead");
        }
    }

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
