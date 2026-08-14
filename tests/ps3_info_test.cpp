// tests/ps3_info_test.cpp
//
// Verifies formatInfo() and isAlreadyPatched() directly against the
// library (not through the CLI), on both an unpatched and a freshly
// patched (in-memory, via buildTrampoline + addLoadSegment) file.

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "elf/file.hpp"
#include "ps3patch/info.hpp"
#include "ps3patch/toc.hpp"
#include "ps3patch/trampoline.hpp"

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
    auto parsed = ElfFile<true, Endian::Big>::parse(bytes);
    CHECK(parsed.ok(), "fixture parses");
    if (!parsed.ok()) return 1;
    auto file = parsed.value(); // mutable copy

    CHECK(!isAlreadyPatched(file), "unpatched fixture is not detected as already patched");

    auto infoResult = formatInfo(file);
    CHECK(infoResult.ok(), "formatInfo succeeds on the unpatched fixture");
    if (infoResult.ok()) {
        const auto& text = infoResult.value();
        CHECK(text.find("EM_PPC64") != std::string::npos, "info report mentions EM_PPC64");
        CHECK(text.find("0x10008") != std::string::npos, "info report includes the resolved code address");
        CHECK(text.find("0x30000") != std::string::npos, "info report includes the resolved TOC value");
        CHECK(text.find("Already patched by ps3patch: no") != std::string::npos,
              "info report correctly shows 'no' for an unpatched file");
        CHECK(text.find("480") != std::string::npos && text.find("481") != std::string::npos,
              "info report lists both syscall numbers");
    }

    // --- Patch it in-memory, then re-check both functions ---
    auto entryResult = resolveEntryDescriptor(file);
    CHECK(entryResult.ok(), "entry resolves for patching");
    if (!entryResult.ok()) return 1;
    const auto& entry = entryResult.value();

    uint32_t trampolineAddr = 0x40000; // clear of the fixture's existing 0x10000/0x20000 segments
    auto trampResult = buildTrampoline(file, entry, trampolineAddr, "/dev_hdd0/tmp/debug.sprx");
    CHECK(trampResult.ok(), "buildTrampoline succeeds for the info test's patch");
    if (!trampResult.ok()) return 1;
    const auto& tramp = trampResult.value();

    auto addResult = file.addLoadSegment(trampolineAddr, tramp.blob, PF_R | PF_X, 0x10000);
    CHECK(addResult.ok(), "addLoadSegment succeeds");
    auto offsetResult = file.vaddrToFileOffset(tramp.entryPatchAddr);
    CHECK(offsetResult.ok(), "entry patch address resolves");
    if (offsetResult.ok()) {
        auto patchResult = file.patchBytesAt(offsetResult.value(), tramp.entryPatchBytes);
        CHECK(patchResult.ok(), "patchBytesAt succeeds");
    }

    CHECK(isAlreadyPatched(file), "isAlreadyPatched detects the freshly-patched (in-memory) file");

    // Attempting to build a second trampoline against the now-patched file must be refused.
    auto secondAttempt = buildTrampoline(file, entry, trampolineAddr + 0x10000, "/dev_hdd0/tmp/other.sprx");
    CHECK(!secondAttempt.ok(), "buildTrampoline refuses to run again on an already-patched file");
    if (!secondAttempt.ok()) {
        CHECK(secondAttempt.error().code == ErrorCode::AlreadyPatched, "refusal reports ErrorCode::AlreadyPatched");
    }

    auto infoAfter = formatInfo(file);
    CHECK(infoAfter.ok(), "formatInfo succeeds on the patched file");
    if (infoAfter.ok()) {
        CHECK(infoAfter.value().find("Already patched by ps3patch: YES") != std::string::npos,
              "info report correctly shows 'YES' after patching");
    }

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
