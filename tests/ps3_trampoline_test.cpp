// tests/ps3_trampoline_test.cpp
//
// Verifies:
//   1. buildTrampoline succeeds against the synthetic PS3 fixture with a
//      nearby trampoline address (1-instruction direct jump-in/jump-back).
//   2. The user-supplied .sprx path string is embedded correctly,
//      null-terminated, and the blob stays 4-byte aligned overall.
//   3. buildTrampoline succeeds with a *far* trampoline address, correctly
//      switching to the 5-instruction long jump for the jump-in.
//   4. Input validation rejects an empty path, an over-length path, and a
//      misaligned trampoline address.
//   5. relocateDisplacedInstructions refuses (rather than emitting a wrong
//      jump) when a displaced conditional branch's corrected displacement
//      no longer fits its 14-bit field -- the core safety property this
//      module exists to guarantee.

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "elf/file.hpp"
#include "ppc/decode.hpp"
#include "ps3patch/toc.hpp"
#include "ps3patch/trampoline.hpp"

using namespace elf;
using namespace ppc;
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
    CHECK(parsed.ok(), "PS3 fixture parses");
    if (!parsed.ok()) return 1;
    const auto& file = parsed.value();

    auto entryResult = resolveEntryDescriptor(file);
    CHECK(entryResult.ok(), "entry descriptor resolves");
    if (!entryResult.ok()) return 1;
    const auto& entry = entryResult.value();

    const std::string path = "/dev_hdd0/tmp/debug.sprx";

    // --- Case 1: nearby trampoline address -> 1-instruction jumps ---
    {
        uint32_t trampolineAddr = static_cast<uint32_t>(entry.codeAddress) + 0x1000;
        auto result = buildTrampoline(file, entry, trampolineAddr, path);
        CHECK(result.ok(), "buildTrampoline succeeds for a nearby trampoline address");
        if (!result.ok()) {
            std::printf("  error: %s\n", result.error().message.c_str());
            return 1;
        }
        const auto& r = result.value();

        CHECK(r.displacedInstructionCount == 1, "nearby trampoline uses the 1-instruction direct jump-in");
        CHECK(r.entryPatchBytes.size() == 4, "entryPatchBytes is exactly 4 bytes for the 1-instruction jump");
        CHECK(r.entryPatchAddr == entry.codeAddress, "entryPatchAddr matches the resolved code entry address");
        CHECK(r.blob.size() % 4 == 0, "blob size is 4-byte aligned overall");

        // Decode the jump-in instruction and confirm it targets trampolineAddr.
        uint32_t jumpInWord = (static_cast<uint32_t>(r.entryPatchBytes[0]) << 24) |
                               (static_cast<uint32_t>(r.entryPatchBytes[1]) << 16) |
                               (static_cast<uint32_t>(r.entryPatchBytes[2]) << 8) |
                               static_cast<uint32_t>(r.entryPatchBytes[3]);
        auto decodedJumpIn = classify(jumpInWord);
        CHECK(decodedJumpIn.kind == BranchKind::DirectRelative, "jump-in decodes as a direct relative branch");
        if (decodedJumpIn.kind == BranchKind::DirectRelative) {
            uint32_t target = static_cast<uint32_t>(entry.codeAddress) + static_cast<uint32_t>(decodedJumpIn.displacement);
            CHECK(target == trampolineAddr + 8, "jump-in branch target matches trampolineAddr + 8 (past the magic marker)");
        }

        // The path string should appear verbatim, null-terminated, somewhere in the blob.
        std::string blobStr(r.blob.begin(), r.blob.end());
        auto pos = blobStr.find(path);
        CHECK(pos != std::string::npos, "path string is embedded in the blob");
        if (pos != std::string::npos) {
            CHECK(r.blob[pos + path.size()] == 0, "path string is null-terminated in the blob");
        }

        // Fixed section lengths: 16 (prologue) + 14 (syscall) + 16 (epilogue) + 3 (toc fixup)
        // + 1 (resume, since the fixture's entry instruction is a single nop)
        // + jumpBack (1, since resumeAddr and remainderAddr are close together here) = 51 instructions.
        size_t expectedInstrCount = 16 + 14 + 16 + 3 + 1 + 1;
        size_t codeBytes = 8 /* magic marker */ + expectedInstrCount * 4;
        CHECK(r.blob.size() >= codeBytes + path.size() + 1,
              "blob is large enough to hold the expected code plus the path string plus null terminator");
    }

    // --- Case 2: far trampoline address -> 5-instruction long jumps ---
    {
        uint32_t trampolineAddr = static_cast<uint32_t>(entry.codeAddress) + 0x10000000u; // 256MB away
        auto result = buildTrampoline(file, entry, trampolineAddr, path);
        CHECK(result.ok(), "buildTrampoline succeeds for a far trampoline address");
        if (result.ok()) {
            const auto& r = result.value();
            CHECK(r.displacedInstructionCount == 5, "far trampoline uses the 5-instruction long jump-in");
            CHECK(r.entryPatchBytes.size() == 20, "entryPatchBytes is exactly 20 bytes for the 5-instruction jump");

            // Confirm the jump-in is the standard makeAbsoluteJump sequence targeting trampolineAddr + 8.
            auto expectedJump = makeAbsoluteJump(trampolineAddr + 8);
            bool matches = true;
            for (int i = 0; i < 5; ++i) {
                uint32_t w = 0;
                for (int b = 0; b < 4; ++b) w = (w << 8) | r.entryPatchBytes[static_cast<size_t>(i * 4 + b)];
                if (w != expectedJump[static_cast<size_t>(i)]) matches = false;
            }
            CHECK(matches, "far jump-in matches the expected 5-instruction makeAbsoluteJump sequence");
        }
    }

    // --- Input validation ---
    {
        auto emptyPath = buildTrampoline(file, entry, static_cast<uint32_t>(entry.codeAddress) + 0x1000, "");
        CHECK(!emptyPath.ok(), "buildTrampoline rejects an empty path");
        if (!emptyPath.ok()) CHECK(emptyPath.error().code == ErrorCode::InvalidArgument, "empty path reports InvalidArgument");

        std::string tooLong(2000, 'a');
        auto longPath = buildTrampoline(file, entry, static_cast<uint32_t>(entry.codeAddress) + 0x1000, tooLong);
        CHECK(!longPath.ok(), "buildTrampoline rejects an over-length path");

        auto misaligned = buildTrampoline(file, entry, static_cast<uint32_t>(entry.codeAddress) + 0x1001, path);
        CHECK(!misaligned.ok(), "buildTrampoline rejects a misaligned trampoline address");
    }

    // --- Safety property: refuse rather than emit a broken relocated branch ---
    {
        // A conditional branch (bc) with a small in-range original displacement...
        uint32_t originalAddr = 0x10000;
        int32_t originalDisplacement = 0x100; // well within the 14-bit BD field's ~32KB reach
        Instruction bc = encodeBranchConditional(4, 2, originalDisplacement, false, false);

        // ...relocated somewhere far enough away that the corrected displacement
        // can no longer fit in that 14-bit field (~32KB reach).
        uint32_t farNewAddr = originalAddr + 1024u * 1024u; // 1MB away, way past 32KB
        auto result = relocateDisplacedInstructions({bc}, originalAddr, farNewAddr);
        CHECK(!result.ok(), "relocateDisplacedInstructions refuses when a conditional branch can't be safely relocated");
        if (!result.ok()) {
            CHECK(result.error().code == ErrorCode::RelocationFailed, "failure reports ErrorCode::RelocationFailed");
        }
    }

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
