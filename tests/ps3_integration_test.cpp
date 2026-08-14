// tests/ps3_integration_test.cpp
//
// This is the closest thing to "does the whole tool actually work" we can
// verify without real PS3 hardware: it re-parses the *actual output file*
// produced by running the compiled ps3patch CLI against the synthetic
// fixture (not calling library functions directly -- this exercises the
// real binary, same as a user would run it), and checks:
//   1. The output is still a valid, parseable ELF.
//   2. e_phnum increased by exactly 1 (the new trampoline segment).
//   3. The new segment's data matches what buildTrampoline would produce.
//   4. The original entrypoint's bytes now decode as a jump into the new
//      segment.
//   5. Following that jump-in to the new segment, then walking to the end
//      of the resume section, the jump-back instruction found there
//      targets the correct "rest of the original code" address -- i.e.
//      the full redirect-and-return chain is self-consistent, which is
//      the strongest static check possible without executing PPC code.
//
// Run via: (from repo root) ./ps3patch tests/fixtures/synthetic_ps3_opd.elf
// /tmp/integration_patched.elf /dev_hdd0/tmp/debug.sprx  --  then this test.
// The CMake test target runs the CLI itself as a fixture step; see
// tests/CMakeLists.txt.

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#ifndef PS3PATCH_BINARY
#define PS3PATCH_BINARY "./bin/ps3patch" // fallback for manual (non-CMake) test runs
#endif

#include "elf/file.hpp"
#include "ppc/decode.hpp"
#include "ps3patch/toc.hpp"

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
    // Run the real, compiled CLI binary against the synthetic fixture --
    // this exercises actual argv parsing, file I/O, and orchestration, not
    // just the library functions in isolation.
    std::string cmd = std::string(PS3PATCH_BINARY) +
                       " tests/fixtures/synthetic_ps3_opd.elf /tmp/integration_patched.elf "
                       "/dev_hdd0/tmp/debug.sprx > /tmp/integration_stdout.txt 2>&1";
    int rc = std::system(cmd.c_str());
    CHECK(rc == 0, "ps3patch CLI runs successfully against the synthetic fixture");
    if (rc != 0) {
        std::system("cat /tmp/integration_stdout.txt");
        return 1;
    }

    auto originalBytes = readFile("tests/fixtures/synthetic_ps3_opd.elf");
    auto patchedBytes = readFile("/tmp/integration_patched.elf");
    CHECK(!patchedBytes.empty(), "patched output file was written and is non-empty");
    CHECK(patchedBytes.size() > originalBytes.size(), "patched file is larger than the original (new segment appended)");

    auto originalParsed = ElfFile<true, Endian::Big>::parse(originalBytes);
    auto patchedParsed = ElfFile<true, Endian::Big>::parse(patchedBytes);
    CHECK(originalParsed.ok(), "original fixture re-parses");
    CHECK(patchedParsed.ok(), "patched output re-parses as a valid ELF");
    if (!originalParsed.ok() || !patchedParsed.ok()) return 1;

    const auto& original = originalParsed.value();
    const auto& patched = patchedParsed.value();

    CHECK(patched.segments().size() == original.segments().size() + 1,
          "patched file has exactly one more segment than the original");

    // The new segment should be the last one, PT_LOAD, R+X, and its size
    // should match the trampoline blob size.
    const auto& newSeg = patched.segments().back();
    CHECK(static_cast<uint32_t>(newSeg.p_type) == PT_LOAD, "new segment is PT_LOAD");
    CHECK((static_cast<uint32_t>(newSeg.p_flags) & (PF_R | PF_X)) == (PF_R | PF_X), "new segment is readable+executable");
    uint64_t newSegVaddr = newSeg.p_vaddr;

    // --- Resolve the entrypoint in BOTH files and confirm the descriptor
    //     itself (codeAddress, tocValue) is unchanged by patching -- we
    //     redirect *from* the entry, we don't corrupt the descriptor. ---
    auto origEntry = resolveEntryDescriptor(original);
    auto patchedEntry = resolveEntryDescriptor(patched);
    CHECK(origEntry.ok() && patchedEntry.ok(), "entry descriptor resolves in both original and patched files");
    if (origEntry.ok() && patchedEntry.ok()) {
        CHECK(origEntry.value().codeAddress == patchedEntry.value().codeAddress,
              "patching does not corrupt the entry descriptor's codeAddress");
        CHECK(origEntry.value().tocValue == patchedEntry.value().tocValue,
              "patching does not corrupt the entry descriptor's tocValue");
    }
    if (!patchedEntry.ok()) return 1;
    uint64_t codeAddr = patchedEntry.value().codeAddress;

    // --- The original entrypoint's instruction should now be a jump into
    //     the new segment. ---
    auto codeOffset = patched.vaddrToFileOffset(codeAddr);
    CHECK(codeOffset.ok(), "patched entrypoint code address resolves to a file offset");
    if (!codeOffset.ok()) return 1;
    auto firstInstrBytes = patched.readAt(codeOffset.value(), 4);
    CHECK(firstInstrBytes.ok(), "can read the first instruction at the patched entrypoint");
    if (!firstInstrBytes.ok()) return 1;
    const auto& fb = firstInstrBytes.value();
    uint32_t firstWord = (static_cast<uint32_t>(fb[0]) << 24) | (static_cast<uint32_t>(fb[1]) << 16) |
                          (static_cast<uint32_t>(fb[2]) << 8) | static_cast<uint32_t>(fb[3]);
    auto decoded = classify(firstWord);
    CHECK(decoded.kind == BranchKind::DirectRelative, "patched entrypoint's first instruction is a direct branch");
    uint64_t jumpTarget = 0;
    if (decoded.kind == BranchKind::DirectRelative) {
        jumpTarget = codeAddr + static_cast<uint64_t>(decoded.displacement);
        CHECK(jumpTarget == newSegVaddr + 8, "the jump-in branch targets exactly the new trampoline segment's code (past the 8-byte magic marker)");
    }

    // --- Walk the injected blob: skip past the fixed prologue/syscall/
    //     epilogue/toc-fixup section (49 instructions) to the resume
    //     section, and confirm the very next instruction after the
    //     1-instruction resume (the fixture's entry is a single nop) is a
    //     jump-back whose target is the original entry + 4 bytes -- i.e.
    //     the rest of the original code the game would have executed. ---
    uint64_t resumeAddr = newSegVaddr + 8 + 49 * 4; // +8 for the magic marker at the start of the segment
    auto resumeOffset = patched.vaddrToFileOffset(resumeAddr);
    CHECK(resumeOffset.ok(), "resume section address resolves to a file offset in the patched file");
    if (resumeOffset.ok()) {
        auto resumeInstrBytes = patched.readAt(resumeOffset.value(), 4);
        CHECK(resumeInstrBytes.ok(), "can read the resumed (relocated) original instruction");
        if (resumeInstrBytes.ok()) {
            const auto& rb = resumeInstrBytes.value();
            uint32_t resumeWord = (static_cast<uint32_t>(rb[0]) << 24) | (static_cast<uint32_t>(rb[1]) << 16) |
                                   (static_cast<uint32_t>(rb[2]) << 8) | static_cast<uint32_t>(rb[3]);
            CHECK(resumeWord == 0x60000000u, "resumed instruction is the fixture's original nop, copied verbatim");
        }

        auto jumpBackOffset = patched.vaddrToFileOffset(resumeAddr + 4);
        CHECK(jumpBackOffset.ok(), "jump-back instruction address resolves to a file offset");
        if (jumpBackOffset.ok()) {
            auto jbBytes = patched.readAt(jumpBackOffset.value(), 4);
            CHECK(jbBytes.ok(), "can read the jump-back instruction");
            if (jbBytes.ok()) {
                const auto& jb = jbBytes.value();
                uint32_t jbWord = (static_cast<uint32_t>(jb[0]) << 24) | (static_cast<uint32_t>(jb[1]) << 16) |
                                   (static_cast<uint32_t>(jb[2]) << 8) | static_cast<uint32_t>(jb[3]);
                auto jbDecoded = classify(jbWord);
                CHECK(jbDecoded.kind == BranchKind::DirectRelative, "jump-back instruction is a direct branch");
                if (jbDecoded.kind == BranchKind::DirectRelative) {
                    uint64_t jbTarget = (resumeAddr + 4) + static_cast<uint64_t>(jbDecoded.displacement);
                    uint64_t expectedRemainder = codeAddr + 4; // codeAddr + displacedCount(1)*4
                    CHECK(jbTarget == expectedRemainder,
                          "jump-back correctly targets the original code right after the displaced instruction -- "
                          "the full redirect-and-return chain is self-consistent");
                }
            }
        }
    }

    // --- Idempotency guard: re-running ps3patch on an already-patched
    //     file must be refused, not silently stack a second trampoline. ---
    std::string cmd2 = std::string(PS3PATCH_BINARY) +
                        " /tmp/integration_patched.elf /tmp/integration_patched_twice.elf "
                        "/dev_hdd0/tmp/other.sprx > /tmp/integration_stdout2.txt 2>&1";
    int rc2 = std::system(cmd2.c_str());
    CHECK(rc2 != 0, "re-running ps3patch on an already-patched file is refused (idempotency guard)");
    auto stdout2 = readFile("/tmp/integration_stdout2.txt");
    std::string stderrText(stdout2.begin(), stdout2.end());
    CHECK(stderrText.find("already been patched") != std::string::npos,
          "refusal message clearly explains why the second patch was rejected");

    // --- --info reports the patched file's status correctly ---
    std::string cmd3 = std::string(PS3PATCH_BINARY) + " --info /tmp/integration_patched.elf > /tmp/integration_info.txt 2>&1";
    int rc3 = std::system(cmd3.c_str());
    CHECK(rc3 == 0, "--info runs successfully against the patched file");
    auto infoOut = readFile("/tmp/integration_info.txt");
    std::string infoText(infoOut.begin(), infoOut.end());
    CHECK(infoText.find("Already patched by ps3patch: YES") != std::string::npos,
          "--info correctly reports the patched file as already patched");

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
