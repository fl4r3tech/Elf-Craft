// ps3patch/src/main.cpp
//
// Command-line entrypoint: read a decrypted PS3 EBOOT.elf, patch it so a
// user-supplied .sprx loads and starts before the game's original code
// runs, and write the result to a new file. Ties together every module
// built so far:
//   libelf   -- parse/mutate the ELF container
//   toc.hpp  -- resolve the real code entrypoint from e_entry's descriptor
//   trampoline.hpp -- build the injected payload + entry-point patch
//
// Usage:
//   ps3patch <input EBOOT.elf> <output EBOOT.elf> <sprx path>
//   ps3patch --info <EBOOT.elf>
//
// Example:
//   ps3patch EBOOT.elf EBOOT.patched.elf /dev_hdd0/tmp/debug.sprx
//   ps3patch --info EBOOT.elf

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "elf/file.hpp"
#include "ps3patch/info.hpp"
#include "ps3patch/toc.hpp"
#include "ps3patch/trampoline.hpp"

using namespace elf;
using namespace ps3patch;

namespace {

std::vector<uint8_t> readFile(const std::string& path, bool& ok) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        ok = false;
        return {};
    }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    ok = true;
    return bytes;
}

bool writeFile(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(out);
}

uint64_t alignUp(uint64_t value, uint64_t align) {
    if (align == 0) return value;
    return ((value + align - 1) / align) * align;
}

void printUsage(const char* argv0) {
    std::fprintf(stderr,
                  "usage: %s <input EBOOT.elf> <output EBOOT.elf> <sprx path>\n"
                  "       %s --info <EBOOT.elf>\n"
                  "example: %s EBOOT.elf EBOOT.patched.elf /dev_hdd0/tmp/debug.sprx\n"
                  "         %s --info EBOOT.elf\n",
                  argv0, argv0, argv0, argv0);
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--info") {
        std::string inputPath = argv[2];

        bool readOk = false;
        std::vector<uint8_t> bytes = readFile(inputPath, readOk);
        if (!readOk) {
            std::fprintf(stderr, "error: could not open '%s' for reading\n", inputPath.c_str());
            return 1;
        }

        auto parsed = parseAny(bytes);
        if (!parsed.ok()) {
            std::fprintf(stderr, "error: failed to parse ELF: %s\n", parsed.error().message.c_str());
            return 1;
        }
        auto* file = std::get_if<ElfFile<true, Endian::Big>>(&parsed.value());
        if (!file) {
            std::fprintf(stderr,
                          "error: input is not a 64-bit big-endian ELF (PS3 executables always are) -- "
                          "this doesn't look like a PS3 EBOOT.elf\n");
            return 1;
        }

        auto infoResult = formatInfo(*file);
        if (!infoResult.ok()) {
            std::fprintf(stderr, "error: could not build info report: %s\n", infoResult.error().message.c_str());
            return 1;
        }
        std::fputs(infoResult.value().c_str(), stdout);
        return 0;
    }

    if (argc != 4) {
        printUsage(argv[0]);
        return 1;
    }
    std::string inputPath = argv[1];
    std::string outputPath = argv[2];
    std::string sprxPath = argv[3];

    // --- Read input file ---
    bool readOk = false;
    std::vector<uint8_t> bytes = readFile(inputPath, readOk);
    if (!readOk) {
        std::fprintf(stderr, "error: could not open '%s' for reading\n", inputPath.c_str());
        return 1;
    }
    std::printf("Read %zu bytes from %s\n", bytes.size(), inputPath.c_str());

    // --- Parse ---
    auto parsed = parseAny(bytes);
    if (!parsed.ok()) {
        std::fprintf(stderr, "error: failed to parse ELF: %s\n", parsed.error().message.c_str());
        return 1;
    }

    // PS3 executables are always ELF64 + big-endian; anything else isn't a
    // PS3 EBOOT and we refuse rather than guess.
    auto* file = std::get_if<ElfFile<true, Endian::Big>>(&parsed.value());
    if (!file) {
        std::fprintf(stderr,
                      "error: input is not a 64-bit big-endian ELF (PS3 executables always are) -- "
                      "this doesn't look like a PS3 EBOOT.elf\n");
        return 1;
    }

    // --- Resolve the real entrypoint (validates EM_PPC64 along the way) ---
    auto entryResult = resolveEntryDescriptor(*file);
    if (!entryResult.ok()) {
        std::fprintf(stderr, "error: could not resolve the entry function descriptor: %s\n",
                      entryResult.error().message.c_str());
        return 1;
    }
    const auto& entry = entryResult.value();
    std::printf("Resolved entrypoint: codeAddress=0x%llx tocValue=0x%llx\n",
                static_cast<unsigned long long>(entry.codeAddress), static_cast<unsigned long long>(entry.tocValue));

    if (isAlreadyPatched(*file)) {
        std::fprintf(stderr,
                      "error: '%s' has already been patched by ps3patch. Refusing to patch it again -- "
                      "use the original, unmodified EBOOT.elf. (Run with --info to inspect this file first.)\n",
                      inputPath.c_str());
        return 1;
    }

    // --- Pick a virtual address for the new segment: just past the
    //     highest existing PT_LOAD segment, aligned up to 64KB (a
    //     conservative choice matching typical PS3 loadable-segment
    //     alignment; real hardware behavior should be confirmed). ---
    uint64_t highestEnd = 0;
    for (const auto& ph : file->segments()) {
        if (static_cast<uint32_t>(ph.p_type) != PT_LOAD) continue;
        uint64_t end = static_cast<uint64_t>(ph.p_vaddr) + static_cast<uint64_t>(ph.p_memsz);
        if (end > highestEnd) highestEnd = end;
    }
    uint32_t trampolineAddr = static_cast<uint32_t>(alignUp(highestEnd, 0x10000));
    std::printf("Placing trampoline segment at vaddr=0x%x\n", trampolineAddr);

    // --- Build the trampoline blob + entry patch ---
    auto trampolineResult = buildTrampoline(*file, entry, trampolineAddr, sprxPath);
    if (!trampolineResult.ok()) {
        std::fprintf(stderr, "error: failed to build trampoline: %s\n", trampolineResult.error().message.c_str());
        return 1;
    }
    const auto& tramp = trampolineResult.value();
    std::printf("Trampoline blob: %zu bytes, displaced %zu instruction(s) at the entrypoint\n", tramp.blob.size(),
                tramp.displacedInstructionCount);

    // --- Apply the patch: add the new segment, then overwrite the
    //     entrypoint's instructions with the jump into it. ---
    auto addSegResult = file->addLoadSegment(trampolineAddr, tramp.blob, PF_R | PF_X, 0x10000);
    if (!addSegResult.ok()) {
        std::fprintf(stderr, "error: failed to add trampoline segment: %s\n", addSegResult.error().message.c_str());
        return 1;
    }

    auto entryOffsetResult = file->vaddrToFileOffset(tramp.entryPatchAddr);
    if (!entryOffsetResult.ok()) {
        std::fprintf(stderr, "error: could not locate the entrypoint to patch: %s\n",
                      entryOffsetResult.error().message.c_str());
        return 1;
    }
    auto patchResult = file->patchBytesAt(entryOffsetResult.value(), tramp.entryPatchBytes);
    if (!patchResult.ok()) {
        std::fprintf(stderr, "error: failed to patch the entrypoint: %s\n", patchResult.error().message.c_str());
        return 1;
    }

    // --- Serialize and write output ---
    std::vector<uint8_t> outBytes = file->serialize();
    if (!writeFile(outputPath, outBytes)) {
        std::fprintf(stderr, "error: could not write output file '%s'\n", outputPath.c_str());
        return 1;
    }

    std::printf("Wrote %zu bytes to %s\n", outBytes.size(), outputPath.c_str());
    std::printf("Patched successfully. On boot, this EBOOT will load and start: %s\n", sprxPath.c_str());
    return 0;
}
