// tests/elf_roundtrip_test.cpp
//
// Verifies:
//   1. parseAny() correctly identifies a big-endian ELF64 fixture and
//      dispatches to ElfFile<true, Endian::Big>.
//   2. parse() -> serialize() is byte-identical for an unmodified file.
//   3. Header/segment/section field values read back correctly (endian
//      swap is actually happening, not silently a no-op).
//   4. Truncated and bad-magic input return typed Errors instead of
//      crashing or reading out of bounds.

#include <cstdio>
#include <fstream>
#include <vector>

#include "elf/file.hpp"

using namespace elf;

static std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static int failures = 0;

#define CHECK(cond, msg)                                                                                         \
    do {                                                                                                         \
        if (!(cond)) {                                                                                           \
            std::printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);                                          \
            ++failures;                                                                                          \
        } else {                                                                                                 \
            std::printf("ok:   %s\n", msg);                                                                      \
        }                                                                                                        \
    } while (0)

int main() {
    auto bytes = readFile("tests/fixtures/synthetic_be64.elf");
    CHECK(!bytes.empty(), "fixture file loaded");

    auto parsed = parseAny(bytes);
    CHECK(parsed.ok(), "parseAny succeeds on well-formed BE64 fixture");
    if (!parsed.ok()) {
        std::printf("  error: %s\n", parsed.error().message.c_str());
        return 1;
    }

    bool dispatchedToBE64 = std::holds_alternative<ElfFile<true, Endian::Big>>(parsed.value());
    CHECK(dispatchedToBE64, "parseAny dispatched to ElfFile<true, Endian::Big>");

    const auto& file = std::get<ElfFile<true, Endian::Big>>(parsed.value());

    CHECK(file.entry() == 0x10000, "entry point read back correctly (endian swap works)");
    CHECK(file.segments().size() == 1, "one PT_LOAD segment parsed");
    CHECK(file.sections().size() == 2, "two sections parsed (NULL + PROGBITS)");

    auto segData = file.segmentData(0);
    CHECK(segData.ok(), "segment data readable");
    if (segData.ok()) {
        std::string s(segData.value().begin(), segData.value().end());
        CHECK(s == "HELLO_PS3_SEGMENT_DATA_PADDING_", "segment data content matches fixture");
    }

    auto reserialized = file.serialize();
    CHECK(reserialized == bytes, "serialize() is byte-identical to input for an unmodified file");

    // --- error handling: truncated file ---
    std::vector<uint8_t> truncated(bytes.begin(), bytes.begin() + 10);
    auto truncResult = parseAny(truncated);
    CHECK(!truncResult.ok(), "parseAny rejects a 10-byte truncated file");
    if (!truncResult.ok()) {
        CHECK(truncResult.error().code == ErrorCode::TruncatedFile, "truncated file reports ErrorCode::TruncatedFile");
    }

    // --- error handling: bad magic ---
    std::vector<uint8_t> badMagic = bytes;
    badMagic[0] = 0x00;
    auto magicResult = parseAny(badMagic);
    CHECK(!magicResult.ok(), "parseAny rejects corrupted magic bytes");
    if (!magicResult.ok()) {
        CHECK(magicResult.error().code == ErrorCode::BadMagic, "bad magic reports ErrorCode::BadMagic");
    }

    // --- error handling: phoff pointing outside the file ---
    std::vector<uint8_t> badPhoff = bytes;
    badPhoff[0x20] = 0xFF; badPhoff[0x21] = 0xFF; // corrupt part of e_phoff (big-endian, byte 0x20 is high-order-ish)
    auto phoffResult = parseAny(badPhoff);
    CHECK(!phoffResult.ok(), "parseAny rejects a program header offset that falls outside the file");

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
