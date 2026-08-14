// tests/ppc_encode_test.cpp
//
// Cross-checks our hand-derived bit layouts against well-known, independently
// verifiable PowerPC instruction encodings (rather than trusting the
// derivation alone), then verifies the makeAbsoluteJump trampoline actually
// produces a clean 32-bit target in the sign-extension edge case that would
// silently break a naive 4-instruction lis/ori/mtctr/bctr sequence.

#include <cstdio>

#include "ppc/encode.hpp"

using namespace ppc;

static int failures = 0;

#define CHECK_HEX(actual, expected, msg)                                                                          \
    do {                                                                                                          \
        if ((actual) != (expected)) {                                                                             \
            std::printf("FAIL: %s -- got 0x%08X, expected 0x%08X (%s:%d)\n", msg, (unsigned)(actual),             \
                         (unsigned)(expected), __FILE__, __LINE__);                                                \
            ++failures;                                                                                           \
        } else {                                                                                                  \
            std::printf("ok:   %s (0x%08X)\n", msg, (unsigned)(actual));                                          \
        }                                                                                                         \
    } while (0)

int main() {
    // Well-known, widely-recognized real-world PPC constants.
    CHECK_HEX(encodeBctr(), 0x4E800420u, "bctr matches the well-known constant 0x4E800420");
    CHECK_HEX(encodeMtctr(0), 0x7C0903A6u, "mtctr r0 matches the well-known constant 0x7C0903A6");
    CHECK_HEX(encodeLis(3, 0x1234), 0x3C601234u, "lis r3, 0x1234 matches expected 0x3C60xxxx pattern");

    // rldicl / clrldi: verify by decoding our own field placement matches
    // the primary-source MD-form layout (OPCD RS RA sh mb XO sh Rc), since
    // there's no single ubiquitous "famous" clrldi constant to check against.
    Instruction clr = encodeClrldi(3, 3, 32); // clrldi r3, r3, 32
    uint32_t opcd = (clr >> 26) & 0x3F;
    uint32_t rs = (clr >> 21) & 0x1F;
    uint32_t ra = (clr >> 16) & 0x1F;
    uint32_t shLo5 = (clr >> 11) & 0x1F;
    uint32_t mb = (clr >> 5) & 0x3F;
    uint32_t xo = (clr >> 2) & 0x7;
    uint32_t shHi1 = (clr >> 1) & 0x1;
    uint32_t rc = clr & 0x1;
    CHECK_HEX(opcd, 30u, "clrldi opcode field is 30 (rldicl primary opcode)");
    CHECK_HEX(rs, 3u, "clrldi RS field is r3");
    CHECK_HEX(ra, 3u, "clrldi RA field is r3");
    CHECK_HEX(shLo5, 0u, "clrldi SH low bits are 0 (no rotate)");
    CHECK_HEX(shHi1, 0u, "clrldi SH high bit is 0");
    CHECK_HEX(mb, 32u, "clrldi MB field is 32 (mask starts at bit 32, clearing the high 32 bits)");
    CHECK_HEX(xo, 0u, "clrldi XO field is 0 (rldicl, not rldicr/rldic/rldimi)");
    CHECK_HEX(rc, 0u, "clrldi Rc bit is 0");

    // The sign-extension bug: a target address whose upper halfword, taken
    // as a standalone 16-bit value, is >= 0x8000. 0x80010000 is a clean
    // example (upper halfword = 0x8000, which is negative as an int16_t).
    auto trampoline = makeAbsoluteJump(0x80010000u, 12);
    CHECK_HEX(trampoline.size(), 5u, "makeAbsoluteJump emits 5 instructions (includes the clrldi fix)");
    // 0x80010000 >> 16 == 0x8001 -- lis r12, 0x8001 sign-extends to
    // 0xFFFFFFFF80010000 in a 64-bit register before the clrldi fix.
    CHECK_HEX(trampoline[0], encodeLis(12, static_cast<int16_t>(0x8001)), "instruction 0 is lis r12, hi16");
    // ori r12, r12, 0x0000
    CHECK_HEX(trampoline[1], encodeOri(12, 12, 0x0000), "instruction 1 is ori r12, r12, lo16");
    // clrldi r12, r12, 32 -- this is the fix: without it, r12 would still
    // hold 0xFFFFFFFF80010000 after the ori above, not 0x0000000080010000.
    CHECK_HEX(trampoline[2], encodeClrldi(12, 12, 32), "instruction 2 is clrldi r12, r12, 32 (the sign-extension fix)");
    CHECK_HEX(trampoline[3], encodeMtctr(12), "instruction 3 is mtctr r12");
    CHECK_HEX(trampoline[4], encodeBctr(), "instruction 4 is bctr");

    // A branch instruction that's out of direct-branch range must throw
    // rather than silently truncate/wrap to a wrong address.
    bool threw = false;
    try {
        encodeBranch(0x10000000, /*absolute=*/false, /*link=*/false); // 256MB, way past 32MB signed range
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK_HEX(threw ? 1u : 0u, 1u, "encodeBranch rejects a displacement beyond the 26-bit LI field's range");

    // Regression test for a real bug caught during review: the range check
    // originally used (1<<25)-1 (a 26-bit bound) instead of the LI field's
    // true 24-bit width, silently allowing displacements up to ~128MB when
    // hardware only supports ~32MB. Verify the true boundary is enforced.
    bool acceptedAtBoundary = false, rejectedJustPastBoundary = false;
    try {
        encodeBranch(33554428, false, false); // exactly kMaxBytes: must succeed
        acceptedAtBoundary = true;
    } catch (const std::invalid_argument&) {
    }
    try {
        encodeBranch(33554432, false, false); // 4 bytes past kMaxBytes: must throw
    } catch (const std::invalid_argument&) {
        rejectedJustPastBoundary = true;
    }
    CHECK_HEX(acceptedAtBoundary ? 1u : 0u, 1u, "encodeBranch accepts the true max in-range displacement (+33554428)");
    CHECK_HEX(rejectedJustPastBoundary ? 1u : 0u, 1u,
              "encodeBranch rejects a displacement 4 bytes past the true 24-bit LI boundary");

    // mflr/mtlr/mfctr: cross-checked against well-known real-world constants.
    CHECK_HEX(encodeMflr(0), 0x7C0802A6u, "mflr r0 matches the well-known constant 0x7C0802A6");
    CHECK_HEX(encodeMtlr(0), 0x7C0803A6u, "mtlr r0 matches the well-known constant 0x7C0803A6");
    CHECK_HEX(encodeMfctr(0), 0x7C0902A6u, "mfctr r0 matches the well-known constant 0x7C0902A6");

    // std/ld: no single ubiquitous constant to check against, so verify by
    // decoding our own field placement matches the primary-source DS-form
    // layout (OPCD RS/RT RA DS XO), same approach used for clrldi earlier.
    // Sign-extending the 14-bit DS field via an int16_t shift trick doesn't
    // work here (integer promotion widens int16_t to int before the shift,
    // so it never wraps at the 16-bit boundary) -- use an explicit
    // sign-extend instead, the same technique decode.hpp uses.
    auto signExtend14 = [](uint32_t v) -> int32_t {
        uint32_t signBit = 1u << 13;
        return static_cast<int32_t>((v ^ signBit) - signBit);
    };
    {
        Instruction store = encodeStd(3, 1, 128); // std r3, 128(r1)
        uint32_t opcd = (store >> 26) & 0x3F;
        uint32_t rs = (store >> 21) & 0x1F;
        uint32_t ra = (store >> 16) & 0x1F;
        int32_t ds14 = signExtend14((store >> 2) & 0x3FFF);
        uint32_t xo = store & 0x3;
        CHECK_HEX(opcd, 62u, "std opcode field is 62");
        CHECK_HEX(rs, 3u, "std RS field is r3");
        CHECK_HEX(ra, 1u, "std RA field is r1");
        CHECK_HEX(static_cast<uint32_t>(ds14), 32u, "std DS field decodes back to displacement/4 = 32 (128/4)");
        CHECK_HEX(xo, 0u, "std XO field is 0 (std, not stdu)");

        Instruction load = encodeLd(4, 1, -8); // ld r4, -8(r1)
        uint32_t lopcd = (load >> 26) & 0x3F;
        int32_t loadDs14 = signExtend14((load >> 2) & 0x3FFF);
        CHECK_HEX(lopcd, 58u, "ld opcode field is 58");
        CHECK_HEX(static_cast<uint32_t>(loadDs14) & 0xFFFFu, static_cast<uint32_t>(-2) & 0xFFFFu,
                  "ld DS field decodes back to displacement/4 = -2 (-8/4), properly sign-extended");

        Instruction update = encodeStdu(1, 1, -256); // stdu r1, -256(r1)
        uint32_t uxo = update & 0x3;
        CHECK_HEX(uxo, 1u, "stdu XO field is 1 (update form)");

        // Round-trip sanity: encode then decode a range of displacements,
        // including negative ones large enough to exercise the sign bit.
        bool allRoundTrip = true;
        for (int32_t d = -256; d <= 256; d += 4) {
            Instruction i = encodeStd(5, 1, d);
            int32_t decoded = signExtend14((i >> 2) & 0x3FFF) * 4;
            if (decoded != d) allRoundTrip = false;
        }
        CHECK_HEX(allRoundTrip ? 1u : 0u, 1u, "std displacement round-trips correctly across -256..256");
    }

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
