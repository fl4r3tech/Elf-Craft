// tests/ps3_syscalls_test.cpp
//
// Verifies:
//   1. encodeSc() matches the well-known real-world constant 0x44000002.
//   2. makeSyscallTrap emits `li <reg>, <number>` followed by `sc`, with
//      the number landing in the expected register.
//   3. makeLoadModuleCall's instruction count and final two instructions
//      (the trap) are correct, and load number 480 into r11.
//   4. makeStartModuleCall's instruction count and trap load 481 into r11.
//   5. None of the generated instructions are misclassified as branches
//      by ppc::classify (a sanity cross-check between decode.hpp and
//      syscalls.hpp, since a false-positive branch classification here
//      would indicate an encoding bug).

#include <cstdio>

#include "ppc/decode.hpp"
#include "ps3patch/syscalls.hpp"

using namespace ppc;
using namespace ps3patch;

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
    CHECK(encodeSc() == 0x44000002u, "encodeSc matches the well-known constant 0x44000002");

    // --- makeSyscallTrap ---
    {
        auto trap = makeSyscallTrap(480, 11);
        CHECK(trap.size() == 2, "makeSyscallTrap emits exactly 2 instructions (li + sc)");
        CHECK(trap[0] == encodeLi(11, 480), "makeSyscallTrap's first instruction is li r11, 480");
        CHECK(trap[1] == encodeSc(), "makeSyscallTrap's second instruction is sc");
    }

    // --- makeLoadModuleCall ---
    {
        uint32_t pathAddr = 0x30100;
        auto call = makeLoadModuleCall(pathAddr);
        // loadImmediate32 (3) + li r4,0 + li r5,0 + li r11,480 + sc = 7
        CHECK(call.size() == 7, "makeLoadModuleCall emits 7 instructions");
        auto expectedPtrLoad = loadImmediate32(REG_ARG0, pathAddr);
        CHECK(call[0] == expectedPtrLoad[0] && call[1] == expectedPtrLoad[1] && call[2] == expectedPtrLoad[2],
              "first 3 instructions load the path pointer into r3 (REG_ARG0)");
        CHECK(call[3] == encodeLi(REG_ARG1, 0), "4th instruction sets r4 (flags) = 0");
        CHECK(call[4] == encodeLi(REG_ARG2, 0), "5th instruction sets r5 (pOpt) = 0");
        CHECK(call[5] == encodeLi(REG_SYSCALL_NUMBER_DEFAULT, static_cast<int16_t>(SYS_PRX_LOAD_MODULE)),
              "6th instruction loads syscall number 480 (sys_prx_load_module) into r11");
        CHECK(call[6] == encodeSc(), "7th (final) instruction is sc");
    }

    // --- makeStartModuleCall ---
    {
        auto call = makeStartModuleCall();
        CHECK(call.size() == 7, "makeStartModuleCall emits 7 instructions");
        CHECK(call[0] == encodeLi(REG_ARG1, 0), "1st instruction sets r4 (args) = 0");
        CHECK(call[1] == encodeLi(REG_ARG2, 0), "2nd instruction sets r5 (argp) = 0");
        CHECK(call[2] == encodeLi(REG_ARG3, 0), "3rd instruction sets r6 (result) = 0");
        CHECK(call[3] == encodeLi(REG_ARG4, 0), "4th instruction sets r7 (flags) = 0");
        CHECK(call[4] == encodeLi(REG_ARG5, 0), "5th instruction sets r8 (pOpt) = 0");
        CHECK(call[5] == encodeLi(REG_SYSCALL_NUMBER_DEFAULT, static_cast<int16_t>(SYS_PRX_START_MODULE)),
              "6th instruction loads syscall number 481 (sys_prx_start_module) into r11");
        CHECK(call[6] == encodeSc(), "7th (final) instruction is sc");
    }

    // --- makeLoadAndStartModule: combined sequence ---
    {
        auto combined = makeLoadAndStartModule(0x30100);
        CHECK(combined.size() == 14, "makeLoadAndStartModule emits 14 instructions (7 + 7)");
    }

    // --- sanity cross-check: none of these are misclassified as branches ---
    {
        auto combined = makeLoadAndStartModule(0x30100);
        bool anyMisclassified = false;
        for (auto instr : combined) {
            if (classify(instr).kind != BranchKind::NotABranch) {
                anyMisclassified = true;
            }
        }
        CHECK(!anyMisclassified, "no syscall-sequence instruction is misclassified as a branch by ppc::classify");
    }

    std::printf("\n%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
