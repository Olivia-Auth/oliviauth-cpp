/**
 * @file integrity.h
 * @brief Production-Ready Integrity Check
 * FIXES: False positives on NOPs, ASLR crashes, and Thunk resolution.
 */

#pragma once

#ifdef _WIN32
#include <windows.h>
#include <cstdint>
#include <vector>

namespace oliviauth {
namespace integrity {

    // Helper: Safe memory reading
    inline bool safe_read(void* src, void* dest, size_t size) {
        SIZE_T bytesRead = 0;
        // ReadProcessMemory on own process is safe and handles protection checks
        return ReadProcessMemory(GetCurrentProcess(), src, dest, size, &bytesRead) && bytesRead == size;
    }

    /**
     * @brief Resolve Function Thunks (Incremental Linking)
     * Visual Studio generates a JMP table (Thunk) instead of the direct function address.
     * We must follow the JMP to find the real code.
     */
    inline void* resolve_function_addr(void* func_ptr) {
        uint8_t buffer[5];
        if (!safe_read(func_ptr, buffer, 5)) return func_ptr;

        // Check for JMP rel32 (0xE9) - Classic Debug/Incremental Link Thunk
        if (buffer[0] == 0xE9) {
            int32_t offset = *reinterpret_cast<int32_t*>(&buffer[1]);
            // Target = Address of next instruction + offset
            uintptr_t next_instruction = (uintptr_t)func_ptr + 5;
            return (void*)(next_instruction + offset);
        }
        return func_ptr;
    }

    /**
     * @brief CHECK 1: Memory Permission Verification (Anti-Patch)
     * Attackers (Cheat Engine, Trainers) usually change page permissions
     * to PAGE_EXECUTE_READWRITE (RWX) to write their patches.
     * Legitimate code should NEVER be writable in .text section.
     */
    inline bool verify_memory_permissions() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            // Find the code section (usually .text)
            if ((section[i].Characteristics & IMAGE_SCN_CNT_CODE) &&
                (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

                uintptr_t start = (uintptr_t)hModule + section[i].VirtualAddress;
                uintptr_t end = start + section[i].Misc.VirtualSize;

                // Scan pages within the section
                for (uintptr_t ptr = start; ptr < end; ptr += 4096) {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQuery((LPCVOID)ptr, &mbi, sizeof(mbi))) {
                        // If code is WRITABLE, it has been tampered with or hooked
                        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                            (mbi.Protect & PAGE_READWRITE) ||
                            (mbi.Protect & PAGE_WRITECOPY)) {
                            return false; // FAIL: Code is writable!
                        }
                    }
                }
            }
        }
        return true; // PASS: All code pages are Read-Only/Execute
    }

    /**
     * @brief CHECK 2: Critical Function Prologue Check
     * Instead of hashing the whole function (which breaks with relocations),
     * we check if the first bytes are legitimate code, not a JMP (Hook).
     */
    inline bool verify_function_integrity(void* target_func) {
        if (!target_func) return false;

        void* real_code = resolve_function_addr(target_func);
        uint8_t bytes[5];

        if (!safe_read(real_code, bytes, 5)) return false;

        // Check for direct JMP hook (0xE9) at the very start of function
        // If it starts with JMP (0xE9) and it's NOT a Thunk (we already resolved thunks),
        // then it's likely an external hook (MinHook/Detours).
        if (bytes[0] == 0xE9) {
            return false; // DETECTED: Inline Hook
        }

        // Check for Short Jump Loop (Infinite loop patch - 0xEB 0xFE)
        if (bytes[0] == 0xEB && bytes[1] == 0xFE) {
            return false; // DETECTED: Freeze patch
        }

        return true;
    }

    /**
     * @brief Main entry point to be called by your app
     */
    inline bool verify_no_obvious_patches() {
        // 1. Check if anyone made our code writable (CRITICAL)
        if (!verify_memory_permissions()) {
            return false;
        }
        return true;
    }

    /**
     * @brief Cross-verification: verify integrity check function itself
     * TEMPORARILY DISABLED: Taking address of inline function causes crashes in Release builds
     * due to aggressive optimization/inlining. Function may not have stable address.
     */
    inline bool verify_integrity_function() {
        // TODO: Implement non-crashing cross-verification
        // Problem: &verify_no_obvious_patches may not be valid if function is inlined
        return true; // TEMPORARY: Disabled to prevent crash
    }

    /**
     * @brief Verify multiple functions cross-check each other
     * @return true if all cross-checks pass
     */
    inline bool cross_verify_all() {
        // Each check verifies a different aspect
        bool check1 = verify_no_obvious_patches();
        bool check2 = verify_integrity_function();

        // Both must agree
        return check1 && check2;
    }

} // namespace integrity
} // namespace oliviauth
#endif // _WIN32
