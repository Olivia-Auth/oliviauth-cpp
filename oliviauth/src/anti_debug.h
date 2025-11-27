/**
 * @file anti_debug.h
 * @brief Anti-debugging detection for Windows
 *
 * Multiple detection methods to make debugging harder.
 * IMPORTANT: These can be bypassed, but they increase difficulty.
 */

#pragma once

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include "xor.h"

namespace oliviauth {
namespace antidebug {

/**
 * @brief Check if debugger is present using multiple methods
 * @return true if debugger detected
 */
inline bool check_debugger() {
    // Method 1: IsDebuggerPresent API
    if (IsDebuggerPresent()) {
        return true;
    }

    // Method 2: CheckRemoteDebuggerPresent
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) {
        return true;
    }

    // Method 3: NtQueryInformationProcess - ProcessDebugPort (7)
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE, UINT, PVOID, ULONG, PULONG);

    auto NtQuery = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA(RXor("ntdll.dll")), RXor("NtQueryInformationProcess"));

    if (NtQuery) {
        DWORD_PTR debugPort = 0;
        NTSTATUS status = NtQuery(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
        if (status == 0 && debugPort != 0) {
            return true;
        }

        // Method 4: ProcessDebugFlags (0x1F)
        DWORD debugFlags = 1;
        status = NtQuery(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), NULL);
        if (status == 0 && debugFlags == 0) {
            return true;
        }
    }

    // Method 5: Check for hardware breakpoints
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Timing-based debugger detection
 * @return true if suspicious timing detected (likely single-stepping)
 */
inline bool check_timing() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Operation that should be very fast
    volatile int x = 0;
    for (int i = 0; i < 10000; i++) {
        x += i;
    }

    QueryPerformanceCounter(&end);
    double ms = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;

    // If single-stepping or heavy monitoring, this takes much longer
    // Normal: < 1ms, Debug: > 50ms
    return ms > 50.0;
}

/**
 * @brief Comprehensive debugger check
 * @return true if ANY detection method triggers
 */
inline bool is_being_debugged() {
    return check_debugger() || check_timing();
}

/**
 * @brief Silent corruption on debug detection
 *
 * Instead of exiting immediately (too obvious), corrupt internal state
 * so authentication appears to succeed but doesn't actually work.
 */
inline void silent_corruption_on_debug(std::string& session_id, bool& authenticated) {
    if (is_being_debugged()) {
        // Silently corrupt state - harder to detect than immediate exit
        session_id.clear();
        authenticated = false;
    }
}

} // namespace antidebug
} // namespace oliviauth

#endif // _WIN32
