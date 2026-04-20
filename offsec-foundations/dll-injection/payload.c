/*
 * Demonstration Payload DLL
 *
 * A minimal Windows DLL whose DllMain displays a MessageBox
 * when the DLL is loaded into a process. Used with the
 * process injector to prove remote code execution inside
 * a target process.
 *
 * Build:  x86_64-w64-mingw32-gcc payload.c -o payload.dll -shared
 * Usage:  Injected into a target via the process-injector tool.
 *         The MessageBox will appear owned by the target process.
 */

#include <windows.h>

/*
 * DllMain is called automatically by Windows at key moments
 * in the DLL's lifecycle. DLL_PROCESS_ATTACH fires immediately
 * when the DLL is loaded — this is where payload code executes.
 */
BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL,
                "Code running in the context of the host process.\n"
                "Check Task Manager — this dialog is owned by the target.",
                "DLL Injection Demo",
                MB_OK | MB_ICONINFORMATION);
            break;

        case DLL_PROCESS_DETACH:
            /* Cleanup on unload would go here */
            break;
    }
    return TRUE;
}
