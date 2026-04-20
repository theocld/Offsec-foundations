# Process Injector

A classic DLL injection implementation using `CreateRemoteThread`, demonstrating the fundamental technique behind most modern malware: executing code inside another process's memory space.

## What it does

Given a target process name, the injector finds that process, allocates memory inside it, writes a DLL path, and forces the target to load that DLL — effectively running attacker-controlled code within the context of the victim process.

```
> injector.exe notepad.exe
[*] PHANTOM Process Injector v0.1
[*] Target: notepad.exe
[+] PID found: 8144
[+] Handle acquired on process
[+] Memory allocated in target process at: 0x0000025d15300000
[+] 39 bytes written to target process
[+] LoadLibraryA resolved at: 0x00007fff6dce0800
[+] Remote thread created, DLL injected.
[*] Injection complete.
```

## How it works

**MITRE ATT&CK**: [T1055.001 - Process Injection: DLL Injection](https://attack.mitre.org/techniques/T1055/001/)

This is the textbook `CreateRemoteThread` technique, appearing in countless malware families from decades past to modern threats.

**1. Process Enumeration (`CreateToolhelp32Snapshot`)**
The injector takes a snapshot of all running processes and iterates through them looking for the target by name. This is the equivalent of `ps aux` on Linux, using the `PROCESSENTRY32` structure.

**2. Handle Acquisition (`OpenProcess`)**
A handle is requested with specific access rights:
- `PROCESS_CREATE_THREAD` — to spawn threads in the target
- `PROCESS_VM_OPERATION` — to manipulate memory
- `PROCESS_VM_WRITE` — to write memory
- `PROCESS_VM_READ` — to read memory

Protected processes (like `services.exe`) require SYSTEM or administrator privileges and cannot be opened from unprivileged context.

**3. Remote Memory Allocation (`VirtualAllocEx`)**
The extended version of `VirtualAlloc` allocates memory in another process's address space. Here we allocate a buffer to hold the path to the DLL we want to inject. The page is initially `PAGE_READWRITE` — using `PAGE_EXECUTE_READWRITE` upfront would raise immediate EDR flags.

**4. Payload Writing (`WriteProcessMemory`)**
The DLL path string is copied from the injector's memory into the allocated buffer in the target process. After this call, the target process "owns" a buffer containing attacker data, without having done anything itself.

**5. LoadLibraryA Resolution (`GetProcAddress`)**
Here's the elegant trick: `kernel32.dll` is loaded at the same base address in every process on a given Windows session (due to ASLR being applied per-boot, not per-process). This means `LoadLibraryA`'s address in the injector is the same as in the target process.

**6. Remote Thread Creation (`CreateRemoteThread`)**
A new thread is spawned inside the target process, with `LoadLibraryA` as its entry point and the DLL path buffer as its argument. From the target's perspective, it "chose" to load a new DLL — a completely legitimate operation.

## Build & Run

Cross-compile:
```bash
x86_64-w64-mingw32-gcc injector.c -o injector.exe
```

On target:
```cmd
# First, open the target process (e.g., notepad)
notepad

# Then inject
injector.exe notepad.exe
```

## Key concepts demonstrated

- Process enumeration with `Toolhelp32`
- Privilege-specific handle requests (`OpenProcess` access masks)
- Cross-process memory allocation (`VirtualAllocEx`)
- Cross-process memory writing (`WriteProcessMemory`)
- ASLR consistency of system DLLs across processes
- Remote thread execution (`CreateRemoteThread`)
- Dynamic API resolution (`GetModuleHandle` + `GetProcAddress`)

## Defensive signatures

Classic `CreateRemoteThread` injection is one of the most detected techniques in the industry:

- **API call chain**: The sequence `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` is a near-perfect injection signature. Modern EDRs alert on this pattern in any unsigned process.
- **Kernel callbacks**: Since Windows Vista, `PsSetCreateThreadNotifyRoutine` allows kernel-level security products to observe every thread creation, including remote threads, with parent/child process metadata.
- **Memory permissions**: Even with `PAGE_READWRITE` initial allocation, modifying pages to executable later (`VirtualProtectEx` to `PAGE_EXECUTE_READ`) is another tripwire.
- **Process relationship anomaly**: A thread in `notepad.exe` originating from a non-Microsoft parent process is inherently suspicious.

## Limitations & improvements

- **Obvious API signature**: Import table reveals `VirtualAllocEx`, `CreateRemoteThread`. Real malware resolves these via `LdrGetProcedureAddress` from PEB walking, leaving no import traces.
- **No admin escalation**: Cannot inject into protected/SYSTEM processes without elevation.
- **Visible in EDR telemetry**: Every step generates observable events. Modern evasion uses alternative APIs:
  - `NtCreateThreadEx` (direct syscall, bypasses usermode hooks)
  - `QueueUserAPC` + `SetThreadContext` (no new thread)
  - Process Hollowing (replace mapped image)
  - Reflective DLL Loading (no disk artifact)

These are the kinds of improvements covered in next stages of the learning path.
