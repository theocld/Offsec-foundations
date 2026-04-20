# DLL Injection Payload

A minimal Windows DLL demonstrating how a payload executes in the context of a host process when loaded via `LoadLibrary`.

## What it does

A standard Windows DLL with a `DllMain` entry point that runs attacker-controlled code (here, a visible MessageBox for demonstration) the moment the DLL is loaded into a process. When combined with the [process-injector](../process-injector/), it shows the full offensive pipeline: injection → loading → execution inside a foreign process.

```
[User opens notepad.exe]
[Attacker runs: injector.exe notepad.exe]
[MessageBox appears — owned by notepad.exe, not injector.exe]
```

The resulting MessageBox is displayed *by notepad itself*. Checking Task Manager at that moment shows the dialog belongs to `notepad.exe`, proving code execution happened in the target process context.

## How it works

**1. DLL Structure**
A Windows DLL is a PE file with specific headers marking it as a shared library rather than an executable. The linker is told to produce a DLL via the `-shared` flag. Instead of a `main` or `WinMain` entry point, DLLs use `DllMain`.

**2. DllMain Invocation**
Windows automatically calls `DllMain` in four scenarios:
- `DLL_PROCESS_ATTACH` — DLL just loaded into the process
- `DLL_PROCESS_DETACH` — DLL about to be unloaded
- `DLL_THREAD_ATTACH` — a new thread started in the host process
- `DLL_THREAD_DETACH` — a thread in the host process is terminating

For malicious payloads, `DLL_PROCESS_ATTACH` is the trigger — code runs automatically with no further action required from the attacker.

**3. Context Inheritance**
The critical property: code running in `DllMain` inherits the full context of the host process:
- **Privileges**: if the host is SYSTEM, the DLL runs as SYSTEM
- **Network trust**: outbound connections originate from the host process's identity
- **File access**: can read/write files the host process has access to
- **Process visibility**: Task Manager shows only the host process; the DLL is hidden inside its module list

## Build & Run

Cross-compile as a DLL (note the `-shared` flag):
```bash
x86_64-w64-mingw32-gcc phantom_dll.c -o phantom_dll.dll -shared
```

Deploy to target and reference its path in the injector's source. See [../process-injector/](../process-injector/) for the full injection workflow.

## Key concepts demonstrated

- DLL file structure and `-shared` compilation
- `DllMain` entry point and reason codes
- Automatic code execution via `DLL_PROCESS_ATTACH`
- Context inheritance from host process
- Separation between delivery (injection) and payload (this DLL)

## Defensive signatures

Injected DLLs are detected through multiple vectors:

- **Module enumeration**: Tools like Process Explorer (Sysinternals) or Volatility (forensics) list every DLL loaded by every process. An unsigned DLL in an unexpected location (e.g., `C:\Users\...\Desktop\phantom_dll.dll` loaded in `notepad.exe`) is a red flag.
- **Signed vs unsigned**: Enterprise environments often enforce WDAC (Windows Defender Application Control) or AppLocker policies that block unsigned DLL loading.
- **ImageLoad events**: Sysmon Event ID 7 logs every module load with full path and signature status. SIEM rules routinely alert on unsigned DLLs loaded in sensitive processes.
- **Atypical loading patterns**: A process loading a DLL from `C:\Users\` or `%TEMP%` rather than `System32` or program install directories.

## The bigger picture

This simple DLL demonstrates the core concept, but real-world malware operates very differently:

- **Memory-only payloads**: Reflective DLL loading places the DLL entirely in memory, with no file on disk — nothing for antivirus to scan.
- **Signed DLLs**: Stolen or forged certificates make malicious DLLs pass signature checks.
- **DLL sideloading/hijacking**: The malicious DLL replaces a legitimate one the target application searches for, abusing DLL search order.
- **Manual mapping**: Sophisticated loaders parse and map PE files themselves, bypassing `LoadLibrary` entirely and leaving no API traces.

Each of these evasion techniques is an advanced topic building on the foundation demonstrated here.

## Legitimate use cases

It's worth noting that DLL injection itself is a completely normal Windows mechanism:

- Accessibility software (screen readers, input tools)
- Anti-cheat systems in video games
- Debuggers and profilers
- Application compatibility shims
- Microsoft's own Detours library for API instrumentation

The technique is neutral — its legitimacy depends entirely on consent and intent.
