# 🛡️ offsec-foundations

## About

This repository is a hands-on exploration of the low-level techniques used in offensive security: network reconnaissance, system hooks, process manipulation, and code injection. Every tool is written from the ground up in C, without relying on high-level frameworks, to understand exactly what happens at the OS level.

The goal isn't to build a production-ready red team toolkit — it's to demystify the mechanisms. Once you've written a keylogger with `SetWindowsHookEx` or a process injector with `CreateRemoteThread`, reading a malware analysis report suddenly makes a lot more sense.

**⚠️ Educational purposes only.** These tools are built for learning, malware research, and authorized testing in controlled environments. Using them against systems you don't own or have permission to test is illegal in most jurisdictions.

---

## Toolkit

| Tool | Description | Platform | Concepts |
|------|-------------|----------|----------|
| [**port-scanner**](port-scanner/) | TCP port scanner with DNS resolution and banner grabbing | Linux | Sockets, `getaddrinfo`, service fingerprinting |
| [**keylogger**](keylogger/) | Global keyboard logger with Unicode support | Windows | Low-level hooks, `ToUnicodeEx`, message loop |
| [**reverse-shell**](reverse-shell/) | TCP reverse shell with pipe-based I/O redirection | Windows | Winsock, pipes, threads, process redirection |
| [**process-injector**](process-injector/) | Classic DLL injection via `CreateRemoteThread` | Windows | Remote memory allocation, thread injection |
| [**dll-injection**](dll-injection/) | Payload DLL demonstrating contextual code execution | Windows | `DllMain`, code hosting in foreign processes |

---

## Architecture

The tools are designed to be **minimal, readable, and self-contained**. No external dependencies beyond the standard C library and Windows API. Each tool is a single `.c` file that compiles to a single binary.

```
offsec-foundations/
├── port-scanner/        # Linux network reconnaissance
│   ├── scanner.c
│   └── README.md
├── keylogger/           # Windows keyboard capture
│   ├── keylogger.c
│   └── README.md
├── reverse-shell/       # Windows → attacker connection
│   ├── rshell.c
│   └── README.md
├── process-injector/    # Remote DLL loading
│   ├── injector.c
│   └── README.md
├── dll-injection/       # Payload DLL
│   ├── phantom_dll.c
│   └── README.md
├── docs/
│   └── winapi-reference.md  # Windows API cheat sheet
└── screenshots/         # Proof of execution
```

---

## Build

All Windows tools are cross-compiled from Linux using **mingw-w64**, which lets you develop on a Linux workstation and produce native Windows binaries.

### Prerequisites

**On Linux (for Windows tools):**
```bash
sudo apt install mingw-w64
```

**On Linux (for the port scanner):**
```bash
sudo apt install build-essential
```

### Compilation

Each tool has its own build command documented in its subfolder. Common patterns:

```bash
# Linux binary
gcc tool.c -o tool

# Windows binary (cross-compiled)
x86_64-w64-mingw32-gcc tool.c -o tool.exe

# Windows binary with Winsock
x86_64-w64-mingw32-gcc tool.c -o tool.exe -lws2_32

# Windows DLL
x86_64-w64-mingw32-gcc dll.c -o dll.dll -shared
```

---

## Lab Setup

These tools are designed to be tested in an **isolated virtualization lab**. The recommended setup:

- **Host**: Windows with VMware Workstation Pro
- **Windows VM**: Windows 10 with [FLARE-VM](https://github.com/mandiant/flare-vm) for analysis tools, Defender disabled
- **Linux attacker VM**: Parrot OS or Kali Linux
- **Network simulation VM**: [REMnux](https://remnux.org/) with INetSim for fake internet

Two separate virtual networks:
- **Isolated network** (host-only, no internet) for malware detonation
- **NAT network** for attacker tooling

Never run these tools against machines you don't own or have written authorization to test.

---

## Documentation

- [**Windows API Reference**](docs/winapi-reference.md) — Cheat sheet for every Windows API function used in this repo, organized by domain (networking, hooks, processes, memory)
- Each tool folder has its own README explaining the technique, the code, and detection signatures

---

## Legal Notice

This software is provided for educational and research purposes. The author assumes no liability for misuse. Running malware, keyloggers, or injection tools on systems without explicit authorization violates laws including:

- **France**: Article 323-1 Code Pénal (up to 3 years prison, €100,000 fine)
- **EU**: Directive 2013/40/EU on attacks against information systems
- **US**: Computer Fraud and Abuse Act (CFAA)
- **UK**: Computer Misuse Act 1990

Use responsibly, on your own lab, or with written authorization.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
