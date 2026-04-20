# Reverse Shell

A Windows reverse shell that establishes an outbound TCP connection and redirects `cmd.exe` I/O through the socket, granting remote shell access to the attacker.

## What it does

The target executes `rshell.exe`, which connects to a predetermined attacker-controlled listener (IP:port). Once connected, the attacker types commands in their terminal and sees the output as if running `cmd.exe` locally on the target machine.

```
Attacker (Linux):                    Target (Windows):
$ nc -lvnp 4444                      > rshell.exe
listening on [any] 4444 ...          
connect to [10.10.10.1] from         (no visible output, runs silently)
(UNKNOWN) [10.10.10.10] 49679        

Microsoft Windows [Version 10.0.19045]
C:\Users\target> whoami
target\user
C:\Users\target> hostname
DESKTOP-ABC123
```

## How it works

Reverse shells solve a critical problem in post-exploitation: **most firewalls block inbound connections but allow outbound ones**. Instead of the attacker connecting to the victim (bind shell), the victim connects to the attacker.

**1. Winsock Initialization**
Unlike Linux, Windows requires explicit initialization of the socket library via `WSAStartup` before any network call. The socket is created with `WSASocket(WSA_FLAG_OVERLAPPED)`, producing a handle compatible with Windows file I/O APIs.

**2. Anonymous Pipes**
The shell uses two anonymous pipes as a bridge between the TCP socket and `cmd.exe`:
- Pipe 1: socket data → cmd.exe stdin (commands from attacker)
- Pipe 2: cmd.exe stdout/stderr → socket data (output to attacker)

Pipes are necessary because MinGW-compiled binaries don't always handle the direct `socket → STARTUPINFO.hStdInput` cast reliably. Using pipes as an intermediary is the portable, robust approach.

**3. Process Creation (`CreateProcessA`)**
`cmd.exe` is launched with its standard handles set to the pipe endpoints, and the `CREATE_NO_WINDOW` flag suppresses the console window. The `bInheritHandles = TRUE` argument is critical — without it, the child process cannot access the parent's pipe handles.

**4. Relay Threads**
Two threads copy data between the socket and pipes in real time. Without these relays, data would accumulate in buffers and neither side would see output. This is essentially a userspace implementation of `tee` between socket and process.

## Build & Run

Cross-compile:
```bash
x86_64-w64-mingw32-gcc rshell.c -o rshell.exe -lws2_32
```

On attacker machine, start listener:
```bash
nc -lvnp 4444
```

On target, execute:
```cmd
rshell.exe
```

(IP and port are hardcoded in the source for simplicity — production shells receive these at runtime)

## Key concepts demonstrated

- Winsock initialization and socket creation
- Anonymous pipe creation (`CreatePipe`)
- Handle inheritance control (`SetHandleInformation`)
- Process creation with redirected I/O (`CreateProcessA` + `STARTUPINFO`)
- Thread-based I/O relay (`CreateThread`)
- `CREATE_NO_WINDOW` for windowless execution

## Defensive signatures

Very easily detected in current form:

- **Plain-text TCP traffic**: Everything transmitted in clear text. IDS signatures trivially detect Windows command prompt banners, `whoami` outputs, etc. Encrypted variants (TLS, AES) are standard in mature implants.
- **Outbound connection patterns**: Connections to non-standard ports from non-browser processes are flagged by network monitoring.
- **cmd.exe parent-child relationship**: An EDR sees a non-standard process spawning `cmd.exe` with redirected handles. This is a high-confidence injection/shell indicator.
- **No sleep/jitter**: Real C2 implants "beacon" at intervals with random jitter to blend with legitimate traffic. This shell is always-connected.

## Limitations & improvements

- **No encryption**: Data flows in plain text. Real implants use TLS or custom crypto layers.
- **Hardcoded C2**: IP and port are compile-time constants. Production malware uses domain generation algorithms (DGA) or multiple fallback C2s.
- **No stealth**: Easily killed via Task Manager. No process injection, no service installation, no persistence.
- **Single session**: If the connection drops, the target process exits. Real implants reconnect with exponential backoff.

These are all upcoming topics in more advanced iterations of the project.
