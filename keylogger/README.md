# Keylogger

A Windows keylogger using low-level keyboard hooks, with full Unicode support and layout-aware character translation.

## What it does

Captures every keystroke globally across the system (all applications, all windows), translates virtual key codes into the actual characters the user is typing, and writes them to a timestamped log file.

```
[2026-04-16 13:21:54] === Session started ===
test, normally this should work; translate this @#€ !
[ENTER]
[ENTER]
:)
```

## How it works

**1. Global Low-Level Hook (`SetWindowsHookExA`)**
The keylogger installs a `WH_KEYBOARD_LL` hook by passing thread ID 0, which applies it to every thread in every process. The OS calls our callback function before the keystroke reaches its destination application.

**2. Message Loop**
Low-level hooks require an active message queue to function. Without a running `GetMessage`/`DispatchMessage` loop, Windows silently uninstalls the hook after a timeout. This is why the program appears to "do nothing" visibly while actively intercepting keystrokes in the background.

**3. Unicode-Aware Translation (`ToUnicodeEx`)**
A naive keylogger captures virtual key codes (VK_CODES) but fails on accented characters, dead keys, and non-US layouts. `ToUnicodeEx` performs proper translation considering:
- Current keyboard layout (AZERTY French, QWERTY US, Dvorak, etc.)
- Modifier key state (Shift, Caps Lock, AltGr)
- Dead keys (e.g., `^` followed by `a` produces `â`)

The `0x04` flag ensures the keylogger observes without modifying the keyboard state, preventing interference with other applications' dead-key handling.

**4. UTF-8 File Logging**
Output is converted from UTF-16 (Windows internal) to UTF-8 (`WideCharToMultiByte`) for portable log files. Each keystroke is immediately flushed to disk (`fflush`) to minimize data loss on system interruption.

## Build & Run

Cross-compiled from Linux:
```bash
x86_64-w64-mingw32-gcc keylogger.c -o keylogger.exe
```

Run on Windows target:
```cmd
keylogger.exe
```

The log file `keylog.txt` is created in the working directory.

## Key concepts demonstrated

- Windows message-based architecture
- `SetWindowsHookExA` with `WH_KEYBOARD_LL`
- Mandatory `CallNextHookEx` chaining
- Keyboard state management (`GetKeyboardState`, `GetKeyboardLayout`)
- Unicode translation with `ToUnicodeEx`
- UTF-16 to UTF-8 conversion
- Special key handling (Enter, Tab, Arrow keys, Function keys)

## Defensive signatures

This keylogger uses textbook techniques that are well-understood by defenders:

- **API call pattern**: `SetWindowsHookEx` with `WH_KEYBOARD_LL` is a high-confidence indicator of keyboard interception. EDR products maintain lists of processes that legitimately use this API (accessibility tools, input method editors).
- **Process behavior**: A process with no visible window maintaining a hook and writing to disk is suspicious.
- **File I/O pattern**: Frequent small writes to a local file can be correlated with keystroke rates.

## Limitations & improvements

- **No persistence**: The process must be manually started and dies when the user logs out. Real-world malware adds registry run keys, scheduled tasks, or service installation.
- **No obfuscation**: Function calls are visible in import tables. Defensive scanners like PE-bear or pestudio flag this immediately.
- **No exfiltration**: Logs stay on disk. A real implant would batch and transmit data through an encrypted channel.
- **Visible console window**: Running the executable shows a CMD window. Recompiling with `-mwindows` and `WinMain` produces a windowless binary.

These are deliberate: this is a learning project, not an operational tool.
