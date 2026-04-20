# 🔧 PHANTOM — Windows API Cheat Sheet (Offensive Security)

> Référence rapide des fonctions Windows utilisées dans les projets PHANTOM.
> Pour chaque fonction : ce qu'elle fait, ses paramètres clés, et pourquoi on l'utilise.
>
> Doc officielle complète : https://learn.microsoft.com/en-us/windows/win32/api/

---

## 📦 Headers et Librairies

| Header | Contenu | Quand l'inclure |
|--------|---------|----------------|
| `windows.h` | API Windows générale (processus, mémoire, threads, fichiers) | Toujours sur un projet Windows |
| `winsock2.h` | Sockets réseau (version 2) | Tout programme réseau |
| `ws2tcpip.h` | Fonctions TCP/IP modernes (`inet_pton`, etc.) | Avec winsock2 |
| `tlhelp32.h` | Énumération de processus et threads | Quand tu cherches un processus par nom |
| `stdio.h` | `printf`, `fprintf`, `fopen` — I/O standard C | Toujours |
| `time.h` | `time`, `localtime` — horodatage | Quand tu veux des timestamps |

**Ordre d'inclusion important** : `winsock2.h` AVANT `windows.h`, sinon conflit de définitions.

**Librairie à linker** : `-lws2_32` pour tout programme utilisant Winsock.

---

## 🔤 Types Windows → Types C réels

| Type Windows | Type C réel | Signification |
|-------------|-------------|---------------|
| `DWORD` | `unsigned long` (32 bits) | Double WORD — entier 32 bits non signé |
| `WORD` | `unsigned short` (16 bits) | Entier 16 bits non signé |
| `BYTE` | `unsigned char` (8 bits) | Un octet |
| `BOOL` | `int` | Booléen Windows (0 = FALSE, autre = TRUE) |
| `HANDLE` | `void *` | Handle générique vers une ressource Windows |
| `HWND` | `void *` | Handle vers une fenêtre |
| `HHOOK` | `void *` | Handle vers un hook |
| `HINSTANCE` | `void *` | Handle vers une instance de programme |
| `HMODULE` | `void *` | Handle vers un module (DLL/EXE chargé) |
| `LPSTR` | `char *` | Pointeur vers chaîne ANSI |
| `LPCSTR` | `const char *` | Pointeur vers chaîne ANSI constante |
| `LPWSTR` | `wchar_t *` | Pointeur vers chaîne Unicode (wide) |
| `LPVOID` | `void *` | Pointeur générique |
| `LRESULT` | `long` / `long long` | Valeur de retour d'une callback Windows |
| `WPARAM` | `unsigned long long` (64-bit) | Paramètre de message Windows |
| `LPARAM` | `long long` (64-bit) | Paramètre de message Windows |
| `SIZE_T` | `unsigned long long` | Taille mémoire |
| `FARPROC` | `void *` (fonction) | Pointeur vers une fonction (retour de GetProcAddress) |

### Préfixes à reconnaître

| Préfixe | Signification | Exemple |
|---------|--------------|---------|
| `H...` | Handle (ticket vers une ressource) | `HANDLE`, `HWND`, `HHOOK` |
| `LP...` | Long Pointer (pointeur) | `LPSTR`, `LPVOID` |
| `P...` | Pointer | `PROCESSENTRY32 *` |
| `...A` | Version ANSI (char) de la fonction | `MessageBoxA`, `CreateProcessA` |
| `...W` | Version Wide/Unicode (wchar_t) | `MessageBoxW`, `CreateProcessW` |
| `...Ex` | Version Extended (souvent : opère sur un autre processus) | `VirtualAllocEx`, `WriteProcessMemory` |
| `h...` | Variable contenant un handle (convention) | `hProcess`, `hThread` |
| `dw...` | Variable de type DWORD (convention) | `dwProcessId` |
| `lp...` | Variable de type pointeur (convention) | `lpBaseAddress` |
| `b...` | Variable booléenne (convention) | `bInheritHandle` |

### Conventions d'appel

| Mot-clé | Signification |
|---------|--------------|
| `WINAPI` | Convention d'appel Windows (pour les fonctions appelées par l'OS) |
| `CALLBACK` | Identique à WINAPI (utilisé pour les callbacks) |
| `NTAPI` | Convention d'appel pour les fonctions ntdll (Native API) |

---

## 🌐 Réseau (Winsock)

### WSAStartup
```c
int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
```
**Quoi** : Initialise la bibliothèque Winsock. Obligatoire avant tout appel réseau sur Windows.
**Paramètres** :
- `MAKEWORD(2, 2)` → demande Winsock version 2.2
- `&wsa` → struct remplie avec les infos de la version

**Retour** : 0 = succès

**Usage PHANTOM** : Première ligne de tout programme réseau Windows (port scanner, reverse shell).

---

### WSASocket
```c
SOCKET WSASocket(int af, int type, int protocol,
                  LPWSAPROTOCOL_INFOA lpProtocolInfo,
                  GROUP g, DWORD dwFlags);
```
**Quoi** : Crée un socket. Version étendue de `socket()`.
**Paramètres clés** :
- `AF_INET` → IPv4
- `SOCK_STREAM` → TCP
- `IPPROTO_TCP` → protocole TCP
- `WSA_FLAG_OVERLAPPED` → crée un handle compatible avec l'API Windows

**Retour** : `SOCKET` (handle), `INVALID_SOCKET` si erreur

**Pourquoi pas juste `socket()`** : `WSASocket` avec `WSA_FLAG_OVERLAPPED` retourne un handle utilisable avec `CreateProcess` et d'autres APIs Windows.

---

### connect
```c
int connect(SOCKET s, const struct sockaddr *name, int namelen);
```
**Quoi** : Se connecte à un serveur distant.
**Retour** : 0 = succès, `SOCKET_ERROR` si erreur

**Erreurs courantes** :
- `10061` (WSAECONNREFUSED) → rien n'écoute sur ce port
- `10060` (WSAETIMEDOUT) → timeout, host injoignable

---

### send / recv
```c
int send(SOCKET s, const char *buf, int len, int flags);
int recv(SOCKET s, char *buf, int len, int flags);
```
**Quoi** : Envoyer / recevoir des données sur un socket connecté.
**Retour** : nombre d'octets envoyés/reçus. 0 ou négatif = connexion fermée ou erreur.
**flags** : généralement 0.

---

### closesocket / WSACleanup
```c
int closesocket(SOCKET s);
int WSACleanup(void);
```
**Quoi** : Fermer un socket / libérer Winsock. Toujours appeler dans cet ordre à la fin.

---

## 🪝 Hooks (Keylogger)

### SetWindowsHookExA
```c
HHOOK SetWindowsHookExA(int idHook, HOOKPROC lpfn,
                         HINSTANCE hMod, DWORD dwThreadId);
```
**Quoi** : Installe un hook système qui intercepte des événements.
**Paramètres** :
- `WH_KEYBOARD_LL` (13) → hook clavier bas niveau (toutes les touches, tous les processus)
- `lpfn` → ta fonction callback appelée à chaque événement
- `GetModuleHandle(NULL)` → handle de ton .exe
- `0` → thread ID (0 = tous les threads = hook GLOBAL)

**Retour** : `HHOOK` (handle du hook), `NULL` si erreur

**Point critique** : Nécessite une message loop active (`GetMessage`) sinon le hook meurt.

---

### CallNextHookEx
```c
LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
```
**Quoi** : Passe le message au hook suivant dans la chaîne.
**OBLIGATOIRE** : Toujours appeler à la fin de ta callback, sinon tu casses la chaîne de hooks.

---

### UnhookWindowsHookEx
```c
BOOL UnhookWindowsHookEx(HHOOK hhk);
```
**Quoi** : Désinstalle un hook. Nettoyage à la fin du programme.

---

### GetKeyState
```c
SHORT GetKeyState(int nVirtKey);
```
**Quoi** : Retourne l'état d'une touche virtuelle.
- `& 0x8000` → touche actuellement enfoncée
- `& 0x0001` → touche en état toggle (Caps Lock, Num Lock)

---

### GetKeyboardState
```c
BOOL GetKeyboardState(PBYTE lpKeyState);
```
**Quoi** : Remplit un tableau de 256 octets avec l'état de TOUTES les touches.
**Usage** : Passé à `ToUnicodeEx` pour la conversion complète.

---

### ToUnicodeEx
```c
int ToUnicodeEx(UINT wVirtKey, UINT wScanCode, const BYTE *lpKeyState,
                 LPWSTR pwszBuff, int cchBuff, UINT wFlags, HKL dwhkl);
```
**Quoi** : Convertit un vkCode + état clavier en caractère Unicode réel.
**Paramètres clés** :
- `wFlags = 0x04` → ne pas modifier l'état interne du clavier (mode observation)
- `dwhkl` → layout clavier (obtenu via `GetKeyboardLayout`)

**Retour** : > 0 = nombre de caractères, 0 = pas de caractère, < 0 = dead key

---

## ⚙️ Processus et Threads

### CreateProcessA
```c
BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
                     LPSECURITY_ATTRIBUTES lpProcessAttributes,
                     LPSECURITY_ATTRIBUTES lpThreadAttributes,
                     BOOL bInheritHandles, DWORD dwCreationFlags,
                     LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
                     LPSTARTUPINFOA lpStartupInfo,
                     LPPROCESS_INFORMATION lpProcessInformation);
```
**Quoi** : Crée un nouveau processus.
**Paramètres critiques** :
- `bInheritHandles = TRUE` → le processus enfant hérite des handles (sockets, pipes)
- `dwCreationFlags` : `0` (normal), `CREATE_NO_WINDOW` (pas de fenêtre console)
- `lpStartupInfo` → contrôle stdin/stdout/stderr du processus enfant

**Usage PHANTOM** : Lancer `cmd.exe` avec les flux redirigés (reverse shell).

---

### OpenProcess
```c
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
```
**Quoi** : Obtient un handle sur un processus existant, avec les droits demandés.
**Droits courants pour l'injection** :
- `PROCESS_CREATE_THREAD` → droit de créer un thread
- `PROCESS_VM_OPERATION` → droit de manipuler la mémoire
- `PROCESS_VM_WRITE` → droit d'écrire dans la mémoire
- `PROCESS_VM_READ` → droit de lire la mémoire

**Retour** : `HANDLE`, `NULL` si erreur (droits insuffisants, processus protégé)

---

### CreateRemoteThread
```c
HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
                           SIZE_T dwStackSize,
                           LPTHREAD_START_ROUTINE lpStartAddress,
                           LPVOID lpParameter, DWORD dwCreationFlags,
                           LPDWORD lpThreadId);
```
**Quoi** : Crée un thread dans un AUTRE processus.
**Paramètres clés** :
- `hProcess` → handle du processus cible (obtenu via OpenProcess)
- `lpStartAddress` → adresse de la fonction à exécuter (ex: LoadLibraryA)
- `lpParameter` → argument passé à cette fonction (ex: chemin de la DLL)

**C'est LA fonction centrale de l'injection de processus.** Très surveillée par les EDR.

---

### CreateThread
```c
HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                     SIZE_T dwStackSize,
                     LPTHREAD_START_ROUTINE lpStartAddress,
                     LPVOID lpParameter, DWORD dwCreationFlags,
                     LPDWORD lpThreadId);
```
**Quoi** : Crée un thread dans le processus COURANT (pas distant).
**Usage PHANTOM** : Threads de relais dans le reverse shell (pipe ↔ socket).

---

### WaitForSingleObject
```c
DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
```
**Quoi** : Bloque jusqu'à ce que l'objet (processus, thread, mutex) soit signalé.
- `INFINITE` → attend indéfiniment

---

## 🧠 Mémoire

### VirtualAllocEx
```c
LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                       DWORD flAllocationType, DWORD flProtect);
```
**Quoi** : Alloue de la mémoire dans un AUTRE processus.
**Paramètres** :
- `hProcess` → handle du processus cible
- `lpAddress = NULL` → Windows choisit l'adresse
- `MEM_COMMIT | MEM_RESERVE` → réserver ET committer
- `PAGE_READWRITE` → permissions RW (plus discret que RWX)
- `PAGE_EXECUTE_READWRITE` → permissions RWX (nécessaire pour du shellcode, mais très suspect)

**Retour** : adresse de la mémoire allouée dans le processus cible

---

### WriteProcessMemory
```c
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
                          LPCVOID lpBuffer, SIZE_T nSize,
                          SIZE_T *lpNumberOfBytesWritten);
```
**Quoi** : Écrit des données dans la mémoire d'un autre processus.
**Paramètres** :
- `lpBaseAddress` → où écrire (adresse retournée par VirtualAllocEx)
- `lpBuffer` → les données à écrire (shellcode, chemin DLL, etc.)

---

### VirtualFreeEx
```c
BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress,
                     SIZE_T dwSize, DWORD dwFreeType);
```
**Quoi** : Libère la mémoire allouée dans un autre processus. Nettoyage.

---

## 🔍 Énumération de processus

### CreateToolhelp32Snapshot
```c
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
```
**Quoi** : Prend un snapshot de tous les processus (ou threads, modules) du système.
- `TH32CS_SNAPPROCESS` → snapshot des processus

**Retour** : handle du snapshot

---

### Process32First / Process32Next
```c
BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
```
**Quoi** : Parcourt les processus du snapshot un par un.
- `lppe->szExeFile` → nom du processus (ex: "notepad.exe")
- `lppe->th32ProcessID` → PID du processus

**Pattern classique** :
```c
Process32First(snapshot, &entry);
do {
    if (strcmp(entry.szExeFile, "notepad.exe") == 0) {
        // trouvé !
    }
} while (Process32Next(snapshot, &entry));
```

---

## 📚 Résolution de modules et fonctions

### GetModuleHandleA
```c
HMODULE GetModuleHandleA(LPCSTR lpModuleName);
```
**Quoi** : Retourne le handle d'un module (DLL) déjà chargé dans le processus.
- `NULL` → retourne le handle de l'exécutable courant
- `"kernel32.dll"` → retourne le handle de kernel32

---

### GetProcAddress
```c
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
```
**Quoi** : Retourne l'adresse d'une fonction exportée par un module.
**Usage** : Trouver l'adresse de `LoadLibraryA` dans `kernel32.dll` pour l'injection.

---

## 🔁 Message Loop (GUI / Hooks)

### GetMessage
```c
BOOL GetMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
```
**Quoi** : Récupère un message de la file de messages du thread. Bloque jusqu'au prochain message.
**Retour** : 0 quand `WM_QUIT` est reçu → la boucle se termine.

### TranslateMessage / DispatchMessage
```c
BOOL TranslateMessage(const MSG *lpMsg);
LRESULT DispatchMessage(const MSG *lpMsg);
```
**Quoi** : Traduit les messages clavier en caractères et les envoie à la fenêtre destinataire. Nécessaire pour que les hooks fonctionnent.

---

## 🔌 Pipes (Communication inter-processus)

### CreatePipe
```c
BOOL CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe,
                 LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
```
**Quoi** : Crée un pipe anonyme (tuyau unidirectionnel). Un bout pour lire, un bout pour écrire.
**Usage PHANTOM** : Relayer stdin/stdout de CMD dans le reverse shell.

**`SECURITY_ATTRIBUTES.bInheritHandle = TRUE`** → les handles sont héritables par les processus enfants.

---

### ReadFile / WriteFile
```c
BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
               LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
                LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
```
**Quoi** : Lire / écrire dans un handle (fichier, pipe, device).
**Usage** : Lire la sortie de CMD depuis le pipe, écrire les commandes dans le pipe.

---

## 🛡️ Divers utilitaires

### GetLastError
```c
DWORD GetLastError(void);
```
**Quoi** : Retourne le code d'erreur du dernier appel API qui a échoué. Indispensable pour le debug.

### ZeroMemory
```c
void ZeroMemory(PVOID Destination, SIZE_T Length);
```
**Quoi** : Met une zone mémoire à zéro. Alias de `memset(dest, 0, len)`.

### SetHandleInformation
```c
BOOL SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
```
**Quoi** : Modifie les propriétés d'un handle (héritable ou non).
**Usage** : Empêcher CMD d'hériter les bouts de pipe qu'on garde pour nous.

### CloseHandle
```c
BOOL CloseHandle(HANDLE hObject);
```
**Quoi** : Ferme un handle. Toujours fermer les handles qu'on n'utilise plus (mémoire, sécurité).

---

## 🎯 Résumé des chaînes d'appels par projet

### Port Scanner
```
WSAStartup → socket → connect → send → recv → close → WSACleanup
```

### Keylogger
```
SetWindowsHookExA → GetMessage loop → KeyboardProc callback
  → GetKeyboardState → ToUnicodeEx → fprintf → fflush
```

### Reverse Shell
```
WSAStartup → WSASocket → connect
  → CreatePipe (×2) → CreateProcessA (cmd.exe)
  → CreateThread (PipeToSocket) + CreateThread (SocketToPipe)
  → WaitForSingleObject
```

### Process Injection
```
CreateToolhelp32Snapshot → Process32First/Next (trouver le PID)
  → OpenProcess → VirtualAllocEx → WriteProcessMemory
  → GetModuleHandleA → GetProcAddress (LoadLibraryA)
  → CreateRemoteThread → WaitForSingleObject
```
