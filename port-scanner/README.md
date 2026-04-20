# Port Scanner

A lightweight TCP port scanner written in C, demonstrating raw socket programming, DNS resolution, and service fingerprinting through banner grabbing.

## What it does

Scans a range of TCP ports on a target host and identifies running services by capturing banners or probing with HTTP requests.

```
$ ./scanner scanme.nmap.org 20 100
[*] PHANTOM Scanner — Target: scanme.nmap.org (45.33.32.156)
[*] Range: 20-100

  [+] Port 22    OPEN  | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  [+] Port 80    OPEN  | HTTP/1.1 200 OK Server: Apache/2.4.7 (Ubuntu)

[*] Scan complete. 2 open port(s) found.
```

## How it works

The scanner operates in three stages:

**1. DNS Resolution (`getaddrinfo`)**
Unlike `inet_pton` which only handles IP strings, `getaddrinfo` performs proper DNS resolution, returning a linked list of address structures. The first IPv4 address is extracted and used for subsequent connections.

**2. TCP Connection Attempt (`connect`)**
For each port in the range, a TCP socket is created and a non-blocking connection is attempted with a 2-3 second timeout. A successful `connect()` means the port is open; connection refused means closed; timeout typically means filtered (firewall).

**3. Banner Grabbing**
When a port is open, the scanner first listens for a spontaneous banner (SSH, FTP, SMTP send a greeting on connection). If the service doesn't speak first, the scanner sends a minimal HTTP HEAD request to elicit a response, which typically reveals web server identification.

## Build & Run

```bash
gcc scanner.c -o scanner
./scanner <host> <port_start> <port_end>
```

## Key concepts demonstrated

- Socket API (`socket`, `connect`, `send`, `recv`)
- DNS resolution with `getaddrinfo` / `freeaddrinfo`
- Socket timeouts via `setsockopt(SO_SNDTIMEO, SO_RCVTIMEO)`
- Service fingerprinting through banner analysis
- Network byte order (`htons`)

## Defensive signatures

This scanner is noisy by design — it performs full TCP handshakes on every port. Defenders typically detect this behavior through:

- **Connection rate anomalies**: Many short-lived connections to sequential ports from the same source
- **SYN flood signatures**: IDS rules like Snort's `sid:469` (ICMP PING NMAP)
- **Banner grab detection**: EDR may flag the specific HTTP HEAD pattern

Stealthier scanning requires SYN scanning (half-open), which itself requires raw sockets and root privileges — a possible future improvement.

## Limitations

- **Single-threaded**: Ports are scanned sequentially. Scanning 1-65535 with a 2-second timeout would take ~36 hours. A production scanner uses worker threads or async I/O.
- **TCP only**: No UDP scanning, which requires different detection logic (no handshake).
- **No stealth**: Full TCP handshakes are trivially logged by any monitoring system.
