# 🔍 netanalyzer – Network Analysis Tool in C++

> Real-time network packet capture and threat detection using **C++** and **libpcap**.  
> Author: **Marc Kambou Kengnang** – Computer Engineering @ HTW Berlin

---

## ✨ Features

- ✅ Real-time packet capture on any network interface
- ✅ Protocol detection: TCP, UDP, ICMP, ARP
- ✅ Service identification: HTTP, HTTPS, SSH, FTP, DNS, DHCP
- ✅ **Port scan detection** (flags suspicious IPs scanning multiple ports)
- ✅ **ICMP flood detection**
- ✅ Top talkers ranking (most active IP addresses)
- ✅ Coloured terminal output for fast readability
- ✅ CSV log export for analysis in Wireshark or Excel
- ✅ BPF filter support (e.g. `"tcp"`, `"udp port 53"`)
- ✅ Save captures as `.pcap` files (readable in Wireshark)

---

## 📁 Project Structure

```
netanalyzer/
├── main.cpp        # Entry point – argument parsing, main loop
├── capture.h/cpp   # libpcap wrapper – packet capture & parsing
├── analyzer.h/cpp  # Protocol analysis & threat detection
├── display.h/cpp   # Coloured terminal output
├── logger.h/cpp    # CSV log file writer
├── Makefile        # Build system
└── README.md       # Documentation
```

---

## 🚀 Installation & Build

### Requirements
- Linux (Debian / Ubuntu)
- `g++` with C++17 support
- `libpcap-dev`

### Install dependencies
```bash
sudo apt update
sudo apt install g++ libpcap-dev -y
```

### Build
```bash
git clone https://github.com/6802Obala/netanalyzer.git
cd netanalyzer
make
```

---

## 🖥 Usage

```bash
# Basic – auto-detect interface
sudo ./netanalyzer

# Specify interface
sudo ./netanalyzer -i eth0

# Apply BPF filter (TCP only)
sudo ./netanalyzer -i eth0 -f "tcp"

# Capture 200 packets and save to file
sudo ./netanalyzer -i eth0 -c 200 -o capture.pcap

# Monitor DNS traffic only
sudo ./netanalyzer -i eth0 -f "udp port 53"

# Stop with Ctrl+C
```

### Options

| Flag | Description |
|------|-------------|
| `-i <interface>` | Network interface (default: auto-detect) |
| `-f <filter>` | BPF filter expression |
| `-o <file.pcap>` | Save capture to `.pcap` file |
| `-c <count>` | Stop after N packets |
| `-h` | Show help |

---

## 📊 Sample Output

```
  ╔══════════════════════════════════════════════════════╗
  ║        🔍  NETWORK ANALYZER  –  C++ / libpcap       ║
  ║        Author : Marc Kambou Kengnang                ║
  ╚══════════════════════════════════════════════════════╝

  [*] Interface : eth0
  [*] Filter    : tcp

  14:32:01.042   TCP   192.168.1.5:52341  →  142.250.74.46:443    128B  HTTPS  [SYN]
  14:32:01.043   UDP   192.168.1.5:51234  →   8.8.8.8:53           60B  DNS
  14:32:01.120   ICMP  192.168.1.10       →  192.168.1.1            84B  Ping
  14:32:01.200   TCP   10.0.0.4:12345     →  192.168.1.5:22         74B  SSH    [SYN]
  ⚠ PORT SCAN detected from 10.0.0.4 (17 unique ports)

  ── STATISTICS ────────────────────────────────────────
  Total packets : 250
  TCP           : 180
  UDP           :  45
  ICMP          :  20
  ARP           :   5
  Alerts        :   2

  TOP TALKERS
    192.168.1.5  →  142 packets
         10.0.0.4  →   58 packets
```

---

## 🛠 Technologies

| Technology | Usage |
|------------|-------|
| C++17 | Core language |
| libpcap | Low-level packet capture |
| Wireshark/tshark | `.pcap` file analysis |
| BPF (Berkeley Packet Filter) | Traffic filtering |
| POSIX sockets | IP/TCP/UDP header parsing |

---

## 🔒 Threat Detection

| Threat | Detection Method |
|--------|-----------------|
| Port Scan | Source IP contacts ≥ 15 unique destination ports |
| ICMP Flood | Source IP sends > 50 ICMP packets |

---

## 📄 License

MIT License – free to use and modify.

---

> Project developed as part of the Bachelor Computer Engineering curriculum – HTW Berlin
