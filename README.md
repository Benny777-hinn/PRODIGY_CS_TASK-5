# PRODIGY_CS_TASK-5
# Educational Packet Sniffer (Python + Scapy)

This is a **simple, educational packet sniffer** written in Python using **Scapy**.  
It captures live network traffic and shows:

- Source and destination IP addresses
- Source and destination ports (for TCP/UDP)
- Protocol (TCP/UDP/ICMP/IP)
- Packet length
- Optional payload preview (hex + ASCII, truncated)

> **Ethical use only:** This tool is for learning and lab environments.  
> Only capture traffic on networks you **own** or where you have **explicit written permission**.

---

## 1. Prerequisites

- **Python 3.9+** installed
- Internet or local access to install Python packages

### Windows-specific

On Windows, Scapy needs a capture driver:

1. Install **Npcap** from the official site (choose the *WinPcap compatible mode* option).
2. Run your terminal (PowerShell or cmd) as **Administrator** when using this sniffer.

---

## 2. Install dependencies

In a terminal inside this project folder:

```bash
pip install -r requirements.txt
```

If you have multiple Python versions, you may need:

```bash
python -m pip install -r requirements.txt
# or
py -m pip install -r requirements.txt
```

---

## 3. Running the sniffer

Basic usage (default interface, unlimited packets until Ctrl+C):

```bash
python sniffer.py
```

Common options:

- `-i/--interface` – interface name (depends on OS)
- `-c/--count` – number of packets to capture (0 = until Ctrl+C)
- `-p/--protocol` – simple filter: `ip`, `tcp`, `udp`, `icmp`
- `--show-payload` – show a short payload preview
- `--bpf-filter` – optional BPF filter passed to Scapy/libpcap

### Examples

**Capture 20 TCP packets on default interface:**

```bash
python sniffer.py -c 20 -p tcp
```

**Capture indefinitely and show payload:**

```bash
python sniffer.py --show-payload
```

**Capture HTTP (port 80) traffic only:**

```bash
python sniffer.py --bpf-filter "tcp port 80"
```

On Windows, if `python` doesn’t work, try:

```bash
py sniffer.py ...
```

---

## 4. Understanding the output

Example line:

```text
[12:34:56.789] TCP     192.168.1.10:52543 -> 142.250.185.68:443 len=74
```

- **`[12:34:56.789]`** – timestamp when packet was seen
- **`TCP`** – protocol
- **`192.168.1.10:52543`** – source IP and port
- **`142.250.185.68:443`** – destination IP and port
- **`len=74`** – full packet length in bytes

If `--show-payload` is enabled, you’ll also see:

```text
    HEX: 16 03 01 00 45 01 ...
    ASCII: .....E..
```

Payload is truncated to keep output readable.

---

## 5. Legal and ethical notice

- **Do not use this tool on networks you do not own or control.**
- **Do not intercept traffic without explicit permission from the owner.**
- Many countries have strict **wiretap**, **privacy**, and **computer misuse** laws.
- Use this tool strictly for:
  - Personal lab environments
  - Classroom exercises
  - CTFs or ranges where capture is allowed

By running this tool, **you accept full responsibility** for how you use it.

---

## 6. Troubleshooting

- **PermissionError / Access denied**
  - Windows: run PowerShell/cmd *as Administrator*
  - Linux/macOS: use `sudo python sniffer.py ...`

- **No packets captured**
  - Check that the interface name is correct
  - Make sure there is traffic on that interface (e.g. open a browser)
  - On Windows, confirm Npcap is installed correctly

- **ImportError: No module named scapy**
  - Make sure `pip install -r requirements.txt` ran successfully
  - Verify you are using the same Python interpreter where Scapy is installed

---

## 7. Next steps for your learning

As a cybersecurity student, you can extend this tool to:

- Parse and pretty-print **DNS**, **HTTP**, or **TLS** details
- Save captured packets to a **pcap** file and open in Wireshark
- Add **coloring rules** for specific protocols
- Implement simple **intrusion detection** style checks (e.g. flag port scans)

Always keep everything inside a **controlled, authorized lab environment**.

