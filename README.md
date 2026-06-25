# Network Packet Sniffer & Analyzer

A lightweight, real-time network packet sniffer built with Python and Scapy. It captures live traffic, decodes TCP flags, and actively alerts on insecure protocols and suspicious network behavior.

## Features

- **Real-time Packet Capture**: Sniffs packets with optional BPF (Berkeley Packet Filter) support.
- **TCP Flag Decoding**: Converts raw TCP flags (e.g., `S`, `A`, `F`) into human-readable names (e.g., `SYN`, `ACK`, `FIN`).
- **Security Alerts**:
  - **Unencrypted HTTP**: Alerts when traffic uses port 80 (plain HTTP).
  - **Suspicious DNS**: Alerts on DNS traffic (port 53) that does not involve your default router/gateway—useful for detecting abnormal DNS queries.
  - **Port Scan Detection**: Monitors SYN/ACK packets and alerts if a single source IP hits more than 10 distinct ports within a 1.1-second window.
- **Automatic Logging**: All output is appended to `record.log` with precise timestamps.

## Prerequisites

- **Python 3.6+**
- **Scapy**: Install via pip:
  ```bash
  pip install scapy
  ```

## Usage

### Basic Capture
Captures all packets until interrupted (Ctrl+C). Outputs to console and `record.log`.

```bash
sudo python sniffer.py
```

### Apply a BPF Filter
Only capture specific traffic (e.g., TCP, port 80, or a specific host).

```bash
sudo python sniffer.py --filter "tcp"
sudo python sniffer.py --filter "port 80"
sudo python sniffer.py --filter "host 192.168.1.100"
```

### Limit Packet Count
Capture a specific number of packets and exit automatically.

```bash
sudo python sniffer.py --count 50
```

### Port Scan Detection Mode
Monitor specifically for port scanning activity. **Note:** In this mode, the script ignores the `--filter` and `--count` arguments and focuses solely on TCP handshake packets.

```bash
sudo python sniffer.py --scan-detection True
```

## Command Line Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--filter` | `str` | `None` | BPF (Berkeley Packet Filter) string to filter captured traffic (e.g., `"tcp"`, `"port 443"`). |
| `--count` | `int` | `0` | Number of packets to capture. `0` means infinite (capture until Ctrl+C). |
| `--scan-detection` | `bool` | `False` | Enable port scan detection mode. Must be set to `True` to activate. |

## How the Alerts Work

### 1. HTTP Unencrypted Alert
If a packet uses the TCP protocol and either the source or destination port is **80**, the script flags it as unencrypted HTTP traffic.

> `[ Alert ] Unencrypted HTTP traffic`

### 2. Suspicious DNS Alert
The script detects your default router IP automatically. If a DNS packet (port 53) is sent or received, but **neither** the source nor the destination is the router, an alert is triggered. This helps catch unusual DNS resolutions that bypass your local DNS server.

> `[ Alert ] Suspicious DNS traffic: 10.0.0.50 -> 8.8.8.8`

### 3. Port Scan Detection
The script tracks SYN, SYN-ACK, and ACK packets. If a single source IP connects to **more than 10 different destination ports** within a time window of **less than 1.1 seconds**, it triggers a port scan alert.

> `[ALERT] Port scan detected from 192.168.1.101 — 15 ports in 0.9s`

## Logging

- All messages printed to the console are also appended to a file named **`record.log`** in the same directory as the script.
- Each log entry is prefixed with a timestamp:

```text
2026-06-24 14:23:45  [ TCP ] 192.168.1.10:54322 -> 142.250.185.46:80 | Flags: SYN
2026-06-24 14:23:45  [ Alert ] Unencrypted HTTP traffic
```

## Code Structure

| Function | Description |
|----------|-------------|
| `getFlags(flags)` | Converts raw TCP flag characters into readable names. |
| `log(s)` | Adds a timestamp and appends the message to `record.log`. |
| `process_packet(packet)` | Main handler for normal mode; parses IP, TCP, and UDP layers, prints output, and triggers alerts. |
| `scan_detection(packet)` | Specialized handler for port scan detection; tracks SYN/ACK packets per IP and alerts on anomalies. |
| `main()` | Parses command-line arguments and starts the appropriate sniffing routine. |

## Important Notes & Caveats

1. **Root/Admin Privileges**: Raw socket access requires elevated permissions.
2. **`--scan-detection` Argument Behavior**: The script expects the exact value `True` to activate scan detection. Because of how Python's `argparse` handles `type=bool`, providing `--scan-detection False` will **not** disable it (it will evaluate as `True`). To disable it, simply omit the argument.
3. **Router IP Detection**: The script uses `conf.route.route("0.0.0.0")[2]` to find your default gateway. Ensure your routing table is correctly configured for accurate DNS suspension checks.

## Example Output

```text
Starting capture... filter=none
2026-06-25 09:12:01  [ TCP ] 192.168.1.20:45123 -> 192.168.1.1:53 | Flags: SYN
2026-06-25 09:12:02  [ UDP ] 192.168.1.20:54321 -> 8.8.8.8:53
2026-06-25 09:12:02  [ Alert ] Suspicious DNS traffic: 192.168.1.20 -> 8.8.8.8
2026-06-25 09:12:05  [ TCP ] 10.0.0.15:50000 -> 93.184.216.34:80 | Flags: SYN
2026-06-25 09:12:05  [ Alert ] Unencrypted HTTP traffic
```

## License
This project is open-source 