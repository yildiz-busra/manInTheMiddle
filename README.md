# manInTheMiddle

A collection of Python scripts for demonstrating and performing various Man-in-the-Middle (MitM) attacks and network analysis techniques.

## Overview

This project is designed for educational and research purposes, showcasing how common network attacks work and how network traffic can be analyzed or manipulated by an attacker. It includes scripts for ARP poisoning, packet sniffing, TCP hijacking, and basic network scanning.

## Features

- **ARP Poisoning (`ARPpoison.py`)**: 
  - Spoofs ARP responses to perform MitM attacks in a LAN.
  - Enables IP forwarding for packet relay.
  - Includes reset to clean up ARP tables after attack.
- **Packet Listener (`packetListener.py`)**:
  - Sniffs HTTP traffic on a given network interface.
  - Extracts URLs and data payloads from packets.
- **TCP Hijacking (`hijack.py`)**:
  - Injects arbitrary payloads into an active TCP session.
  - Customizable for victim/server ports, sequence, and acknowledgment numbers.
- **Network Scanner (`netScanner(1).py`)**:
  - Scans a target IP for active hosts using ARP requests.

## Usage

### Prerequisites

- Python 3.x
- scapy (`pip install scapy`)
- Administrative/root privileges for some scripts (e.g., ARP poisoning)

### Running the Scripts

#### ARP Poisoning

```bash
sudo python ARPpoison.py -i <target_ip> -g <gateway_ip>
```

#### Packet Listener

```bash
sudo python packetListener.py -i <network_interface>
```

#### TCP Hijacking

```bash
sudo python hijack.py -p <victim_port> -q <server_port> -S <seq_num> -A <ack_num>
```

#### Network Scanner

```bash
python netScanner(1).py -i <target_ip>
```

## Disclaimer

These scripts are for educational and authorized testing purposes only. Do not use them on networks where you do not have explicit permission.

## Author

[Busra Yildiz](https://github.com/yildiz-busra)

---
*Contributions and feedback are welcome!*
