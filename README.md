# Advanced Python Firewall

## Overview

The **Advanced Python Firewall** is an advanced script designed for network monitoring and protection. Using the `scapy` library, this firewall script captures, inspects, and filters network packets, enforcing dynamic rules to safeguard your system against various attacks.

## Features

- **Packet Sniffing**: Capture and inspect network packets in real-time.
- **Attack Detection**: Identify and block attacks such as DDoS, DoS, ARP Spoofing, DNS Spoofing, and IP Spoofing.
- **Dynamic Rule Management**: Add or block IPs, ports, and domains dynamically.
- **Verbose Logging**: Print critical information and alerts for significant packet events and attack detections.

## Requirements

- **Python 3.x**
- **`Requierd` library**

To install the required library, run:

```
pip install scapy
```
## Usage
Start Sniffing Packets
To start sniffing packets on a specific network interface and capture up to a set number of packets, use the following command:


```sudo python3 firewall.py -sniff -interface eth0 -max_packets 100```<br>

Replace eth0 with your network interface and 100 with the desired number of packets to capture before stopping.

Modify Firewall Rules
Add IP to Allowed List:

```sudo python3 firewall.py -add_ip 192.168.1.20```<br>
Block IP:<br>

```sudo python3 firewall.py -block_ip 203.0.113.2```<br>
Add Port to Allowed List:<br>


```sudo python3 firewall.py -add_port 8080```<br>
Block Port:<br>


```sudo python3 firewall.py -block_port 22```<br>
Add Domain to Allowed List:<br>

```sudo python3 firewall.py -add_domain safe.com```<br>
Block Domain:<br>

```sudo python3 firewall.py -block_domain unsafe.com```<br>
Display Current Rules<br>
To view the current firewall rules:<br>

```sudo python3 firewall.py -logs```<br>

```sh
Command Line Arguments<br>
-sniff: Start packet sniffing.<br>
-interface <interface>: Specify the network interface to use (default: eth0).<br>
-max_packets <number>: Maximum number of packets to capture before stopping.<br>
-add_ip <IP>: Add an IP address to the allowed list.<br>
-block_ip <IP>: Block an IP address.<br>
-add_port <port>: Add a port to the allowed list.<br>
-block_port <port>: Block a port.<br>
-add_domain <domain>: Add a domain to the allowed list.<br>
-block_domain <domain>: Block a domain.<br>
-logs: Display current firewall rules and logs of sniffed packets.<br>
```

## Security and Privacy<br>
This script is intended for educational purposes and basic network protection. It should not be used as a replacement for professional-grade firewall solutions in production environments.


Contact
For questions or feedback, please contact me on Telegram : @jkak4
or, in instagram : @esefkh740_

### Key Improvements:

1. **Improved Formatting**: Clearer and more structured layout with appropriate headings and code blocks.
2. **Detailed Instructions**: Enhanced explanations on how to use each command-line argument.
3. **Security Note**: Clarified that the script is for educational use and not for production.

This `README.md` provides a comprehensive guide for users.
