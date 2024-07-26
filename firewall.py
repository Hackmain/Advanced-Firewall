import argparse
import logging
import socket
from scapy.all import sniff, IP, TCP, UDP, ARP, DNS
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Event, Thread

# Setup logging to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define initial firewall rules and thresholds
ALLOWED_IPS = ["192.168.1.10", "10.0.0.5"]
BLOCKED_IPS = ["203.0.113.1", "198.51.100.2"]
ALLOWED_PORTS = [80, 443]
BLOCKED_PORTS = [22]
ALLOWED_DOMAINS = ["example.com"]
BLOCKED_DOMAINS = ["malicious.com"]

# Attack detection thresholds
DDoS_THRESHOLD = 1000  # Packets per minute for DDoS
DO_S_THRESHOLD = 500   # Packets per minute for DoS
RATE_LIMIT_WINDOW = timedelta(minutes=1)

# Global variables for packet tracking
PACKET_COUNT = defaultdict(int)
LAST_SEEN = defaultdict(datetime)
ARP_TABLE = {}
ARP_SPOOF_DETECTED = False
DNS_SPOOF_DETECTED = False
IP_SPOOF_DETECTED = defaultdict(bool)

# Event for controlling sniffing
sniffing_event = Event()
packet_counter = 0
max_packets = None

def resolve_domain(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except socket.herror:
        return None

def packet_filter(packet):
    global ARP_SPOOF_DETECTED, DNS_SPOOF_DETECTED, IP_SPOOF_DETECTED

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_info = f"Packet: {ip_src} -> {ip_dst}"

        # Rate Limiting for DDoS and DoS Protection
        now = datetime.now()
        if ip_src not in LAST_SEEN or (now - LAST_SEEN[ip_src]) > RATE_LIMIT_WINDOW:
            PACKET_COUNT[ip_src] = 0
        PACKET_COUNT[ip_src] += 1
        LAST_SEEN[ip_src] = now

        # DDoS Detection
        if PACKET_COUNT[ip_src] > DDoS_THRESHOLD:
            logging.warning(f"DDoS Protection: Blocking IP {ip_src} due to rate limit exceedance")
            if ip_src not in BLOCKED_IPS:
                BLOCKED_IPS.append(ip_src)

        # DoS Detection
        elif PACKET_COUNT[ip_src] > DO_S_THRESHOLD:
            logging.warning(f"DoS Protection: Blocking IP {ip_src} due to rate limit exceedance")
            if ip_src not in BLOCKED_IPS:
                BLOCKED_IPS.append(ip_src)

        # IP Spoofing Detection
        if ip_src not in ALLOWED_IPS and not IP_SPOOF_DETECTED[ip_src]:
            logging.warning(f"IP Spoofing Detected from IP {ip_src}")
            IP_SPOOF_DETECTED[ip_src] = True

        # Check if the packet should be allowed or blocked
        if ip_src in BLOCKED_IPS or ip_dst in BLOCKED_IPS:
            logging.info(f"Blocked packet {packet_info}")
            return

        if ip_src in ALLOWED_IPS or ip_dst in ALLOWED_IPS:
            port_src = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
            port_dst = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

            if port_src in BLOCKED_PORTS or port_dst in BLOCKED_PORTS:
                logging.info(f"Blocked packet {packet_info}")
                return

            if port_src in ALLOWED_PORTS or port_dst in ALLOWED_PORTS:
                logging.info(f"Allowed packet {packet_info}")

        # Domain Filtering
        if DNS in packet:
            dns_query = packet[DNS].qd.qname.decode()  # Decode DNS query name
            if any(domain in dns_query for domain in BLOCKED_DOMAINS):
                logging.warning(f"Blocked DNS Query for domain {dns_query}")
                return
            if any(domain in dns_query for domain in ALLOWED_DOMAINS):
                logging.info(f"Allowed DNS Query for domain {dns_query}")

    # MITM Detection: ARP Spoofing
    if ARP in packet:
        arp_src_ip = packet[ARP].psrc
        arp_src_mac = packet[ARP].hwsrc
        if arp_src_ip in ARP_TABLE and ARP_TABLE[arp_src_ip] != arp_src_mac:
            logging.warning(f"MITM Attack Detected: ARP Spoofing from IP {arp_src_ip} with MAC {arp_src_mac}")
            ARP_SPOOF_DETECTED = True
        ARP_TABLE[arp_src_ip] = arp_src_mac

    # MITM Detection: DNS Spoofing
    if DNS in packet:
        dns_query = packet[DNS].qd.qname.decode()  # Decode DNS query name
        dns_ip_src = packet[IP].src
        if DNS_SPOOF_DETECTED:
            logging.warning(f"DNS Spoofing Detected from IP {dns_ip_src} with Query {dns_query}")
            DNS_SPOOF_DETECTED = False  # Reset after detection

def packet_callback(packet):
    global packet_counter

    try:
        if IP in packet:
            # Important packets only: Log and display relevant information
            logging.info(f"Received packet: {packet.summary()}")
            packet_filter(packet)

            # Increment packet counter and check if it exceeds the maximum limit
            packet_counter += 1
            if max_packets is not None and packet_counter >= max_packets:
                logging.info(f"Captured {packet_counter} packets. Stopping sniffing.")
                sniffing_event.set()  # Signal to stop sniffing
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def sniff_packets(interface: str):
    logging.info(f"Sniffing packets on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: sniffing_event.is_set())

def modify_lists(action, ip=None, port=None, domain=None, list_type=None):
    global ALLOWED_IPS, BLOCKED_IPS, ALLOWED_PORTS, BLOCKED_PORTS, ALLOWED_DOMAINS, BLOCKED_DOMAINS

    if list_type == "ip":
        if action == "add":
            if ip not in ALLOWED_IPS and ip not in BLOCKED_IPS:
                ALLOWED_IPS.append(ip)
                logging.info(f"Added IP {ip} to allowed list.")
            elif ip in BLOCKED_IPS:
                BLOCKED_IPS.remove(ip)
                ALLOWED_IPS.append(ip)
                logging.info(f"Moved IP {ip} from blocked to allowed list.")
        elif action == "block":
            if ip in ALLOWED_IPS:
                ALLOWED_IPS.remove(ip)
                logging.info(f"Removed IP {ip} from allowed list.")
            if ip not in BLOCKED_IPS:
                BLOCKED_IPS.append(ip)
                logging.info(f"Blocked IP {ip}.")

    elif list_type == "port":
        if action == "add":
            if port not in ALLOWED_PORTS and port not in BLOCKED_PORTS:
                ALLOWED_PORTS.append(port)
                logging.info(f"Added port {port} to allowed list.")
            elif port in BLOCKED_PORTS:
                BLOCKED_PORTS.remove(port)
                ALLOWED_PORTS.append(port)
                logging.info(f"Moved port {port} from blocked to allowed list.")
        elif action == "block":
            if port in ALLOWED_PORTS:
                ALLOWED_PORTS.remove(port)
                logging.info(f"Removed port {port} from allowed list.")
            if port not in BLOCKED_PORTS:
                BLOCKED_PORTS.append(port)
                logging.info(f"Blocked port {port}.")

    elif list_type == "domain":
        if action == "add":
            if domain not in ALLOWED_DOMAINS and domain not in BLOCKED_DOMAINS:
                ALLOWED_DOMAINS.append(domain)
                logging.info(f"Added domain {domain} to allowed list.")
            elif domain in BLOCKED_DOMAINS:
                BLOCKED_DOMAINS.remove(domain)
                ALLOWED_DOMAINS.append(domain)
                logging.info(f"Moved domain {domain} from blocked to allowed list.")
        elif action == "block":
            if domain in ALLOWED_DOMAINS:
                ALLOWED_DOMAINS.remove(domain)
                logging.info(f"Removed domain {domain} from allowed list.")
            if domain not in BLOCKED_DOMAINS:
                BLOCKED_DOMAINS.append(domain)
                logging.info(f"Blocked domain {domain}.")

    # Display updated rules
    display_rules()

def display_rules():
    logging.info("Current Firewall Rules:")
    logging.info("Allowed IPs: %s", ALLOWED_IPS)
    logging.info("Blocked IPs: %s", BLOCKED_IPS)
    logging.info("Allowed Ports: %s", ALLOWED_PORTS)
    logging.info("Blocked Ports: %s", BLOCKED_PORTS)
    logging.info("Allowed Domains: %s", ALLOWED_DOMAINS)
    logging.info("Blocked Domains: %s", BLOCKED_DOMAINS)

def main():
    global sniffing_event, max_packets

    parser = argparse.ArgumentParser(description="Advanced Python Firewall")
    parser.add_argument('-sniff', action='store_true', help="Start sniffing network packets")
    parser.add_argument('-interface', type=str, default='eth0', help="Network interface to sniff packets on")
    parser.add_argument('-max_packets', type=int, help="Maximum number of packets to capture before stopping")
    parser.add_argument('-add_ip', type=str, help="Add IP to allowed list")
    parser.add_argument('-block_ip', type=str, help="Block IP to blocked list")
    parser.add_argument('-add_port', type=int, help="Add port to allowed list")
    parser.add_argument('-block_port', type=int, help="Block port to blocked list")
    parser.add_argument('-add_domain', type=str, help="Add domain to allowed list")
    parser.add_argument('-block_domain', type=str, help="Block domain to blocked list")
    parser.add_argument('-logs', action='store_true', help="Show logs of sniffed packets")

    args = parser.parse_args()

    sniffing_event = Event()  # Event to control sniffing

    if args.sniff:
        max_packets = args.max_packets
        sniffing_thread = Thread(target=sniff_packets, args=(args.interface,))
        sniffing_event.clear()
        sniffing_thread.start()
        sniffing_thread.join()  # Wait for sniffing thread to complete
    elif args.add_ip:
        modify_lists("add", ip=args.add_ip, list_type="ip")
    elif args.block_ip:
        modify_lists("block", ip=args.block_ip, list_type="ip")
    elif args.add_port:
        modify_lists("add", port=args.add_port, list_type="port")
    elif args.block_port:
        modify_lists("block", port=args.block_port, list_type="port")
    elif args.add_domain:
        modify_lists("add", domain=args.add_domain, list_type="domain")
    elif args.block_domain:
        modify_lists("block", domain=args.block_domain, list_type="domain")
    elif args.logs:
        display_rules()  # Display current rules as logs
    else:
        logging.error("Please specify an option. Use -sniff to start sniffing packets, -add_ip to add IP, -block_ip to block IP, -add_port to add port, -block_port to block port, -add_domain to add domain, or -block_domain to block domain.")

if __name__ == "__main__":
    main()
