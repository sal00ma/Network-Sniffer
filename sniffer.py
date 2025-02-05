
from scapy.all import *
import time
import logging
import threading
from collections import defaultdict
import os

# Initialize logging for packet capturing
logging.basicConfig(filename="sniffer_output.log", level=logging.INFO)

# Dictionary to hold traffic statistics (for real-time reporting)
traffic_stats = defaultdict(int)

# This function logs captured packets and displays protocol-specific information
def log_packet(packet):
    # Print packet summary to console
    print(packet.summary())

    # Log packet summary to file
    logging.info(f"Timestamp: {time.time()} - {packet.summary()}")

    # Handle DNS packets (if the packet contains DNS)
    if packet.haslayer(DNS):
        dns_query = packet[DNS].qd.qname.decode('utf-8')
        print(f"DNS Query: {dns_query}")
        logging.info(f"DNS Query: {dns_query}")

    # Handle HTTP packets (looking for HTTP GET/POST)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')  # Decode the raw payload
        if "GET" in payload or "POST" in payload:
            print(f"HTTP Request: {payload}")
            logging.info(f"HTTP Request: {payload}")

    # Update traffic stats
    update_traffic_stats(packet)

# Function to update traffic statistics
def update_traffic_stats(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        traffic_stats[ip_src] += len(packet)
        traffic_stats[ip_dst] += len(packet)

# Function to capture packets with protocol-specific filters
def capture_packets(filter=None, count=None):
    # Sniff packets and process them with the log_packet callback
    sniff(prn=log_packet, store=0, filter=filter, count=count)

# Function to display real-time traffic statistics
def display_traffic_stats():
    while True:
        time.sleep(10)  # Update stats every 10 seconds
        print("\nTraffic Stats (Last 10 seconds):")
        for ip, bytes in traffic_stats.items():
            print(f"{ip}: {bytes} bytes")
        traffic_stats.clear()  # Reset stats after displaying

# Function to handle saving captured packets to a .pcap file
def save_to_pcap(packets, filename="captured_packets.pcap"):
    wrpcap(filename, packets)

# Example: Capture DNS traffic
def capture_dns_traffic():
    capture_packets(filter="udp port 53", count=50)  # DNS uses UDP port 53

# Example: Capture HTTP traffic
def capture_http_traffic():
    capture_packets(filter="tcp port 80", count=50)  # HTTP traffic (TCP port 80)

# Example: Capture all packets
def capture_all_traffic():
    capture_packets(filter=None, count=100)  # No filter, capture all traffic

# Example: Capture packets with advanced filtering (e.g., capture DNS and HTTP)
def capture_filtered_traffic():
    capture_packets(filter="udp port 53 or tcp port 80", count=50)

# Function to capture and analyze traffic with detailed protocol inspection
def capture_and_analyze():
    # Capture HTTP and DNS traffic in the background
    capture_thread = threading.Thread(target=capture_filtered_traffic)
    capture_thread.start()

    # Start displaying real-time traffic statistics
    stats_thread = threading.Thread(target=display_traffic_stats)
    stats_thread.start()

    # Wait for both threads to finish (they will run indefinitely until manually stopped)
    capture_thread.join()
    stats_thread.join()

# Main execution
if __name__ == "__main__":
    # Start the sniffer and traffic stats reporting
    capture_and_analyze()
