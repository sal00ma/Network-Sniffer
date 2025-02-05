# Network-Sniffer
This advanced network sniffer is a powerful tool for monitoring network traffic. It captures and decodes different types of packets (like DNS, HTTP), provides real-time traffic statistics, and logs captured packets for further analysis. 

# Key Features and Enhancements:
 Logging and Timestamping:

Every captured packet is logged with a timestamp to a file sniffer_output.log, and the packet summary is printed to the console.
DNS queries and HTTP requests are also logged separately, which helps to identify domain name lookups and HTTP traffic.
DNS Query Extraction:

The script checks for packets containing DNS requests (UDP port 53) and extracts the domain names being queried.
Example: If a DNS query for www.example.com is captured, it will print and log the domain name.
HTTP Request Detection:

The sniffer looks for HTTP traffic (TCP port 80) and extracts the HTTP headers, including GET and POST requests.
Example: It will log HTTP requests and display them, such as GET /index.html HTTP/1.1.
Traffic Statistics:

Real-time statistics are generated for each captured packet, displaying the number of bytes sent/received by each IP address.
Traffic stats are printed every 10 seconds and reset after each update.
Capture Specific Protocols:

You can customize the filter argument in the capture_packets() function to capture specific types of traffic (e.g., DNS, HTTP, or all traffic).
For example:
filter="udp port 53" captures only DNS traffic.
filter="tcp port 80" captures HTTP traffic.
Saving Packets to a .pcap File:

The save_to_pcap() function saves captured packets into a .pcap file for later analysis. This file can be opened using tools like Wireshark.
Multithreading for Concurrent Operations:

The script uses Python's threading module to handle packet capturing and traffic stats reporting simultaneously, without blocking each other.
This allows for real-time analysis while capturing packets.
