PCAP Analysis Tool
Project Description
This Python-based tool analyzes PCAP (Packet Capture) files, providing insights into network traffic. It processes basic packet information, 
analyzes protocol distribution, and identifies top talkers in the network. 
The results are stored in a SQLite database for easy querying and visualization.
Features

Load and process PCAP files
Extract basic packet information (source IP, destination IP, protocol, length, timestamp)
Analyze protocol distribution
Identify top talkers (most active IP addresses)
Store results in a SQLite database
Display results in a tabular format

Pcap files are saved via wireshark. PCAP files are not provided. 

Dependencies

pyshark
sqlite3
tabulate

Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
License
This project is licensed under the MIT License - see the LICENSE file for details.
