# PCAP Analysis Tool

## Project Description
This Python-based tool analyzes PCAP (Packet Capture) files, providing insights into network traffic. It processes basic packet information, analyzes protocol distribution, and identifies top talkers in the network. The results are stored in a SQLite database for easy querying and visualization.

## Features
- Load and process PCAP files
- Extract basic packet information (source IP, destination IP, protocol, length, timestamp)
- Analyze protocol distribution
- Identify top talkers (most active IP addresses)
- Store results in a SQLite database
- Display results in a tabular format

## Please read the PDF file for more information. 

The end goal of the project was to create machine learning model that could predict anomalous network traffic by being given one PCAP file of local network data. Then, when a second pcap file is submitted. Network traffic is compared to the model to determine anomalies. 
This work was was completed using a different code base. Utilizing pytorch library and a basic anomaly detection model, however its use and accuracy is sub-optimal. These files will be added at a later date. 
## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
