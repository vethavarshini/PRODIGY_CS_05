# PRODIGY_CS_05
# Network Packet Analyzer

This project provides a packet sniffer tool that captures and analyzes network packets in Python. It displays relevant information such as source and destination IP addresses, protocols, and payload data. The tool is designed for educational purposes to understand network traffic and protocols.

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/vethavarshini/PRODIGY_CS_05.git
    ```

2. Navigate to the project directory:

    ```bash
    cd packet_analyzer
    ```

3. Run the application:

    ```bash
    python packet_analyzer.py
    ```

4. The GUI window will appear displaying options to start and stop packet sniffing.

5. Click the "Start Sniffing" button to begin capturing network packets.

6. Once packets are captured, relevant information such as packet number, timestamp, source and destination MAC and IP addresses, ports, protocol, and payload length will be displayed in a tabular format.

7. Click the "Stop Sniffing" button to stop packet sniffing.

8. Double-click on a packet entry to view detailed information about the packet.

## Requirements

- Python 3.x
- tkinter library (usually included in Python installations)
- scapy library

Install scapy library using pip:

```bash
pip install scapy

