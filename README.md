

---

# Packet Sniffer Tool

A simple Python-based packet sniffer using the Scapy library. This tool allows you to capture network packets and log details about them, such as the source and destination IP addresses, the protocol in use (TCP or UDP), and more.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Examples](#examples)
- [Disclaimer](#disclaimer)
- [License](#license)

## Installation

1. Ensure you have Python installed on your system.
2. Install the Scapy library:

   ```bash
   pip install scapy
   ```

3. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   ```

## Usage

Run the script with the following options:

```bash
python packet_sniffer.py [--protocol tcp|udp|all] [--count COUNT] [--output FILE]
```

### Options:
- `--protocol`: Specify which packets to capture (TCP, UDP, or all protocols). Default is `all`.
- `--count`: Number of packets to capture. Default is `10`.
- `--output`: Log output to a specified file instead of printing it to the console.

### Example:

To capture 20 TCP packets and log the output to a file:

```bash
python packet_sniffer.py --protocol tcp --count 20 --output packet_log.txt
```

## Features

- **Protocol Filtering**: Capture specific protocols (`TCP`, `UDP`) or all protocols.
- **Packet Logging**: Logs packets to a file or prints them to the console.
- **Packet Details**: For each packet, the tool logs:
  - Timestamp
  - Source IP and Port
  - Destination IP and Port
  - Protocol (TCP/UDP)
- **Command-line Arguments**: Flexible usage with command-line options for packet count, protocol, and output.

## Examples

1. **Capture 50 packets of any protocol**:
    ```bash
    python packet_sniffer.py --count 50
    ```

2. **Capture only UDP packets**:
    ```bash
    python packet_sniffer.py --protocol udp --count 10
    ```

3. **Log TCP packets to a file**:
    ```bash
    python packet_sniffer.py --protocol tcp --output output.log
    ```

## Disclaimer

This tool is meant for educational purposes only. Ensure that you have permission to sniff traffic on the network you are capturing from. Unauthorized use of this tool may be illegal and unethical.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
