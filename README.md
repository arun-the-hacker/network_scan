# network_scan
ARP Network Scanner

This Python script performs an ARP (Address Resolution Protocol) scan on the local network to discover active devices and their corresponding MAC addresses.
Usage

    Clone the Repository:

    bash

git clone https://github.com/yourusername/arp-network-scanner.git

Navigate to the Project Directory:

bash

cd arp-network-scanner

Run the Script:

bash

    python arp_scanner.py -t <target_ip>

    Replace <target_ip> with the IP address of the target network (e.g., 192.168.1.0/24).

Requirements

    Python 3

    scapy library

    Install the library using pip:

    bash

    pip install scapy

Options

    -t, --target: Specify the target IP address or IP range to scan.

Example

bash

python arp_scanner.py -t 192.168.1.0/24

Author

This script was created by Arun Ravi.
License

This project is licensed under the MIT License - see the LICENSE file for details.

You can place this README.md file in the root directory of your project repository. Make sure to update the GitHub repository URL and other details accordingly.
