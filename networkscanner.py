#! /usr/bin/env python

import scapy.all as scapy
import argparse
import sys


def print_banner():
    """
    Print a banner for the script with the name "Arun Ravi".
    """
    banner = """
        #     #
        ##    #  ######   #####  #    #   ####   #####   #    #
        # #   #  #          #    #    #  #    #  #    #  #   #
        #  #  #  #####      #    #    #  #    #  #    #  ####
        #   # #  #          #    # ## #  #    #  #####   #  #
        #    ##  #          #    ##  ##  #    #  #   #   #   #
        #     #  ######     #    #    #   ####   #    #  #    #

         #####
        #     #   ####     ##    #    #  #    #     #    #    #   ####
        #        #    #   #  #   ##   #  ##   #     #    ##   #  #    #
         #####   #       #    #  # #  #  # #  #     #    # #  #  #
              #  #       ######  #  # #  #  # #     #    #  # #  #  ###
        #     #  #    #  #    #  #   ##  #   ##     #    #   ##  #    #
         #####    ####   #    #  #    #  #    #     #    #    #   ####
          
                                                           by Arun Ravi
    """
    print(banner)


def get_arguments():
    """
    Parse command-line arguments to get the target IP address.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP address. Use --help for more info.")
    return options


def scan(ip):
    """
    Send ARP requests to the specified IP address and collect responses.
    """
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            clients_dict = {"IP Address": element[1].psrc, "MAC Address": element[1].hwsrc}
            clients_list.append(clients_dict)
        return clients_list
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def print_result(result_list):
    """
    Print the scan results in a formatted table.
    """
    if not result_list:
        print("[-] No results to print.")
        return

    print("IP Address\t\t\tMAC Address\n" + "-" * 50)
    for client in result_list:
        print(f"{client['IP Address']}\t\t{client['MAC Address']}")


def main():
    """
    Main function to orchestrate the scanning process.
    """
    print_banner()
    options = get_arguments()
    scan_result = scan(options.target)
    if scan_result:
        print_result(scan_result)
    else:
        print("[-] Exiting due to errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
