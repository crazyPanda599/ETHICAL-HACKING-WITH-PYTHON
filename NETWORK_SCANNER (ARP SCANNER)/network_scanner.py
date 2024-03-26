#!/usr/bin/env python

import scapy.all as scapy
#import optparse        # is deprecated and will likely be removed in the future. BUt still work with python3
import argparse         # argparse is recommended over optparse

def get_arguments():
    parser = argparse.ArgumentParser(description="IP Range to scan the Network")
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range")
    args = parser.parse_args()
    if not args.target:
        parser.error("[-] Please specify an target IP/IP_Range, use --help for more info.")
    return args

# def get_arguments():
#     parser = optparse.OptionParser()
#     parser.add_option("-t", "--target", dest="target", help="Target IP/IP Range")
#     (options, arguments) = parser.parse_args()
#     if not options.target:
#         parser.error("[-] Please specify an target IP/IP_Range, use --help for more info.")
#     return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dic)
    return client_list

def scan_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_list = scan(options.target)
scan_result(scan_list)