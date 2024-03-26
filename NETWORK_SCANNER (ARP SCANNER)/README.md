# Network Scanner (ARP SCANNER)

A **network scanner** is a tool or application used to detect and categorize all devices in a network by their **IP addresses**, **MAC addresses**, **vendor**, **port**, and other relevant information. Here are some key points about network scanning:

- **Detection of Active Devices**: Network scanners help **identify all active hosts** on a network.
- **Network Diagnostics**: They aid in **network diagnostics**, **troubleshooting**, **penetration testing**, and **forensic investigations**.
- **Security Measures**: Regular network scanning allows administrators to **monitor devices**, **spot flaws**, and understand the **flow of traffic** between connected devices and applications.
- **Vulnerability Detection**: Scanning helps identify **known vulnerabilities** in computing systems.

network_scanner.py ARP Scanner **Final code**

```python
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
```

![Screenshot 2024-03-11 214932.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_214932.png)

---

## Introduction To ARP

**ARP scanning** is a process used to identify other active hosts on a local network. It’s surprisingly easy to perform and is commonly used by both network administrators and security professionals.

- **ARP** stands for **`Address Resolution Protocol`**.
- It’s a **fundamental networking protocol** that binds **layer two addresses `(MAC addresses)`** to **layer three addresses `(IP addresses)`**.
- In IPv4, ARP creates one-to-one links between `MAC addresses` and `IP addresses`.

![Untitled](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Untitled.png)

![Untitled](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Untitled%201.png)

Simple `ARP Scanning` programe 

```python
#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)

scan("192.168.111.1/24")
```

`import scapy.all as scapy` : **Scapy** is a **powerful interactive packet manipulation library** written in **Python**. It provides a versatile set of tools for working with network packets.

![Screenshot 2024-03-11 145436.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_145436.png)

# Network Scanner Algorithm (ARP Scanning)

![Screenshot 2024-03-11 144907.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_144907.png)

## 1. Create arp request directed to broadcast `MAC` asking for `IP`

- **Use ARP to ask who has target IP**

![Screenshot 2024-03-11 150036.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_150036.png)

![Screenshot 2024-03-11 151340.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_151340.png)

**`scapy.ARP()` : class represents Address Resolution Protocol (ARP) packets.**

[`scapy.ls](http://scapy.ls/)(scapy.ARP())` : It will show the fields for crafting custom `ARP` packets using `Scapy`

![Screenshot 2024-03-11 151501.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_151501.png)

```python
#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    print(arp_request.summary())

scan("192.168.111.1/24")
```

![Screenshot 2024-03-11 150216.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_150216.png)

- **Set destination MAC to broadcast MAC**

![Screenshot 2024-03-11 150540.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_150540.png)

![Screenshot 2024-03-11 152336.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_152336.png)

The **`scapy.Ether()`** class represents **Ethernet frames**.

`scapy.ls(scapy.Ether)` : It will show the fields for crafting custom Ethernet frames using Scapy

![Screenshot 2024-03-11 152447.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_152447.png)

![Screenshot 2024-03-11 153146.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_153146.png)

![Screenshot 2024-03-11 153159.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_153159.png)

Combining the two object/variables `arp_request` and `broadcast`

![Screenshot 2024-03-11 153959.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_153959.png)

`arp_request_broadcast.show()` : It will show the details of combined packets

![Screenshot 2024-03-11 154101.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_154101.png)

## 2. Send Packet and Received Response

![Screenshot 2024-03-11 155426.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_155426.png)

![Screenshot 2024-03-11 155523.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_155523.png)

`scapy.sr()` : function is used for `sending` and `receiving` packets at **Layer 3** (network layer).

`scapy.srp()` : This function is used for `sending` and `receiving` packets at **Layer 2** (data link layer).

But `srp()` function help to send custom Ether Packet . 

`srp()` function return the two response `answered` and `unanswered` 

- The **`answered`** list contains ARP responses from devices that matched the requested IP address.
- The **`unanswered`** list contains packets that did not receive a response.

`timeout=1` : parameter specifies how long to wait for responses (in seconds)

```python
#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)
    print(answered.summary())

scan("192.168.111.1/24")
```

![Screenshot 2024-03-11 160048.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_160048.png)

## 3. Parsing the Response

![Screenshot 2024-03-11 172224.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_172224.png)

![Screenshot 2024-03-11 173032.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_173032.png)

![Screenshot 2024-03-11 174621.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_174621.png)

![Screenshot 2024-03-11 173133.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_173133.png)

![Screenshot 2024-03-11 174012.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_174012.png)

![Screenshot 2024-03-11 174025.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_174025.png)

## 4. Print Result

![Screenshot 2024-03-11 174647.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_174647.png)

![Screenshot 2024-03-11 175640.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_175640.png)

Setting **`verbose`** to **`False`** or **`0`** suppresses most output

```python
#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print("IP\t\t\tMAC Address\n---------------------------------------------" )
    for element in answered_list:
        #print(element[1].show())
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

scan("192.168.111.1/24")
```

![Screenshot 2024-03-11 205614.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_205614.png)

## #Improving the Program Using a `List of Dictionaries`.

![Screenshot 2024-03-11 205133.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_205133.png)

![Screenshot 2024-03-11 205150.png](Network%20Scanner%20(ARP%20SCANNER)%20c18e6d53a55341e1ab0a8e97de3cffd3/Screenshot_2024-03-11_205150.png)

```python
#!/usr/bin/env python

import scapy.all as scapy

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

scan_list = scan("192.168.111.1/24")
scan_result(scan_list)
```

## #**Get IP Range Using Command Line Arguments**

```python
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
```