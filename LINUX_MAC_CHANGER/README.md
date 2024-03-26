# MAC_CHANGER

# **What is the MAC address?**

A MAC address, which stands for Media Access Control address, is a unique identifier assigned to network interfaces for communications at the data link layer of a network segment. MAC addresses are used as network addresses for most IEEE 802 network technologies, including Ethernet and Wi-Fi. [It’s a 48 or 64-bit address associated with a network adapter and is also known as the hardware address or physical address1](https://www.tutorialspoint.com/what-is-a-mac-address-in-computer-networks). [MAC addresses are crucial for the management of network traffic and are hardcoded into network interface cards (NICs) by the manufacturer](https://www.howtogeek.com/764868/what-is-a-mac-address-and-how-does-it-work/)

![Screenshot 2024-03-11 033345.png](MAC_CHANGER%20c9b8e3479bef424582337700b5c66893/Screenshot_2024-03-11_033345.png)

## WHY CHANGE THE MAC ADDRESS?

1. Increase anonymity.
2. Impersonate other devices.
3. Bypass filters.

mac_changer.py

```python
#!/usr/bin/env python3

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_mac:
        parser.error("[-] Please specify a new MAC, use --help for more info.")
    return options
def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_address_search_result:
        return (mac_address_search_result.group(0))
    else:
        print("[-] could not read MAC address")

options = get_arguments()
current_mac = get_current_mac(options.interface)
print("Current MAC = " + str(current_mac))
change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac.casefold() == options.new_mac.casefold():
    print("[+] MAC address was successfully change to " + current_mac)
else:
    print("[-] MAC address did not get changed.")

```

`import subprocess` : using a module to Execute System Commands

`import optparse` : It provides a convenient and flexible way to handle command-line arguments and options

`import re` : search for specific patterns within a string.

```python
python3 mac_changer.py --help
python3 mac_changer.py --interface <interface> --mac <new_mac_address>
```

![Screenshot 2024-03-11 035114.png](MAC_CHANGER%20c9b8e3479bef424582337700b5c66893/Screenshot_2024-03-11_035114.png)

![Screenshot 2024-03-11 035139.png](MAC_CHANGER%20c9b8e3479bef424582337700b5c66893/Screenshot_2024-03-11_035139.png)

---

# Manually Change MAC Address

1. Identify network interface (**`ifconfig`**).
2. Bring interface down (**`sudo ifconfig [interface] down`**).
3. Change MAC address (**`sudo macchanger -r [interface]`** for random).
4. Change to a Specific MAC Address (**`sudo macchanger -m xx:xx:xx:xx:xx:xx [interface]`** ).
5. Bring interface up (**`sudo ifconfig [interface] up`**).
6. Verify change (**`sudo macchanger -s [interface]`**).