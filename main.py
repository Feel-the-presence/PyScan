from interface import *
import actions

hello_screen()

choice = int(input("Choice an option: 1 - port_scan, 2 - arp_scan: "))
if choice == 1:
    target = input("Enter the target's IP: ")
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 445, 8080]
    actions.scan_ports(target, ports)
elif choice == 2:
    actions.arp_scan()
else:
    print("Nu ti i perec")