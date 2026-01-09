from interface import *
import actions

hello_screen()
print("Initializing SilentFlow...")

target = input("Enter the target's IP: ")
ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 445, 8080]

print(f"\nTarget: {target}\n" + "-"*30)

actions.scan_ports(ports, target)
