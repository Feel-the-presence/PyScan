import actions

main_ports = [135, 139, 445]

if __name__ == "__main__":

    my_scanner = NetworkScan.NetworkScanner("192.168.0.106", main_ports)

    choice = input("Choose an option (1-portScan, 2-grabBanner, 3-arpscan):    ")

    if choice == "1":
        my_scanner.scan_ports()

        print("Open ports: ", my_scanner.open_ports)

    elif choice == "2":
        banner = my_scanner.grab_banner(445)

        print("Info: ", banner)

    elif choice == "3":
        my_scanner.arp_scan()